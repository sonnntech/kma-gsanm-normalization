#!/usr/bin/env python3
"""So sánh TRƯỚC và SAU chuẩn hóa trên cùng một kịch bản tấn công.

TRƯỚC: log thô ở 5 nguồn – mỗi nguồn gọi IP nguồn bằng một tên khác, ghi thời gian
       theo một định dạng/múi giờ khác -> không thể viết 1 truy vấn tương quan chung.
SAU  : 1 câu SQL trên trường ECS (source.ip, event.outcome, @timestamp) phát hiện
       IP xuất hiện ở >= 3 nguồn với hành vi thất bại/cảnh báo trong cửa sổ 15 phút.

    python eval/correlate.py
"""
import json
import re
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
B, C, Y, G, R, X = "\033[1;34m", "\033[36m", "\033[33m", "\033[32m", "\033[1;31m", "\033[0m"

RAW = [  # (file, tên trường IP gốc, cách ghi thời gian)
    ("linux_auth.log", 'văn bản tự do "... from <ip> port"', "Nov 10 08:47:00  (giờ VN, không có năm)"),
    ("apache_access.log", "token đầu dòng", "10/Nov/2026:08:45:00 +0700"),
    ("suricata_eve.json", "src_ip", "2026-11-10T01:45:00.000000+0000 (UTC)"),
    ("fortigate.log", "srcip", 'date=2026-11-10 time=08:46:00 + tz="+0700"'),
    ("windows_security.json", "EventData.IpAddress", "/Date(1794275340000)/ (epoch ms)"),
]

RULE = """
WITH bad AS (
  SELECT source_ip, event_dataset, timestamp
  FROM events
  WHERE network_direction = 'inbound'          -- nguồn từ Internet vào hệ thống
    AND (event_outcome = 'failure' OR event_kind = 'alert')
)
SELECT source_ip,
       COUNT(DISTINCT event_dataset)             AS so_nguon,
       COUNT(*)                                  AS so_su_kien,
       MIN(timestamp)                            AS dau_tien,
       MAX(timestamp)                            AS cuoi_cung,
       GROUP_CONCAT(DISTINCT event_dataset)      AS cac_nguon
FROM bad
GROUP BY source_ip,
         strftime('%Y-%m-%dT%H', timestamp) || (CAST(strftime('%M', timestamp) AS INT) / 15)
HAVING so_nguon >= 3
ORDER BY so_nguon DESC, so_su_kien DESC;
"""


def before(ip):
    print(f"{B}▌TRƯỚC chuẩn hóa – tìm IP {ip} trong log thô{X}")
    print(f"  {'File':24s} {'Số dòng':>7s}  {'Trường IP gốc':34s} Cách ghi thời gian")
    for f, field, ts in RAW:
        n = sum(1 for line in open(ROOT / "samples" / f, encoding="utf-8", errors="replace") if ip in line)
        print(f"  {f:24s} {n:7d}  {field:34s} {ts}")
    print(f"  {Y}→ 5 tên trường IP, 5 định dạng thời gian, 3 múi giờ: grep thấy được nhưng KHÔNG tương quan được{X}")
    first = []
    for f, *_ in RAW:
        for line in open(ROOT / "samples" / f, encoding="utf-8", errors="replace"):
            if ip in line:
                m = re.search(r"(?<!\d)(\d{2}:\d{2}:\d{2})(?!\d)", line)
                if m:
                    first.append((f, m.group(1)))
                    break
    print(f"  {Y}→ Đọc giờ 'thô' của sự kiện đầu tiên mỗi nguồn:{X} " +
          ", ".join(f"{f.split('_')[0].split('.')[0]}={t}" for f, t in first))
    print(f"  {R}  Suricata ghi 01:45 còn Apache ghi 08:45 cho CÙNG một thời điểm → lệch 7 giờ nếu so trực tiếp.{X}\n")


def after():
    db = sqlite3.connect(ROOT / "output" / "gsanm.db")
    print(f"{B}▌SAU chuẩn hóa – 1 luật tương quan trên trường ECS{X}{C}{RULE}{X}")
    rows = db.execute(RULE).fetchall()
    if not rows:
        print("  Không có cảnh báo.")
    for ip, n_src, n_ev, t0, t1, srcs in rows:
        ti = db.execute("SELECT threat_indicator_provider, source_geo_country_iso_code FROM events "
                        "WHERE source_ip=? AND threat_indicator_provider IS NOT NULL LIMIT 1", (ip,)).fetchone()
        print(f"{R}  [CẢNH BÁO] {ip}{X}: {n_src} nguồn, {n_ev} sự kiện, {t0} → {t1}")
        print(f"     nguồn: {srcs}")
        if ti:
            print(f"     threat intel: {ti[0]} | quốc gia: {ti[1]}")
    if rows:
        ip = rows[0][0]
        print(f"\n{B}▌Dòng thời gian hợp nhất (UTC) của {ip}{X}")
        q = """SELECT timestamp, event_dataset, COALESCE(rule_name, event_action, url_original, ''),
                      COALESCE(user_name, ''), COALESCE(destination_ip, host_name, '') , COUNT(*)
               FROM events WHERE source_ip=?
               GROUP BY event_dataset, strftime('%H:%M', timestamp)
               ORDER BY MIN(timestamp) LIMIT 14"""
        for ts, ds, what, user, dst, n in db.execute(q, (ip,)):
            print(f"  {G}{ts}{X}  {ds:18s} {what[:38]:38s} {user:14s} → {dst:15s} x{n}")
    summary = {"alerts": [dict(zip(["source_ip", "datasets", "events", "first", "last", "sources"], r)) for r in rows]}
    (ROOT / "output" / "correlation.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    before("185.220.101.45")
    after()
