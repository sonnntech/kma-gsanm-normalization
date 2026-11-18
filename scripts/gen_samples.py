#!/usr/bin/env python3
"""Sinh log mẫu cho 5 nguồn GSANM với định dạng, múi giờ và tên trường khác nhau.

Kịch bản tấn công được cài sẵn: IP 185.220.101.45 quét web, brute-force SSH,
bị Suricata cảnh báo, bị FortiGate chặn và thử đăng nhập Windows DC.
Ngoài ra có chèn dòng lỗi (malformed) và dòng trùng lặp để đo parse rate và dedup.

    python scripts/gen_samples.py --n 2000
"""
import argparse
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "samples"

VN = timezone(timedelta(hours=7))
BASE = datetime(2026, 11, 10, 8, 0, 0, tzinfo=VN)  # giờ Việt Nam
ATTACKER = "185.220.101.45"

INTERNAL_CLIENTS = [f"10.10.2.{i}" for i in range(10, 60)]
EXTERNAL = ["14.161.20.8", "113.160.5.21", "42.112.30.7", "203.113.131.2",
            "8.8.8.8", "1.1.1.1", "52.95.110.1", "104.16.0.5", "45.33.32.156"]
WEB01, DC01, FW_VIP = "10.10.1.20", "10.10.1.10", "10.10.1.1"
USERS = ["son.nn", "lan.pt", "hieu.vm", "minh.tq", "anh.dt", "svc_backup"]
URLS = ["/", "/index.html", "/login", "/api/v1/orders", "/static/app.js", "/images/logo.png"]
SCAN_URLS = ["/wp-login.php", "/.env", "/phpmyadmin/", "/admin/config.php",
             "/cgi-bin/luci", "/.git/config", "/backup.zip"]
UAS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0",
       "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) Safari/605.1.15",
       "curl/8.5.0"]


def rnd_time(rng, minutes=120):
    return BASE + timedelta(seconds=rng.randint(0, minutes * 60), microseconds=rng.randint(0, 999999))


# ---------- 1. Linux auth.log (syslog BSD, giờ địa phương, KHÔNG có năm) ----------
def auth_line(t, host, pid, msg):
    return f"{t:%b} {t.day:2d} {t:%H:%M:%S} {host} sshd[{pid}]: {msg}"


def gen_auth(rng, n):
    rows = []
    for _ in range(n):
        t = rnd_time(rng)
        ip = rng.choice(INTERNAL_CLIENTS)
        u = rng.choice(USERS)
        r = rng.random()
        if r < 0.75:
            msg = f"Accepted publickey for {u} from {ip} port {rng.randint(40000, 65000)} ssh2"
        elif r < 0.95:
            msg = f"Failed password for {u} from {ip} port {rng.randint(40000, 65000)} ssh2"
        else:
            msg = f"pam_unix(sshd:session): session closed for user {u}"
        rows.append((t, auth_line(t, "web01", rng.randint(1000, 9999), msg)))
    # tấn công: brute-force 60 lần trong ~3 phút
    start = BASE + timedelta(minutes=47)
    for i in range(60):
        t = start + timedelta(seconds=i * 3)
        u = rng.choice(["root", "admin", "ubuntu", "oracle", "test"])
        inv = "invalid user " if u != "root" else ""
        rows.append((t, auth_line(t, "web01", 7000 + i,
                                  f"Failed password for {inv}{u} from {ATTACKER} port {50000 + i} ssh2")))
    return rows


# ---------- 2. Apache access log (combined, có offset +0700) ----------
def gen_apache(rng, n):
    rows = []

    def line(t, ip, method, url, status, size, ua):
        return (f'{ip} - - [{t.strftime("%d/%b/%Y:%H:%M:%S %z")}] "{method} {url} HTTP/1.1" '
                f'{status} {size} "-" "{ua}"')
    for _ in range(n):
        t = rnd_time(rng)
        ip = rng.choice(EXTERNAL + INTERNAL_CLIENTS)
        url = rng.choice(URLS)
        rows.append((t, line(t, ip, rng.choice(["GET", "GET", "GET", "POST"]), url,
                             rng.choice([200, 200, 200, 304, 404]), rng.randint(200, 50000), rng.choice(UAS))))
    start = BASE + timedelta(minutes=45)
    for i, url in enumerate(SCAN_URLS * 3):
        t = start + timedelta(seconds=i * 4)
        rows.append((t, line(t, ATTACKER, "GET", url, 404, 196, "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)")))
    return rows


# ---------- 3. Suricata eve.json (JSON lồng nhau, UTC, tên trường src_ip/dest_ip) ----------
def gen_suricata(rng, n):
    rows = []

    def ev(t, src, sport, dst, dport, sig, sid, sev, cat):
        return json.dumps({
            "timestamp": t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+0000"),
            "flow_id": rng.randint(10**14, 10**15), "in_iface": "eth1", "event_type": "alert",
            "src_ip": src, "src_port": sport, "dest_ip": dst, "dest_port": dport, "proto": "TCP",
            "alert": {"action": "allowed", "gid": 1, "signature_id": sid, "rev": 3,
                      "signature": sig, "category": cat, "severity": sev},
            "host": "ids-sensor-01"}, ensure_ascii=False)
    benign = [("ET POLICY curl User-Agent Outbound", 2013028, 3, "Attempted Information Leak"),
              ("ET INFO Observed DNS Query to .cloud TLD", 2027758, 3, "Potentially Bad Traffic")]
    for _ in range(n):
        t = rnd_time(rng)
        sig, sid, sev, cat = rng.choice(benign)
        rows.append((t, ev(t, rng.choice(INTERNAL_CLIENTS), rng.randint(40000, 65000),
                           rng.choice(EXTERNAL), 443, sig, sid, sev, cat)))
    attack = [("ET SCAN Nuclei Scanner User-Agent", 2033120, 2, "Web Application Attack"),
              ("ET SCAN Potential SSH Scan", 2001219, 2, "Attempted Information Leak"),
              ("ET COMPROMISED Known Tor Exit Node Traffic", 2522000, 1, "Misc Attack")]
    for i in range(12):
        t = BASE + timedelta(minutes=45, seconds=i * 20)
        sig, sid, sev, cat = attack[i % 3]
        rows.append((t, ev(t, ATTACKER, 50000 + i, WEB01, 22 if "SSH" in sig else 443, sig, sid, sev, cat)))
    return rows


# ---------- 4. FortiGate (key=value, date + time tách rời, tz riêng) ----------
def gen_fortigate(rng, n):
    rows = []

    def kv(t, src, sport, dst, dport, action, policy):
        return (f'date={t.strftime("%Y-%m-%d")} time={t.strftime("%H:%M:%S")} devname="FGT-HQ" '
                f'devid="FG100F0000000001" logid="0000000013" type="traffic" subtype="forward" level="notice" '
                f'srcip={src} srcport={sport} srcintf="wan1" dstip={dst} dstport={dport} dstintf="dmz" '
                f'proto=6 action="{action}" policyid={policy} service="{ {22: "SSH", 443: "HTTPS", 80: "HTTP"}.get(dport, "tcp") }" '
                f'sentbyte={rng.randint(0, 9000)} rcvdbyte={rng.randint(0, 90000)} tz="+0700"')
    for _ in range(n):
        t = rnd_time(rng)
        dport = rng.choice([443, 443, 80, 22])
        act = "accept" if rng.random() < 0.9 else "deny"
        rows.append((t, kv(t, rng.choice(EXTERNAL), rng.randint(40000, 65000), WEB01, dport, act, 2)))
    for i in range(40):
        t = BASE + timedelta(minutes=46, seconds=i * 6)
        rows.append((t, kv(t, ATTACKER, 51000 + i, rng.choice([WEB01, DC01]),
                           rng.choice([22, 3389, 445, 3306]), "deny", 3)))
    return rows


# ---------- 5. Windows Security (PowerShell ConvertTo-Json, thời gian /Date(epoch-ms)/) ----------
def gen_windows(rng, n):
    rows = []

    def ev(t, eid, user, ip, ltype, status=None):
        d = {"EventID": eid, "MachineName": "DC01.corp.local", "ProviderName": "Microsoft-Windows-Security-Auditing",
             "TimeCreated": f"/Date({int(t.timestamp() * 1000)})/",
             "EventData": {"TargetUserName": user, "TargetDomainName": "CORP", "IpAddress": ip,
                           "IpPort": str(rng.randint(40000, 65000)), "LogonType": str(ltype),
                           "WorkstationName": "-" if ip == ATTACKER else f"PC-{rng.randint(100, 199)}"}}
        if status:
            d["EventData"]["Status"] = status
        return json.dumps(d)
    for _ in range(n):
        t = rnd_time(rng)
        u = rng.choice(USERS)
        if rng.random() < 0.85:
            rows.append((t, ev(t, 4624, u, rng.choice(INTERNAL_CLIENTS), rng.choice([2, 3, 10]))))
        else:
            rows.append((t, ev(t, 4625, u, rng.choice(INTERNAL_CLIENTS), 3, "0xC000006D")))
    for i in range(25):
        t = BASE + timedelta(minutes=49, seconds=i * 5)
        rows.append((t, ev(t, 4625, rng.choice(["administrator", "admin", "backup"]), ATTACKER, 3, "0xC000006A")))
    return rows


MALFORMED = {
    "linux_auth.log": ["web01 sshd: truncated", "<garbage>\x00\x00"],
    "apache_access.log": ['- - - [bad date] "GET', "\\x16\\x03\\x01 TLS handshake on HTTP port"],
    "suricata_eve.json": ['{"timestamp": "2026-11-10T01:00:00", "src_ip": ', "not json"],
    "fortigate.log": ["date=2026-11-10 truncated"],
    "windows_security.json": ['{"EventID": 4624, "TimeCreated": '],
}


def write(name, rows, rng, dup_ratio=0.01):
    rows.sort(key=lambda r: r[0])
    lines = [r[1] for r in rows]
    # chèn bản ghi trùng (mô phỏng gửi lại do mất kết nối agent)
    for _ in range(int(len(lines) * dup_ratio)):
        i = rng.randrange(len(lines))
        lines.insert(i + 1, lines[i])
    for bad in MALFORMED.get(name, []):
        lines.insert(rng.randrange(len(lines)), bad)
    (OUT / name).write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=2000, help="số sự kiện bình thường mỗi nguồn")
    ap.add_argument("--seed", type=int, default=16)
    a = ap.parse_args()
    rng = random.Random(a.seed)
    OUT.mkdir(exist_ok=True)
    gens = {"linux_auth.log": gen_auth, "apache_access.log": gen_apache, "suricata_eve.json": gen_suricata,
            "fortigate.log": gen_fortigate, "windows_security.json": gen_windows}
    for name, g in gens.items():
        print(f"{name:24s} {write(name, g(rng, a.n), rng):6d} dòng")


if __name__ == "__main__":
    main()
