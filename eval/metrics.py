#!/usr/bin/env python3
"""Đánh giá chất lượng chuẩn hóa.

Chỉ số:
  1. Parse rate       = số dòng parse được / tổng số dòng
  2. Field coverage   = % sự kiện có đủ các trường lõi ECS (khai báo ở schema/ecs_mapping.yaml)
  3. Dedup            = số bản ghi trùng bị loại
  4. Throughput (EPS) = số sự kiện xử lý / giây
  5. Timestamp        = số sự kiện không chuẩn hóa được thời gian

Ghi kết quả ra output/metrics.md và output/metrics.png (dùng cho slide).
"""
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "output"


def has(doc, path):
    cur = doc
    for p in path.split("."):
        if p == "@timestamp" and "@timestamp" in cur:
            return True
        if not isinstance(cur, dict) or p not in cur:
            return False
        cur = cur[p]
    return cur not in (None, "", [])


def main():
    stats = json.loads((OUT / "stats.json").read_text(encoding="utf-8"))
    core = yaml.safe_load((ROOT / "schema" / "ecs_mapping.yaml").read_text(encoding="utf-8"))["core_fields"]
    per_ds, total = {}, {}
    with open(OUT / "normalized.ndjson", encoding="utf-8") as f:
        for line in f:
            d = json.loads(line)
            ds = d["event"]["dataset"]
            c = per_ds.setdefault(ds, {"n": 0, "full": 0, **{k: 0 for k in core}})
            c["n"] += 1
            ok_all = True
            for k in core:
                ok = any(has(d, alt) for alt in k.split("|"))
                c[k] += ok
                ok_all &= ok
            c["full"] += ok_all

    ds_of = {"linux_auth": "system.auth", "apache": "apache.access", "suricata": "suricata.eve",
             "fortigate": "fortinet.firewall", "windows": "windows.security"}
    lines = ["# Kết quả đánh giá chuẩn hóa GSANM -> ECS", "",
             "| Nguồn | Dòng | Parse rate | Lỗi parse | Trùng bị loại | Lỗi thời gian | Độ phủ trường lõi | EPS |",
             "|---|---:|---:|---:|---:|---:|---:|---:|"]
    chart = []
    for src, st in stats.items():
        if src.startswith("_"):
            continue
        c = per_ds.get(ds_of.get(src, src), {"n": 1, "full": 0})
        cov = 100 * c["full"] / c["n"]
        chart.append((src, st["parse_rate"], cov))
        lines.append(f"| {src} | {st['lines']:,} | {st['parse_rate']:.2f}% | {st['parse_failed']} | "
                     f"{st['duplicates']} | {st['timestamp_failed']} | {cov:.1f}% | {st['eps']:,} |")
    t = stats["_total"]
    lines += ["", f"**Tổng:** {t['lines']:,} dòng thô → {t['output']:,} sự kiện ECS trong {t['seconds']} s "
                  f"(~{t['eps']:,} EPS, Python đơn luồng).", "",
              "## Độ phủ từng trường lõi", "", "| Nguồn | " + " | ".join(core) + " |",
              "|---|" + "---:|" * len(core)]
    for ds, c in per_ds.items():
        lines.append(f"| {ds} | " + " | ".join(f"{100 * c[k] / c['n']:.0f}%" for k in core) + " |")
    lines += ["", "## Ví dụ dòng không parse được", ""]
    for src, st in stats.items():
        for ex in st.get("failed_examples", [])[:2]:
            lines.append(f"- `{src}`: `{ex!r}`")
    md = "\n".join(lines) + "\n"
    (OUT / "metrics.md").write_text(md, encoding="utf-8")
    print(md)

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        names = [c[0] for c in chart]
        x = range(len(names))
        fig, ax = plt.subplots(figsize=(8, 3.6), dpi=160)
        ax.bar([i - 0.2 for i in x], [c[1] for c in chart], 0.4, label="Parse rate", color="#1F3A68")
        ax.bar([i + 0.2 for i in x], [c[2] for c in chart], 0.4, label="Độ phủ trường lõi", color="#F28C28")
        ax.set_xticks(list(x), names)
        ax.set_ylim(90, 100.5)
        ax.set_ylabel("%")
        ax.legend(loc="lower right", frameon=False)
        for s in ("top", "right"):
            ax.spines[s].set_visible(False)
        fig.tight_layout()
        fig.savefig(OUT / "metrics.png")
        print("Biểu đồ: output/metrics.png")
    except ImportError:
        print("(bỏ qua biểu đồ: chưa cài matplotlib)", file=sys.stderr)


if __name__ == "__main__":
    main()
