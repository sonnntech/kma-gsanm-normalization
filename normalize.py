#!/usr/bin/env python3
"""Pipeline chuẩn hóa dữ liệu GSANM -> Elastic Common Schema (ECS).

    Thu thập -> Parse -> Mapping trường + ép kiểu -> Chuẩn hóa thời gian (UTC)
             -> Phân loại (taxonomy) -> Làm giàu -> Khử trùng lặp -> Lưu trữ

    python normalize.py                       # chạy toàn bộ nguồn trong schema/ecs_mapping.yaml
    python normalize.py --only suricata       # chỉ một nguồn
    python normalize.py --show 185.220.101.45 # in vài bản ghi đã chuẩn hóa của 1 IP
"""
import argparse
import hashlib
import ipaddress
import json
import re
import sqlite3
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from enrich import Enricher
from parsers import PARSERS

ROOT = Path(__file__).resolve().parent
SAMPLES, OUTPUT = ROOT / "samples", ROOT / "output"
MSDATE_RE = re.compile(r"/Date\((-?\d+)\)/")
TZ_RE = re.compile(r"^([+-])(\d{2}):?(\d{2})$")


# ------------------------------------------------------------------ thời gian
def _tz(s):
    m = TZ_RE.match(s.strip())
    if not m:
        raise ValueError(f"tz không hợp lệ: {s}")
    sign = 1 if m.group(1) == "+" else -1
    return timezone(sign * timedelta(hours=int(m.group(2)), minutes=int(m.group(3))))


def parse_time(raw, spec):
    src = spec["from"]
    val = " ".join(str(raw[k]) for k in src) if isinstance(src, list) else raw[src]
    fmt = spec["format"]
    if fmt == "iso8601":
        dt = datetime.fromisoformat(str(val).replace("Z", "+00:00"))
    elif fmt == "msdate":
        dt = datetime.fromtimestamp(int(MSDATE_RE.search(str(val)).group(1)) / 1000, tz=timezone.utc)
    else:
        if "assume_year" in spec:                    # syslog BSD (RFC 3164) không ghi năm
            val, fmt = f"{spec['assume_year']} {val}", "%Y " + fmt
        dt = datetime.strptime(str(val), fmt)
    if dt.tzinfo is None:                            # thời gian "trần" -> gắn múi giờ gốc của nguồn
        tz = spec.get("tz") or (raw.get(spec["tz_field"]) if spec.get("tz_field") else None)
        if tz is None:
            raise ValueError("thiếu múi giờ")
        dt = dt.replace(tzinfo=_tz(tz))
    return dt.astimezone(timezone.utc)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


# ------------------------------------------------------------------ ép kiểu
def cast(v, typ):
    if v is None or v == "" or v == "-":
        return None
    if typ in (None, "str"):
        return str(v)
    if typ == "int":
        return int(v)
    if typ == "lower":
        return str(v).lower()
    if typ == "upper":
        return str(v).upper()
    if typ == "ip":
        return str(ipaddress.ip_address(str(v)))
    if typ == "severity_suricata":           # Suricata 1(cao)..4(thấp) -> thang ECS 0..100
        return {1: 90, 2: 70, 3: 40, 4: 20}.get(int(v), 0)
    raise ValueError(f"kiểu không hỗ trợ: {typ}")


def match(raw, cond):
    for k, expect in cond.items():
        v = raw.get(k)
        if v is None:
            return False
        if isinstance(expect, dict) and "regex" in expect:
            if not re.search(expect["regex"], str(v)):
                return False
        elif str(v) != str(expect):
            return False
    return True


# ------------------------------------------------------------------ chuẩn hóa 1 bản ghi
def normalize(raw, line, name, cfg):
    ev = {"ecs.version": "8.11.0", "event.kind": "event"}
    ev.update(cfg.get("static", {}))
    tags = []
    try:
        ev["@timestamp"] = iso(parse_time(raw, cfg["timestamp"]))
    except Exception:
        tags.append("_timestamp_failure")
    for src, rule in cfg.get("fields", {}).items():
        if src not in raw:
            continue
        try:
            v = cast(raw[src], rule.get("type"))
        except (ValueError, TypeError):
            tags.append(f"_type_failure:{rule['to']}")
            continue
        if v is not None:
            ev[rule["to"]] = v
    for c in cfg.get("classify", []):
        if match(raw, c["when"]):
            ev.update(c["set"])
    ev["event.original"] = line
    ev["event.hash"] = hashlib.sha256(f"{name}|{line}".encode()).hexdigest()
    if tags:
        ev["tags"] = tags
    return ev


def nest(flat):
    """{'source.ip': x} -> {'source': {'ip': x}} để ghi NDJSON đúng cấu trúc ECS."""
    out = {}
    for k, v in flat.items():
        if k == "@timestamp":
            out[k] = v
            continue
        cur = out
        parts = k.split(".")
        for p in parts[:-1]:
            cur = cur.setdefault(p, {})
        cur[parts[-1]] = v
    return out


# ------------------------------------------------------------------ lưu trữ
SQL_COLS = ["@timestamp", "event.dataset", "event.kind", "event.category", "event.action",
            "event.outcome", "event.severity", "event.risk_score", "source.ip", "source.port",
            "source.geo.country_iso_code", "destination.ip", "destination.port", "user.name",
            "host.name", "observer.product", "rule.name", "url.original", "threat.indicator.provider",
            "network.direction"]


def col(c):
    return c.replace("@", "").replace(".", "_")


def open_db(path):
    path.unlink(missing_ok=True)
    db = sqlite3.connect(path)
    db.execute(f"CREATE TABLE events ({', '.join(col(c) + ' TEXT' for c in SQL_COLS)}, doc TEXT)")
    return db


def to_row(ev):
    vals = []
    for c in SQL_COLS:
        v = ev.get(c)
        vals.append(",".join(v) if isinstance(v, list) else (None if v is None else str(v)))
    return vals + [json.dumps(nest(ev), ensure_ascii=False)]


# ------------------------------------------------------------------ main
def run(only=None, quiet=False):
    conf = yaml.safe_load((ROOT / "schema" / "ecs_mapping.yaml").read_text(encoding="utf-8"))
    OUTPUT.mkdir(exist_ok=True)
    enricher = Enricher()
    db = open_db(OUTPUT / "gsanm.db")
    seen, stats = set(), {}
    nd = open(OUTPUT / "normalized.ndjson", "w", encoding="utf-8")
    t_all = time.perf_counter()
    for name, cfg in conf["sources"].items():
        if only and name not in only:
            continue
        parser = PARSERS[cfg["parser"]]
        st = dict(lines=0, parsed=0, parse_failed=0, duplicates=0, timestamp_failed=0, output=0)
        failed_examples = []
        t0 = time.perf_counter()
        rows = []
        with open(SAMPLES / cfg["file"], encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line.strip():
                    continue
                st["lines"] += 1
                raw = parser(line)
                if raw is None:
                    st["parse_failed"] += 1
                    failed_examples.append(line[:80])
                    continue
                st["parsed"] += 1
                ev = normalize(raw, line, name, cfg)
                if ev["event.hash"] in seen:
                    st["duplicates"] += 1
                    continue
                seen.add(ev["event.hash"])
                if "_timestamp_failure" in ev.get("tags", []):
                    st["timestamp_failed"] += 1
                enricher.enrich(ev)
                ev["event.ingested"] = iso(datetime.now(timezone.utc))
                nd.write(json.dumps(nest(ev), ensure_ascii=False) + "\n")
                rows.append(to_row(ev))
                st["output"] += 1
        db.executemany(f"INSERT INTO events VALUES ({','.join('?' * (len(SQL_COLS) + 1))})", rows)
        st["seconds"] = round(time.perf_counter() - t0, 4)
        st["eps"] = round(st["lines"] / st["seconds"]) if st["seconds"] else None
        st["parse_rate"] = round(100 * st["parsed"] / st["lines"], 2)
        st["failed_examples"] = failed_examples
        stats[name] = st
        if not quiet:
            print(f"  {name:11s} {st['lines']:6d} dòng | parse {st['parse_rate']:6.2f}% | "
                  f"trùng {st['duplicates']:3d} | lỗi {st['parse_failed']} | {st['eps']:>7,} EPS")
    nd.close()
    db.commit()
    db.close()
    total = sum(s["lines"] for s in stats.values())
    elapsed = time.perf_counter() - t_all
    stats["_total"] = {"lines": total, "output": sum(s["output"] for s in stats.values()),
                       "seconds": round(elapsed, 3), "eps": round(total / elapsed)}
    (OUTPUT / "stats.json").write_text(json.dumps(stats, ensure_ascii=False, indent=2), encoding="utf-8")
    if not quiet:
        t = stats["_total"]
        print(f"  {'TỔNG':11s} {t['lines']:6d} dòng -> {t['output']} sự kiện ECS trong {t['seconds']}s "
              f"(~{t['eps']:,} EPS)\n  Đầu ra: output/normalized.ndjson, output/gsanm.db, output/stats.json")
    return stats


SHOW_FIELDS = ["@timestamp", "event.dataset", "event.category", "event.action", "event.outcome",
               "source.ip", "source.geo.country_iso_code", "destination.ip", "destination.port",
               "user.name", "host.name", "rule.name", "url.original", "threat.indicator.provider",
               "event.risk_score"]


def flat(d, prefix=""):
    out = {}
    for k, v in d.items():
        key = k if not prefix else f"{prefix}.{k}"
        out.update(flat(v, key) if isinstance(v, dict) else {key: v})
    return out


def show(ip, full=False):
    """In bản ghi GỐC và bản ECS của cùng một IP ở mỗi nguồn -> minh họa 'trước / sau'."""
    db = sqlite3.connect(OUTPUT / "gsanm.db")
    for ds, in db.execute("SELECT DISTINCT event_dataset FROM events WHERE source_ip=? ORDER BY 1", (ip,)):
        doc, = db.execute("SELECT doc FROM events WHERE source_ip=? AND event_dataset=? ORDER BY timestamp LIMIT 1",
                          (ip, ds)).fetchone()
        d = flat(json.loads(doc))
        print(f"\n\033[1;34m===== {ds} =====\033[0m")
        print(f"\033[33mGỐC\033[0m  {d['event.original'][:160]}")
        keys = sorted(d) if full else SHOW_FIELDS
        for k in keys:
            if k in d and k not in ("event.original", "event.hash"):
                print(f"\033[32mECS\033[0m  {k:30s} {d[k]}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--only", nargs="*", help="chỉ chạy các nguồn này")
    ap.add_argument("--show", metavar="IP", help="in bản ghi gốc và bản ECS của IP theo từng nguồn")
    ap.add_argument("--full", action="store_true", help="in toàn bộ trường ECS khi dùng --show")
    a = ap.parse_args()
    if a.show:
        show(a.show, a.full)
        sys.exit(0)
    print("Chuẩn hóa dữ liệu GSANM -> ECS")
    run(a.only)
