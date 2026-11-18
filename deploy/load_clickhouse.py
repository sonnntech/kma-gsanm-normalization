#!/usr/bin/env python3
"""Nạp output/gsanm.db (SQLite) vào ClickHouse qua HTTP interface (không cần thư viện ngoài).

    python deploy/load_clickhouse.py [--url http://localhost:8123] [--user gsanm --password gsanm]
    python deploy/load_clickhouse.py --chdb      # dùng ClickHouse nhúng (pip install chdb), không cần Docker
"""
import argparse
import base64
import json
import sqlite3
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DDL = (ROOT / "deploy" / "clickhouse_ddl.sql").read_text(encoding="utf-8")
RULE = (ROOT / "deploy" / "correlation_clickhouse.sql").read_text(encoding="utf-8")
INT_COLS = {"event_severity", "event_risk_score", "source_port", "destination_port"}


def rows():
    db = sqlite3.connect(ROOT / "output" / "gsanm.db")
    db.row_factory = sqlite3.Row
    for r in db.execute("SELECT * FROM events"):
        d = dict(r)
        d["timestamp"] = d["timestamp"].replace("T", " ").rstrip("Z")
        d["event_category"] = d["event_category"].split(",") if d["event_category"] else []
        d["observer_product"] = d["observer_product"] or ""
        for c in INT_COLS:
            if d[c] is not None:
                d[c] = int(d[c])
        yield json.dumps(d, ensure_ascii=False)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:8123")
    ap.add_argument("--user", default="gsanm")
    ap.add_argument("--password", default="gsanm")
    ap.add_argument("--chdb", action="store_true", help="dùng ClickHouse nhúng chdb thay vì server")
    a = ap.parse_args()
    data = "\n".join(rows())

    if a.chdb:
        from chdb import session
        s = session.Session()
        for st in [x for x in DDL.split(";") if "CREATE" in x]:
            s.query(st)
        s.query("INSERT INTO gsanm.events FORMAT JSONEachRow\n" + data)
        print(s.query("SELECT count() FROM gsanm.events", "PrettyCompact"))
        print(s.query(RULE.rstrip().rstrip(";"), "PrettyCompact"))
        return

    auth = base64.b64encode(f"{a.user}:{a.password}".encode()).decode()

    def post(sql, body=""):
        req = urllib.request.Request(f"{a.url}/?query={urllib.request.quote(sql)}", data=body.encode(),
                                     headers={"Authorization": f"Basic {auth}"})
        return urllib.request.urlopen(req).read().decode()
    for st in [x for x in DDL.split(";") if "CREATE" in x]:
        post(st)
    post("TRUNCATE TABLE gsanm.events")
    post("INSERT INTO gsanm.events FORMAT JSONEachRow", data)
    print("Đã nạp:", post("SELECT count() FROM gsanm.events").strip(), "sự kiện")
    print(post(RULE.rstrip().rstrip(";") + " FORMAT PrettyCompact"))


if __name__ == "__main__":
    main()
