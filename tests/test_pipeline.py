import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from enrich import Enricher  # noqa: E402
from normalize import normalize  # noqa: E402
from parsers import PARSERS  # noqa: E402

CONF = yaml.safe_load((Path(__file__).resolve().parent.parent / "schema" / "ecs_mapping.yaml").read_text())["sources"]


def run(src, line):
    cfg = CONF[src]
    raw = PARSERS[cfg["parser"]](line)
    assert raw is not None
    return Enricher().enrich(normalize(raw, line, src, cfg))


def test_auth_local_time_to_utc():
    ev = run("linux_auth", "Nov 10 08:47:00 web01 sshd[7000]: Failed password for invalid user oracle "
                           "from 185.220.101.45 port 50000 ssh2")
    assert ev["@timestamp"] == "2026-11-10T01:47:00.000Z"
    assert ev["source.ip"] == "185.220.101.45" and ev["user.name"] == "oracle"
    assert ev["event.outcome"] == "failure" and ev["event.category"] == ["authentication"]
    assert ev["threat.indicator.provider"] == "tor-exit-list"


def test_same_instant_across_sources():
    a = run("apache", '185.220.101.45 - - [10/Nov/2026:08:45:00 +0700] "GET /.env HTTP/1.1" 404 196 "-" "x"')
    s = run("suricata", '{"timestamp":"2026-11-10T01:45:00.000000+0000","src_ip":"185.220.101.45",'
                        '"dest_ip":"10.10.1.20","alert":{"signature":"x","severity":2}}')
    f = run("fortigate", 'date=2026-11-10 time=08:45:00 devname="FGT" srcip=185.220.101.45 dstip=10.10.1.20 '
                         'action="deny" proto=6 tz="+0700"')
    w = run("windows", '{"EventID":4625,"TimeCreated":"/Date(1794275100000)/","MachineName":"DC01",'
                       '"EventData":{"IpAddress":"185.220.101.45","TargetUserName":"Admin"}}')
    assert a["@timestamp"] == s["@timestamp"] == f["@timestamp"] == w["@timestamp"] == "2026-11-10T01:45:00.000Z"
    assert {e["source.ip"] for e in (a, s, f, w)} == {"185.220.101.45"}
    assert w["user.name"] == "admin" and w["event.outcome"] == "failure"
    assert s["event.severity"] == 70 and f["network.transport"] == "tcp"


def test_malformed_lines_rejected():
    assert PARSERS["syslog_auth"]("web01 sshd: truncated") is None
    assert PARSERS["json"]('{"EventID": 4624, "TimeCreated": ') is None
    assert PARSERS["kv"]("date=2026-11-10 truncated") is None
