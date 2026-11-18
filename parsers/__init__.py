"""Tầng 1 – Phân tích cú pháp (parsing).

Mỗi parser nhận MỘT dòng log thô và trả về dict các trường thô (giữ nguyên tên gốc
của nhà cung cấp). Trả về None nếu dòng không parse được. Việc đổi tên trường,
ép kiểu, chuẩn hóa thời gian… do tầng mapping (schema/*.yaml) đảm nhiệm, để parser
chỉ lo đúng một việc: tách cấu trúc.

Bốn kỹ thuật parse được minh họa:
  * Regex / Grok-style  : syslog auth.log, Apache combined
  * JSON (lồng nhau)    : Suricata eve.json, Windows (PowerShell JSON)
  * Key=Value           : FortiGate
"""
import json
import re

# ---------------------------------------------------------------- regex / grok
SYSLOG_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (?P<hostname>\S+) "
    r"(?P<program>[\w\-/.]+)(?:\[(?P<pid>\d+)\])?: (?P<message>.+)$")

SSHD_PATTERNS = [
    ("failed_password", re.compile(
        r"Failed password for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<src_ip>\S+) port (?P<src_port>\d+)")),
    ("accepted", re.compile(
        r"Accepted (?P<method>\w+) for (?P<user>\S+) from (?P<src_ip>\S+) port (?P<src_port>\d+)")),
    ("invalid_user", re.compile(r"Invalid user (?P<user>\S+) from (?P<src_ip>\S+)")),
    ("session_closed", re.compile(r"session closed for user (?P<user>\S+)")),
]

APACHE_RE = re.compile(
    r'^(?P<clientip>\S+) \S+ (?P<auth>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<url>\S+) (?P<proto>HTTP/[\d.]+)" '
    r'(?P<status>\d{3}) (?P<bytes>\d+|-) "(?P<referrer>[^"]*)" "(?P<agent>[^"]*)"$')

KV_RE = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')


def parse_syslog_auth(line):
    m = SYSLOG_RE.match(line)
    if not m:
        return None
    d = m.groupdict()
    d["sshd_action"] = "other"
    for action, pat in SSHD_PATTERNS:
        mm = pat.search(d["message"])
        if mm:
            d["sshd_action"] = action
            d.update({k: v for k, v in mm.groupdict().items() if v is not None})
            break
    return d


def parse_apache_combined(line):
    m = APACHE_RE.match(line)
    return m.groupdict() if m else None


def _flatten(obj, prefix=""):
    out = {}
    for k, v in obj.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(_flatten(v, key + "."))
        else:
            out[key] = v
    return out


def parse_json(line):
    try:
        obj = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None
    return _flatten(obj) if isinstance(obj, dict) else None


def parse_kv(line):
    pairs = KV_RE.findall(line)
    if len(pairs) < 5:          # quá ít cặp → coi như dòng hỏng/bị cắt
        return None
    return {k: v[1:-1] if v.startswith('"') else v for k, v in pairs}


PARSERS = {
    "syslog_auth": parse_syslog_auth,
    "apache_combined": parse_apache_combined,
    "json": parse_json,
    "kv": parse_kv,
}
