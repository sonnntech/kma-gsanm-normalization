"""Tầng 4 – Làm giàu dữ liệu (enrichment), chạy offline từ các file CSV trong enrich/data/.

  * GeoIP/ASN  : source.ip / destination.ip  -> *.geo.country_iso_code, *.as.organization.name
  * Tài sản    : IP nội bộ -> host đích, vai trò, mức độ quan trọng (labels.asset_criticality)
  * Threat intel: IP khớp danh sách IoC -> threat.indicator.*, event.risk_score
  * Phân vùng mạng: private/public -> network.direction
"""
import csv
import ipaddress
from pathlib import Path

DATA = Path(__file__).parent / "data"


def _read(name):
    with open(DATA / name, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


class Enricher:
    def __init__(self):
        self.geo = [(ipaddress.ip_network(r["cidr"]), r) for r in _read("geoip_lite.csv")]
        self.assets = {r["ip"]: r for r in _read("assets.csv")}
        self.ti = {r["indicator"]: r for r in _read("threat_intel.csv")}

    def _geo(self, ip):
        a = ipaddress.ip_address(ip)
        for net, r in self.geo:
            if a in net:
                return r
        return None

    def enrich(self, ev):
        for side in ("source", "destination"):
            ip = ev.get(f"{side}.ip")
            if not ip:
                continue
            if ipaddress.ip_address(ip).is_private:
                asset = self.assets.get(ip)
                if asset:
                    ev[f"{side}.domain"] = asset["hostname"]
                    ev.setdefault("labels.asset_role", asset["role"])
                    ev.setdefault("labels.asset_criticality", asset["criticality"])
            else:
                g = self._geo(ip)
                if g:
                    ev[f"{side}.geo.country_iso_code"] = g["country_iso_code"]
                    ev[f"{side}.geo.country_name"] = g["country_name"]
                    ev[f"{side}.as.number"] = int(g["asn"][2:])
                    ev[f"{side}.as.organization.name"] = g["as_org"]
            hit = self.ti.get(ip)
            if hit:
                ev["threat.indicator.type"] = "ipv4-addr"
                ev["threat.indicator.ip"] = ip
                ev["threat.indicator.provider"] = hit["source"]
                ev["threat.indicator.confidence"] = hit["confidence"].capitalize()
                ev["threat.indicator.description"] = hit["description"]
                ev["event.risk_score"] = 90 if hit["confidence"] == "high" else 40

        s, d = ev.get("source.ip"), ev.get("destination.ip")
        if s:
            sp = ipaddress.ip_address(s).is_private
            dp = ipaddress.ip_address(d).is_private if d else True
            ev["network.direction"] = ("internal" if sp and dp else "inbound" if not sp and dp
                                       else "outbound" if sp else "external")
        return ev
