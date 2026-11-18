# Kết quả đánh giá chuẩn hóa GSANM -> ECS

| Nguồn | Dòng | Parse rate | Lỗi parse | Trùng bị loại | Lỗi thời gian | Độ phủ trường lõi | EPS |
|---|---:|---:|---:|---:|---:|---:|---:|
| linux_auth | 2,082 | 99.90% | 2 | 20 | 0 | 95.8% | 16,736 |
| apache | 2,043 | 99.90% | 2 | 20 | 0 | 100.0% | 15,548 |
| suricata | 2,034 | 99.90% | 2 | 20 | 0 | 100.0% | 14,234 |
| fortigate | 2,061 | 99.95% | 1 | 20 | 0 | 100.0% | 11,004 |
| windows | 2,046 | 99.95% | 1 | 20 | 0 | 100.0% | 19,104 |

**Tổng:** 10,266 dòng thô → 10,158 sự kiện ECS trong 0.733 s (~14,010 EPS, Python đơn luồng).

## Độ phủ từng trường lõi

| Nguồn | @timestamp | event.dataset | event.category | event.outcome | source.ip | host.name|observer.name | user.name|destination.ip|url.original |
|---|---:|---:|---:|---:|---:|---:|---:|
| system.auth | 100% | 100% | 100% | 96% | 96% | 100% | 100% |
| apache.access | 100% | 100% | 100% | 100% | 100% | 100% | 100% |
| suricata.eve | 100% | 100% | 100% | 100% | 100% | 100% | 100% |
| fortinet.firewall | 100% | 100% | 100% | 100% | 100% | 100% | 100% |
| windows.security | 100% | 100% | 100% | 100% | 100% | 100% | 100% |

## Ví dụ dòng không parse được

- `linux_auth`: `'<garbage>\x00\x00'`
- `linux_auth`: `'web01 sshd: truncated'`
- `apache`: `'- - - [bad date] "GET'`
- `apache`: `'\\x16\\x03\\x01 TLS handshake on HTTP port'`
- `suricata`: `'not json'`
- `suricata`: `'{"timestamp": "2026-11-10T01:00:00", "src_ip": '`
- `fortigate`: `'date=2026-11-10 truncated'`
- `windows`: `'{"EventID": 4624, "TimeCreated": '`
