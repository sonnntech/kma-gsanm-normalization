# So sánh các lược đồ (schema) chuẩn hóa dữ liệu GSANM

## Cùng một khái niệm, mỗi chuẩn đặt tên một kiểu

| Khái niệm | ECS (Elastic) | OCSF | Splunk CIM | CEF (ArcSight) | LEEF (QRadar) |
|---|---|---|---|---|---|
| Thời điểm sự kiện | `@timestamp` | `time` (epoch ms) | `_time` | `rt` | `devTime` |
| IP nguồn | `source.ip` | `src_endpoint.ip` | `src` / `src_ip` | `src` | `src` |
| Cổng nguồn | `source.port` | `src_endpoint.port` | `src_port` | `spt` | `srcPort` |
| IP đích | `destination.ip` | `dst_endpoint.ip` | `dest` | `dst` | `dst` |
| Tài khoản | `user.name` | `actor.user.name` / `user.name` | `user` | `suser` / `duser` | `usrName` |
| Kết quả | `event.outcome` | `status_id` / `status` | `action` (success/failure) | `outcome` | – |
| Mức độ | `event.severity` | `severity_id` (0–6) | `severity` | `Severity` (0–10) | `sev` (1–10) |
| Phân loại | `event.category` + `event.type` | `category_uid` + `class_uid` | Data model + tag | `cat` | `cat` |
| Bản gốc | `event.original` | `raw_data` | `_raw` | – | – |

## Đặc điểm

| Tiêu chí | ECS | OCSF | Splunk CIM | CEF / LEEF |
|---|---|---|---|---|
| Bản chất | Schema trường (field set) | Schema theo lớp sự kiện (event class) | Data model trên search-time | Định dạng truyền log |
| Mức độ cấu trúc | Lồng nhau, ~800 trường | Lồng nhau, có class/category/profile | Phẳng | Header cố định + extension key=value |
| Mở / trung lập | Mở (Apache 2.0), đã góp vào OpenTelemetry | Mở, nhiều vendor (AWS, Splunk, IBM…) | Gắn với Splunk | Gắn với ArcSight / QRadar |
| Áp dụng khi | Thu thập về Elastic, ClickHouse, OpenSearch | Security Lake, trao đổi đa vendor | Đang dùng Splunk ES | Thiết bị chỉ xuất được syslog CEF/LEEF |

**Lựa chọn trong thực nghiệm:** ECS, vì nó cụ thể, có taxonomy `event.*` rõ ràng, tài liệu đầy đủ và được nhiều
công cụ mã nguồn mở hỗ trợ. Ánh xạ ECS → OCSF chủ yếu là đổi tên trường, nên có thể bổ sung sau bằng cách
thêm một file mapping thứ hai.
