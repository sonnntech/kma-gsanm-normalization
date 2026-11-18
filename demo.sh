#!/usr/bin/env bash
# Kịch bản demo ~10 phút. Nhấn Enter để chuyển bước.
set -e
cd "$(dirname "$0")"
step() { echo; echo -e "\033[1;44m  $1  \033[0m"; read -r -p "  (Enter) " _; }

step "BƯỚC 1/5 - Log thô từ 5 nguồn GSANM (định dạng, tên trường, múi giờ khác nhau)"
for f in linux_auth.log apache_access.log suricata_eve.json fortigate.log windows_security.json; do
  echo -e "\n\033[1;33m# samples/$f\033[0m"; grep -m1 185.220.101.45 "samples/$f" | cut -c1-230
done

step "BƯỚC 2/5 - Chạy pipeline chuẩn hóa -> ECS"
python3 normalize.py

step "BƯỚC 3/5 - Trước / Sau: cùng một IP tấn công ở từng nguồn"
python3 normalize.py --show 185.220.101.45

step "BƯỚC 4/5 - Tương quan đa nguồn: không làm được trên log thô, 1 câu SQL sau chuẩn hóa"
python3 eval/correlate.py

step "BƯỚC 5/5 - Đánh giá: parse rate, độ phủ trường, dedup, throughput"
python3 eval/metrics.py | head -12
