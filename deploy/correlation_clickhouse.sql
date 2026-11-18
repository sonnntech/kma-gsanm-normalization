-- Luật tương quan đa nguồn (bản ClickHouse): IP từ Internet có hành vi thất bại/cảnh báo
-- ở >= 3 nguồn khác nhau trong cùng cửa sổ 15 phút.
SELECT
    source_ip,
    toStartOfInterval(timestamp, INTERVAL 15 MINUTE) AS window_start,
    uniqExact(event_dataset)                         AS so_nguon,
    count()                                          AS so_su_kien,
    groupUniqArray(event_dataset)                    AS cac_nguon,
    any(threat_indicator_provider)                   AS threat_intel
FROM gsanm.events
WHERE network_direction = 'inbound'
  AND (event_outcome = 'failure' OR event_kind = 'alert')
GROUP BY source_ip, window_start
HAVING so_nguon >= 3
ORDER BY so_nguon DESC, so_su_kien DESC;
