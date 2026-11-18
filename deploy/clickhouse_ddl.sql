-- Kho lưu trữ sự kiện GSANM đã chuẩn hóa ECS trên ClickHouse
CREATE DATABASE IF NOT EXISTS gsanm;

CREATE TABLE IF NOT EXISTS gsanm.events
(
    timestamp                    DateTime64(3, 'UTC'),
    event_dataset                LowCardinality(String),
    event_kind                   LowCardinality(String),
    event_category               Array(LowCardinality(String)),
    event_action                 LowCardinality(Nullable(String)),
    event_outcome                LowCardinality(Nullable(String)),
    event_severity               Nullable(UInt8),
    event_risk_score             Nullable(UInt8),
    source_ip                    Nullable(IPv4),
    source_port                  Nullable(UInt16),
    source_geo_country_iso_code  LowCardinality(Nullable(String)),
    destination_ip               Nullable(IPv4),
    destination_port             Nullable(UInt16),
    user_name                    Nullable(String),
    host_name                    LowCardinality(Nullable(String)),
    observer_product             LowCardinality(String),
    rule_name                    Nullable(String),
    url_original                 Nullable(String),
    threat_indicator_provider    LowCardinality(Nullable(String)),
    network_direction            LowCardinality(Nullable(String)),
    doc                          String CODEC(ZSTD(3))          -- bản ECS đầy đủ (JSON)
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (event_dataset, timestamp)
TTL toDateTime(timestamp) + INTERVAL 180 DAY;
