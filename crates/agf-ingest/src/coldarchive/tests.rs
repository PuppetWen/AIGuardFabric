//! 冷归档单元测试：Parquet 往返、回落路径、对象键/内容类型与 Python 编码器逐字节一致性。

use super::*;
use agf_core::enums::{IngestProtocol, Severity};
use agf_core::ids::{Id, TenantId};

fn event(at: &str, severity: Severity) -> Event {
    let mut e = Event::new(TenantId::default_tenant(), Id::new(), IngestProtocol::Webhook);
    if let Ok(ts) = Timestamp::parse_rfc3339(at) {
        e.time = ts;
    }
    e.severity = severity;
    e.message = format!("事件 {at}");
    e.raw_hash = agf_core::secret::content_hash(&e.message);
    e.source_name = "unit-test".to_string();
    e.vendor = "generic".to_string();
    e.product = "json".to_string();
    e.host.name = Some("edge-1".to_string());
    e
}

fn sample() -> Vec<Event> {
    vec![
        event("2026-02-21T10:00:00Z", Severity::High),
        event("2026-02-21T10:30:00Z", Severity::Critical),
        event("2026-02-21T11:00:00Z", Severity::Low),
    ]
}

fn archiver() -> ColdArchiver {
    ColdArchiver::new(Arc::new(agf_storage::objectstore::MemoryObjectStore::new()), ColdArchiveConfig::default())
}

#[test]
fn default_format_is_parquet_and_env_parsing_is_forgiving() {
    let cfg = ColdArchiveConfig::default();
    assert_eq!(cfg.format, ColdFormat::Parquet, "默认必须是 Parquet");
    assert_eq!(ColdFormat::default(), ColdFormat::Parquet);
    assert!(ColdFormat::Parquet.is_implemented());
    assert!(ColdFormat::NdjsonGzip.is_implemented());
    assert_eq!(ColdFormat::parse("PARQUET"), Some(ColdFormat::Parquet));
    assert_eq!(ColdFormat::parse("ndjson-gzip"), Some(ColdFormat::NdjsonGzip));
    assert_eq!(ColdFormat::parse("ndjson.gz"), Some(ColdFormat::NdjsonGzip));
    assert_eq!(ColdFormat::parse("ndjson_gzip"), Some(ColdFormat::NdjsonGzip));
    assert_eq!(ColdFormat::parse("gzip"), Some(ColdFormat::NdjsonGzip));
    assert_eq!(ColdFormat::parse("ndjson"), Some(ColdFormat::Ndjson));
    assert_eq!(ColdFormat::parse("orc"), None);
    assert_eq!(ColdFormat::Parquet.as_str(), "parquet");
    assert_eq!(ColdFormat::NdjsonGzip.extension(), "ndjson.gz");
    assert_eq!(ColdFormat::Parquet.content_type(), "application/vnd.apache.parquet");
    assert_eq!(ColdFormat::Ndjson.content_type(), "application/x-ndjson");
}

#[test]
fn format_sniffing_distinguishes_gzip_parquet_and_ndjson() {
    let packed = gzip(b"{}").unwrap_or_default();
    assert_eq!(ColdFormat::sniff(&packed), Some(ColdFormat::NdjsonGzip));
    let mut fake_pq = b"PAR1".to_vec();
    fake_pq.extend_from_slice(&[0_u8; 16]);
    fake_pq.extend_from_slice(b"PAR1");
    assert_eq!(ColdFormat::sniff(&fake_pq), Some(ColdFormat::Parquet));
    assert_eq!(ColdFormat::sniff(b"{\"a\":1}\n"), Some(ColdFormat::Ndjson));
    assert_eq!(ColdFormat::sniff(b""), None);
}

#[test]
fn parquet_schema_covers_event_core_fields_and_maps_from_event() {
    // schema 文本里的列名必须与 PARQUET_COLUMNS 完全一致（**没有虚构字段**）
    assert_eq!(PARQUET_COLUMNS.len(), 13);
    for column in PARQUET_COLUMNS {
        assert!(PARQUET_SCHEMA.contains(column), "schema 缺少列 {column}");
    }
    for required in ["time", "tenant_id", "protocol", "host", "severity", "message", "raw_json"] {
        assert!(PARQUET_COLUMNS.contains(&required), "核心字段 {required} 必须入列");
    }
    assert!(PARQUET_SCHEMA.contains("TIMESTAMP(MILLIS,true)"), "{PARQUET_SCHEMA}");

    // 列值确实来自事件结构（不编造）：时间/租户/协议/主机/等级/消息/原始 JSON
    let events = sample();
    let bytes = encode_parquet(&events).unwrap_or_default();
    assert!(!bytes.is_empty());
    let facts = parquet_facts(&bytes);
    assert!(facts.is_ok(), "{facts:?}");
    let Ok(facts) = facts else { return };
    assert_eq!(facts.rows, 3);
    assert!(facts.columns_match_schema(), "{:?}", facts.columns);
    assert_eq!(facts.columns, PARQUET_COLUMNS.to_vec());
    assert_eq!(facts.row_groups, 1);
    assert!(facts.compressions.iter().all(|c| c.contains("SNAPPY")), "{:?}", facts.compressions);
    // 头部魔数
    assert_eq!(bytes.get(..4), Some(b"PAR1".as_slice()));
    assert_eq!(bytes.get(bytes.len().saturating_sub(4)..), Some(b"PAR1".as_slice()));
}

#[test]
fn parquet_roundtrip_is_lossless_and_column_names_match() {
    let events = sample();
    let bytes = encode_parquet(&events).unwrap_or_default();
    let back = decode_parquet(&bytes);
    assert!(back.is_ok(), "{back:?}");
    let Ok(back) = back else { return };
    assert_eq!(back.len(), events.len(), "行数必须一致");
    // 逐条无损：id / 时间 / 等级 / 消息 / 租户 / 协议 / raw_hash 全等
    for (original, restored) in events.iter().zip(back.iter()) {
        assert_eq!(original.id, restored.id);
        assert_eq!(original.time, restored.time);
        assert_eq!(original.severity, restored.severity);
        assert_eq!(original.message, restored.message);
        assert_eq!(original.tenant_id, restored.tenant_id);
        assert_eq!(original.protocol, restored.protocol);
        assert_eq!(original.raw_hash, restored.raw_hash);
        assert_eq!(original.source_name, restored.source_name);
        assert_eq!(original.host.name, restored.host.name);
    }
    // 列名与 schema 一致（"读回行数与列名一致"）
    let facts = parquet_facts(&bytes).unwrap_or(ParquetFacts {
        rows: -1,
        columns: Vec::new(),
        row_groups: 0,
        compressions: Vec::new(),
        file_bytes: 0,
    });
    assert_eq!(facts.rows, i64::try_from(events.len()).unwrap_or(-1));
    assert!(facts.columns_match_schema());
    // 坏数据必须报错而不是返回空
    assert!(decode_parquet(b"not parquet").is_err());
    assert!(parquet_facts(b"not parquet").is_err());
}

#[test]
fn parquet_failure_falls_back_to_gzip_and_is_counted() {
    let events = sample();
    let before = archive_metrics().snapshot().fallbacks;
    // 注入必然失败的 Parquet 编码器 ⇒ 必须回落 gzip 且带上原因
    let failing = |_events: &[Event]| -> DomainResult<Vec<u8>> {
        Err(DomainError::Internal("注入的编码失败".to_string()))
    };
    let outcome = encode_batch_with(&events, ColdFormat::Parquet, &failing);
    assert!(outcome.is_ok(), "{outcome:?}");
    let Ok(outcome) = outcome else { return };
    assert_eq!(outcome.format, ColdFormat::NdjsonGzip, "必须回落到 gzip");
    assert!(outcome.fallback_reason.unwrap_or_default().contains("注入的编码失败"));
    assert!(outcome.bytes.starts_with(&[0x1f, 0x8b]), "回落内容必须是 gzip");
    assert_eq!(ColdFormat::sniff(&outcome.bytes), Some(ColdFormat::NdjsonGzip));
    // 回落内容照样能读回（格式降级 ≠ 数据丢失）
    let back = decode_batch(&outcome.bytes, ColdFormat::NdjsonGzip);
    assert_eq!(back.map(|v| v.len()).ok(), Some(events.len()));
    assert!(archive_metrics().snapshot().fallbacks > before, "回落必须计数");

    // 请求 gzip/ndjson 时**绝不**尝试 Parquet（也不会回落）
    let direct = encode_batch_with(&events, ColdFormat::NdjsonGzip, &failing);
    assert_eq!(direct.map(|o| o.format).ok(), Some(ColdFormat::NdjsonGzip));
    assert_eq!(
        encode_batch_with(&events, ColdFormat::Ndjson, &failing).map(|o| o.format).ok(),
        Some(ColdFormat::Ndjson)
    );
}

#[tokio::test]
async fn archive_and_read_roundtrip() {
    let a = archiver();
    let events = vec![event("2026-02-21T10:00:00Z", Severity::High), event("2026-02-21T10:30:00Z", Severity::Critical)];
    let stored = a.archive_batch(&events).await;
    assert!(stored.is_ok(), "{stored:?}");
    let Ok(stored) = stored else { return };
    assert_eq!(stored.backend, "memory");
    assert_eq!(stored.content_type.as_deref(), Some("application/vnd.apache.parquet"));
    assert!(stored.key.ends_with(".parquet"), "{}", stored.key);
    let back = a.read_batch(&stored.key).await;
    assert!(back.is_ok(), "{back:?}");
    let Ok(back) = back else { return };
    assert_eq!(back.len(), 2);
    assert_eq!(back.first().map(|e| e.severity), Some(Severity::High));
    assert_eq!(back.get(1).map(|e| e.severity), Some(Severity::Critical));
    assert_eq!(back.first().map(|e| e.id), events.first().map(|e| e.id));
    let listed = a.list_day("2026-02-21", 10).await.unwrap_or_default();
    assert_eq!(listed.len(), 1);
    assert!(!a.list_day("2026-02-22", 10).await.unwrap_or_default().iter().any(|k| k.contains("2026-02-21")));
}

#[tokio::test]
async fn fallback_archive_keeps_key_suffix_and_content_in_sync() {
    // 回落路径：对象键后缀 + content_type 必须跟随**实际格式**（不名不符实）
    let cfg = ColdArchiveConfig { format: ColdFormat::NdjsonGzip, ..ColdArchiveConfig::default() };
    let a = ColdArchiver::new(Arc::new(agf_storage::objectstore::MemoryObjectStore::new()), cfg);
    let stored = a.archive_batch(&[event("2026-02-21T12:00:00Z", Severity::Low)]).await;
    assert!(stored.is_ok(), "{stored:?}");
    let Ok(stored) = stored else { return };
    assert!(stored.key.ends_with(".ndjson.gz"), "{}", stored.key);
    assert_eq!(stored.content_type.as_deref(), Some("application/gzip"));
    let back = a.read_batch(&stored.key).await;
    assert_eq!(back.map(|v| v.len()).ok(), Some(1));
}

#[tokio::test]
async fn empty_batch_and_oversize_are_rejected() {
    let a = archiver();
    let empty = a.archive_batch(&[]).await;
    assert!(matches!(empty, Err(DomainError::Validation(_))), "{empty:?}");
    let cfg = ColdArchiveConfig { max_batch: 1, ..ColdArchiveConfig::default() };
    let small = ColdArchiver::new(Arc::new(agf_storage::objectstore::MemoryObjectStore::new()), cfg);
    let too_many = small
        .archive_batch(&[event("2026-02-21T10:00:00Z", Severity::Low), event("2026-02-21T10:00:01Z", Severity::Low)])
        .await;
    assert!(matches!(too_many, Err(DomainError::Validation(_))), "{too_many:?}");
}

#[test]
fn key_is_date_and_hour_partitioned() {
    let a = archiver();
    let ts = Timestamp::parse_rfc3339("2026-02-21T10:23:45Z").unwrap_or_else(|_| Timestamp::now());
    let key = a.archive_key(&ts, 7);
    assert!(key.starts_with("agf-events/dt=2026-02-21/hour=10/"), "{key}");
    assert!(key.ends_with(".parquet"), "默认格式后缀必须是 .parquet：{key}");
    assert!(key.contains("00007"), "{key}");
    let other = a.archive_key(&ts, 7);
    assert_ne!(key, other, "同一小时的对象键必须唯一（含随机 id）");
    // 显式指定格式时后缀跟随格式
    assert!(a.archive_key_for(&ts, 7, ColdFormat::NdjsonGzip).ends_with(".ndjson.gz"));
    assert!(a.archive_key_for(&ts, 7, ColdFormat::Ndjson).ends_with(".ndjson"));
}

#[test]
fn gzip_roundtrip_and_corruption_detection() {
    let data = "第一行\n第二行\n".repeat(50);
    let packed = gzip(data.as_bytes());
    assert!(packed.is_ok());
    let Ok(packed) = packed else { return };
    assert!(packed.len() < data.len(), "压缩应有效");
    assert_eq!(gunzip(&packed).ok().and_then(|v| String::from_utf8(v).ok()), Some(data));
    assert!(gunzip(b"not gzip at all").is_err());
}

#[test]
fn ndjson_roundtrip_without_compression() {
    let events = vec![event("2026-02-21T11:00:00Z", Severity::Medium)];
    let plain = encode_batch(&events, ColdFormat::Ndjson);
    assert!(plain.is_ok());
    let Ok(plain) = plain else { return };
    assert!(plain.ends_with(b"\n"));
    let text = String::from_utf8_lossy(&plain);
    assert_eq!(text.lines().count(), 1);
    assert_eq!(decode_batch(&plain, ColdFormat::Ndjson).map(|v| v.len()).ok(), Some(1));
    assert!(decode_batch(b"{\"not\":\"an event\"}", ColdFormat::Ndjson).is_err());
}

#[test]
fn retention_plan_documents_parquet_support() {
    let plan = retention_plan(30, 365);
    assert_eq!(plan.hot_days, 30);
    assert_eq!(plan.cold_days, 365);
    assert!(plan.hot_backend.contains("clickhouse"));
    assert!(plan.cold_key_template.contains("dt=YYYY-MM-DD"));
    assert!(plan.cold_key_template.ends_with(".parquet"), "{}", plan.cold_key_template);
    assert_eq!(plan.steps.len(), 5);
    assert!(plan.parquet_supported, "Parquet 必须如实标注为支持");
    assert!(plan.note.contains("回落"), "{}", plan.note);
    let via_archiver = ColdArchiver::retention_plan(7, 90);
    assert_eq!(via_archiver.hot_days, 7);
    assert!(via_archiver.lifecycle_rule.contains("90 天后"));
}

#[tokio::test]
async fn archive_metrics_render_prometheus_text() {
    // 自包含：自己归档一次，不依赖其它用例的执行顺序（进程级计数器是共享的）
    let a = archiver();
    let stored = a.archive_batch(&[event("2026-02-21T13:00:00Z", Severity::Medium)]).await;
    assert!(stored.is_ok(), "{stored:?}");
    let text = archive_metrics().prometheus();
    for name in [
        "agf_ingest_coldarchive_objects_total",
        "agf_ingest_coldarchive_bytes_total",
        "agf_ingest_coldarchive_events_total",
        "agf_ingest_coldarchive_fallbacks_total",
        "agf_ingest_coldarchive_parquet_objects_total",
    ] {
        assert!(text.contains(&format!("# TYPE {name} counter")), "缺少指标族 {name}");
    }
    let snapshot = archive_metrics().snapshot();
    assert!(snapshot.objects >= 1);
    assert!(snapshot.bytes > 0, "归档字节数必须大于 0");
    assert!(snapshot.events >= 1);
    assert!(snapshot.parquet_objects >= 1);
}

#[test]
fn default_config_matches_spec_defaults() {
    let cfg = ColdArchiveConfig::default();
    assert_eq!(cfg.hot_days, 30, "热层默认 30 天（§4.5）");
    assert_eq!(cfg.cold_days, 365);
    assert_eq!(cfg.max_batch, 10_000);
    assert_eq!(cfg.format, ColdFormat::Parquet);
    assert_eq!(ColdFormat::NdjsonGzip.extension(), "ndjson.gz");
}

mod arrow;
mod replay;
