//! 本轮补齐的三项能力的**跨模块集成测试**（MySQL/SQL 方言、SNMP v3、Parquet 冷归档）。
//!
//! 设计约定：
//! * **不依赖 docker / 外部服务**：数据库与外部代理不参与，MySQL 路径验证的是"方言 SQL 拼装 + 驱动选择"，
//!   真实 MySQL 的端到端拉取由 `docker compose --profile mysql` + `agf-ingest` 实跑证明（见答复）；
//! * SNMP v3 的**线级兼容性**用 `tools/simulators/snmp_v3_trap.py`（纯标准库手写 USM 编码器）
//!   实际产出的报文 hex 作为固定向量——Rust 解析器必须能直接吃下这些字节，
//!   这样"模拟器 ↔ 接收器"就不是各说各话；
//! * Parquet 的证据是**真写文件 → 用 parquet 自己读回 → 比对行数与列名**（硬证据，不是进程内计数）。

use std::sync::Arc;

use agf_core::enums::{IngestProtocol, Severity};
use agf_core::event::Event;
use agf_core::ids::{Id, TenantId};
use agf_core::time::Timestamp;
use agf_ingest::coldarchive::{
    ColdArchiveConfig, ColdArchiver, ColdFormat, PARQUET_COLUMNS, archive_metrics, decode_batch, decode_parquet,
    encode_batch_with, encode_batch_with_fallback, encode_parquet, gzip, parquet_facts, retention_plan,
};
use agf_ingest::jdbc::{CursorType, SqlDialect, build_pull_sql_for, quote_identifier_for};
use agf_ingest::snmp::{AuthProtocol, EngineClock, UsmConfig, UsmStats, V3SecurityLevel, encode, parse_v3_message};

fn sample_events() -> Vec<Event> {
    ["2026-02-21T10:00:00Z", "2026-02-21T10:30:00Z", "2026-02-21T11:00:00Z", "2026-02-21T11:30:00Z"]
        .iter()
        .enumerate()
        .map(|(index, at)| {
            let mut event = Event::new(TenantId::default_tenant(), Id::new(), IngestProtocol::Syslog);
            if let Ok(ts) = Timestamp::parse_rfc3339(at) {
                event.time = ts;
            }
            event.ingested_at = event.time;
            event.severity = if index % 2 == 0 { Severity::High } else { Severity::Info };
            event.message = format!("集成测试事件 {index}");
            event.source_name = "integration".to_string();
            event.vendor = "generic".to_string();
            event.product = "json".to_string();
            event.host.name = Some(format!("edge-{index}"));
            event.raw_hash = agf_core::secret::content_hash(&event.message);
            event
        })
        .collect()
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("agf-{tag}-{}", uuid::Uuid::new_v4()));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

// ---------------------------------------------------------------------------
// 1) SNMP v3：Python 手写编码器 ↔ Rust 解析器（线级兼容）
// ---------------------------------------------------------------------------

/// `tools/simulators/snmp_v3_trap.py --dump-hex` 的真实输出（password=`maplesyrup`，
/// engineID=`80001f8880000000000002`，engineBoots=1，engineTime=100，user=`agf`，
/// varbind = snmpTrapOID.0 + sysUpTime.0）。
const PY_V3_NOAUTH: &str = "307f02010330100203100000020300ffe3040104020103041e301c040b80001f88800000000000020201010201640403616766040004003048040b80001f88800000000000020400a7370203100000020100020100302a3017060a2b06010603010104010006092b06010401bf080001300f06082b060102010103004303bc614e";
const PY_V3_AUTH_MD5: &str = "30818b02010330100203100000020300ffe3040105020103042a3028040b80001f88800000000000020201010201640403616766040c9b509d7c0cd8a0c231534bba04003048040b80001f88800000000000020400a7370203100000020100020100302a3017060a2b06010603010104010006092b06010401bf080001300f06082b060102010103004303bc614e";
const PY_V3_AUTH_SHA: &str = "30818b02010330100203100000020300ffe3040105020103042a3028040b80001f88800000000000020201010201640403616766040c8307544e75bf9bad7f3e49c704003048040b80001f88800000000000020400a7370203100000020100020100302a3017060a2b06010603010104010006092b06010401bf080001300f06082b060102010103004303bc614e";

fn decode_hex(text: &str) -> Vec<u8> {
    let cleaned: String = text.chars().filter(char::is_ascii_hexdigit).collect();
    cleaned
        .as_bytes()
        .chunks(2)
        .filter(|chunk| chunk.len() == 2)
        .map(|chunk| u8::from_str_radix(std::str::from_utf8(chunk).unwrap_or(""), 16).unwrap_or(0))
        .collect()
}

#[test]
fn python_simulator_v3_vectors_are_accepted_by_rust_parser() {
    // noAuthNoPriv
    let stats = UsmStats::new();
    let trap = parse_v3_message(&decode_hex(PY_V3_NOAUTH), &UsmConfig::no_auth(), &EngineClock::new(), &stats);
    assert!(trap.is_ok(), "noAuthNoPriv 向量必须被接受: {trap:?}");
    let Ok(trap) = trap else { return };
    assert_eq!(trap.version, "v3");
    assert_eq!(trap.user.as_deref(), Some("agf"));
    assert_eq!(trap.security_level.as_deref(), Some("noAuthNoPriv"));
    assert_eq!(trap.engine_id.as_deref(), Some("80001f8880000000000002"));
    assert_eq!(trap.trap_oid().as_deref(), Some("1.3.6.1.4.1.8072.0.1"));
    assert_eq!(trap.varbinds.len(), 2, "snmpTrapOID.0 + sysUpTime.0");
    assert_eq!(stats.snapshot().accepted_noauth, 1);

    // authNoPriv + HMAC-MD5-96
    let md5_config = UsmConfig::auth_no_priv("agf", AuthProtocol::Md5, "maplesyrup");
    assert!(md5_config.is_ok(), "{md5_config:?}");
    let Ok(md5_config) = md5_config else { return };
    let md5_stats = UsmStats::new();
    let md5 = parse_v3_message(&decode_hex(PY_V3_AUTH_MD5), &md5_config, &EngineClock::new(), &md5_stats);
    assert!(md5.is_ok(), "Python 手写 HMAC-MD5-96 必须被 Rust 校验通过: {md5:?}");
    assert_eq!(md5_stats.snapshot().accepted_auth, 1);
    assert_eq!(md5_stats.snapshot().wrong_digests, 0);

    // authNoPriv + HMAC-SHA-96
    let sha_config = UsmConfig::auth_no_priv("agf", AuthProtocol::Sha1, "maplesyrup");
    assert!(sha_config.is_ok(), "{sha_config:?}");
    let Ok(sha_config) = sha_config else { return };
    let sha_stats = UsmStats::new();
    let sha = parse_v3_message(&decode_hex(PY_V3_AUTH_SHA), &sha_config, &EngineClock::new(), &sha_stats);
    assert!(sha.is_ok(), "Python 手写 HMAC-SHA-96 必须被 Rust 校验通过: {sha:?}");
    assert_eq!(sha_stats.snapshot().accepted_auth, 1);

    // 交叉：MD5 向量送到只配 SHA 的接收侧必须被拒（协议不匹配不能放过）
    let crossed = parse_v3_message(&decode_hex(PY_V3_AUTH_MD5), &sha_config, &EngineClock::new(), &UsmStats::new());
    assert!(crossed.is_err(), "{crossed:?}");
}

#[test]
fn rust_encoder_and_python_encoder_produce_identical_bytes() {
    // 两个编码器（Rust `agf_ingest::snmp::encode` 与 Python 手写）必须逐字节一致，
    // 否则线级兼容只是巧合。
    let mut spec = encode::V3TrapSpec::new("agf", V3SecurityLevel::NoAuthNoPriv);
    spec.engine_boots = 1;
    spec.engine_time = 100;
    let rust_bytes = encode::v3_trap(&spec).unwrap_or_default();
    assert_eq!(hex(&rust_bytes), PY_V3_NOAUTH, "Rust 与 Python 的 noAuthNoPriv 报文必须逐字节一致");

    let mut md5 = encode::V3TrapSpec::new("agf", V3SecurityLevel::AuthNoPriv);
    md5.engine_boots = 1;
    md5.engine_time = 100;
    md5.auth_protocol = AuthProtocol::Md5;
    md5.auth_password = "maplesyrup".to_string();
    assert_eq!(hex(&encode::v3_trap(&md5).unwrap_or_default()), PY_V3_AUTH_MD5);

    let mut sha = encode::V3TrapSpec::new("agf", V3SecurityLevel::AuthNoPriv);
    sha.engine_boots = 1;
    sha.engine_time = 100;
    sha.auth_protocol = AuthProtocol::Sha1;
    sha.auth_password = "maplesyrup".to_string();
    assert_eq!(hex(&encode::v3_trap(&sha).unwrap_or_default()), PY_V3_AUTH_SHA);
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

// ---------------------------------------------------------------------------
// 2) 冷归档 Parquet：真写文件 → 用 parquet 读回（行数 + 列名）
// ---------------------------------------------------------------------------

#[test]
fn parquet_file_is_written_and_read_back_with_matching_rows_and_columns() {
    let dir = temp_dir("parquet");
    let path = dir.join("agf-events-1.parquet");
    let events = sample_events();
    let bytes = encode_parquet(&events);
    assert!(bytes.is_ok(), "{bytes:?}");
    let Ok(bytes) = bytes else { return };
    // 真落盘（"真实冷归档"的产物就是这个文件）
    assert!(std::fs::write(&path, &bytes).is_ok(), "Parquet 文件必须能落盘");

    // 用 parquet 自己读回：行数 + 列名（硬证据）
    let read_back = std::fs::read(&path).unwrap_or_default();
    assert_eq!(read_back.len(), bytes.len());
    let facts = parquet_facts(&read_back);
    assert!(facts.is_ok(), "{facts:?}");
    let Ok(facts) = facts else { return };
    assert_eq!(facts.rows, i64::try_from(events.len()).unwrap_or(-1), "读回行数必须一致");
    assert_eq!(facts.columns, PARQUET_COLUMNS.to_vec(), "读回列名必须一致");
    assert!(facts.columns_match_schema());
    assert_eq!(facts.row_groups, 1);
    assert!(facts.compressions.iter().all(|c| c.contains("SNAPPY")), "{:?}", facts.compressions);
    assert_eq!(read_back.get(..4), Some(b"PAR1".as_slice()));
    assert_eq!(read_back.get(read_back.len().saturating_sub(4)..), Some(b"PAR1".as_slice()));

    // 事件级无损回灌
    let restored = decode_parquet(&read_back);
    assert!(restored.is_ok(), "{restored:?}");
    let Ok(restored) = restored else { return };
    assert_eq!(restored.len(), events.len());
    for (before, after) in events.iter().zip(restored.iter()) {
        assert_eq!(before.id, after.id);
        assert_eq!(before.time, after.time);
        assert_eq!(before.message, after.message);
        assert_eq!(before.severity, after.severity);
        assert_eq!(before.host.name, after.host.name);
    }
    // 列名断言必须能真的失败（防"永远通过"的假测试）
    let mut wrong = facts.clone();
    wrong.columns.push("bogus".to_string());
    assert!(!wrong.columns_match_schema());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn parquet_facts_reject_non_parquet_bytes() {
    assert!(parquet_facts(b"this is not parquet at all").is_err());
    assert!(parquet_facts(&[]).is_err());
    assert!(decode_parquet(b"PAR1garbagePAR1").is_err());
}

#[tokio::test]
async fn archiver_writes_parquet_objects_and_reads_them_back() {
    let archiver =
        ColdArchiver::new(Arc::new(agf_storage::objectstore::MemoryObjectStore::new()), ColdArchiveConfig::default());
    let events = sample_events();
    let stored = archiver.archive_batch(&events).await;
    assert!(stored.is_ok(), "{stored:?}");
    let Ok(stored) = stored else { return };
    assert!(stored.key.ends_with(".parquet"), "{}", stored.key);
    assert_eq!(stored.content_type.as_deref(), Some("application/vnd.apache.parquet"));
    let back = archiver.read_batch(&stored.key).await;
    assert_eq!(back.map(|v| v.len()).ok(), Some(events.len()));
}

/// **真实冷归档到本地文件系统**：对象真正落成磁盘上的 `.parquet` 文件，
/// 再由 parquet 自己读回（行数 + 列名），并把证据 JSON 写到 `target/parquet-evidence/`，
/// 供端到端验证直接引用（`target/` 是构建目录，不入库）。
#[tokio::test]
async fn parquet_archive_lands_as_a_real_file_and_reads_back() {
    let root = temp_dir("parquet-archive");
    let store = agf_storage::objectstore::LocalFileObjectStore::new(&root);
    assert!(store.is_ok(), "{store:?}");
    let Ok(store) = store else { return };
    let archiver = ColdArchiver::new(Arc::new(store), ColdArchiveConfig::default());
    let events = sample_events();
    let stored = archiver.archive_batch(&events).await;
    assert!(stored.is_ok(), "{stored:?}");
    let Ok(stored) = stored else { return };
    assert_eq!(stored.backend, "local");
    assert!(stored.key.ends_with(".parquet"), "{}", stored.key);

    // 磁盘上的真实文件
    let path = root.join(&stored.key);
    assert!(path.is_file(), "冷归档必须真的落成文件: {}", path.display());
    let bytes = std::fs::read(&path).unwrap_or_default();
    assert!(bytes.starts_with(b"PAR1") && bytes.ends_with(b"PAR1"));

    // 用 parquet 自己读回：行数 + 列名一致
    let facts = parquet_facts(&bytes);
    assert!(facts.is_ok(), "{facts:?}");
    let Ok(facts) = facts else { return };
    assert_eq!(facts.rows, i64::try_from(events.len()).unwrap_or(-1));
    assert_eq!(facts.columns, PARQUET_COLUMNS.to_vec());
    assert!(facts.columns_match_schema());
    let restored = archiver.read_batch(&stored.key).await;
    let restored_len = restored.map(|v| v.len()).unwrap_or(0);
    assert_eq!(restored_len, events.len());

    // 证据 JSON（由真实读回结果生成，不是手写）
    let target_dir = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target"));
    let evidence_dir = target_dir.join("parquet-evidence");
    let _ = std::fs::create_dir_all(&evidence_dir);
    let report = serde_json::json!({
        "backend": stored.backend,
        "object_key": stored.key,
        "content_type": stored.content_type,
        "file_bytes": facts.file_bytes,
        "row_groups": facts.row_groups,
        "compressions": facts.compressions,
        "rows_written": events.len(),
        "rows_read_back": facts.rows,
        "columns_read_back": facts.columns,
        "columns_match_schema": facts.columns_match_schema(),
        "roundtrip_events": restored_len,
    });
    let _ = std::fs::write(evidence_dir.join("report.json"), serde_json::to_vec_pretty(&report).unwrap_or_default());
    let _ = std::fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------
// 3) 回落路径：Parquet 失败 → gzip NDJSON（绝不丢数据）
// ---------------------------------------------------------------------------

#[test]
fn parquet_failure_falls_back_to_gzip_and_still_roundtrips() {
    let events = sample_events();
    let failing = |_events: &[Event]| -> agf_core::error::DomainResult<Vec<u8>> {
        Err(agf_core::error::DomainError::Internal("集成测试注入的 Parquet 编码失败".to_string()))
    };
    let outcome = encode_batch_with(&events, ColdFormat::Parquet, &failing);
    assert!(outcome.is_ok(), "{outcome:?}");
    let Ok(outcome) = outcome else { return };
    assert_eq!(outcome.format, ColdFormat::NdjsonGzip);
    assert!(outcome.fallback_reason.unwrap_or_default().contains("集成测试注入"));
    assert_eq!(ColdFormat::sniff(&outcome.bytes), Some(ColdFormat::NdjsonGzip));
    assert!(outcome.bytes.starts_with(&[0x1f, 0x8b]));
    let restored = decode_batch(&outcome.bytes, ColdFormat::NdjsonGzip);
    assert_eq!(restored.map(|v| v.len()).ok(), Some(events.len()), "回落路径必须无损");

    // 显式请求 gzip 时也照常工作（回落之外的"正常降级"路径）
    let gz = encode_batch_with_fallback(&events, ColdFormat::NdjsonGzip);
    assert_eq!(gz.map(|o| o.format).ok(), Some(ColdFormat::NdjsonGzip));
    let ndjson = encode_batch_with_fallback(&events, ColdFormat::Ndjson);
    assert_eq!(ndjson.map(|o| o.format).ok(), Some(ColdFormat::Ndjson));
    // 回落计数必须真实增长（进程级指标）
    let before = archive_metrics().snapshot().fallbacks;
    let _ = encode_batch_with(&events, ColdFormat::Parquet, &failing);
    assert!(archive_metrics().snapshot().fallbacks > before);
}

#[tokio::test]
async fn fallback_object_key_and_content_type_follow_the_actual_format() {
    // 用 gzip 配置走一遍完整归档：对象键后缀 / content_type / 读回三者必须自洽
    let archiver = ColdArchiver::new(
        Arc::new(agf_storage::objectstore::MemoryObjectStore::new()),
        ColdArchiveConfig { format: ColdFormat::NdjsonGzip, ..ColdArchiveConfig::default() },
    );
    let events = sample_events();
    let stored = archiver.archive_batch(&events).await;
    assert!(stored.is_ok(), "{stored:?}");
    let Ok(stored) = stored else { return };
    assert!(stored.key.ends_with(".ndjson.gz"), "{}", stored.key);
    assert_eq!(stored.content_type.as_deref(), Some("application/gzip"));
    let back = archiver.read_batch(&stored.key).await;
    assert_eq!(back.map(|v| v.len()).ok(), Some(events.len()));
    // gzip 与 Parquet 的体积对比：两者都真实存在（信息性断言，不做性能承诺）
    let parquet = encode_parquet(&events).unwrap_or_default();
    let packed = gzip(&serde_json::to_vec(&events).unwrap_or_default()).unwrap_or_default();
    assert!(!parquet.is_empty() && !packed.is_empty());
}

#[test]
fn retention_plan_and_metrics_state_parquet_support_truthfully() {
    let plan = retention_plan(30, 365);
    assert!(plan.parquet_supported);
    assert!(plan.cold_key_template.ends_with(".parquet"));
    assert!(plan.note.contains("回落"));
    let text = archive_metrics().prometheus();
    for family in [
        "agf_ingest_coldarchive_bytes_total",
        "agf_ingest_coldarchive_objects_total",
        "agf_ingest_coldarchive_fallbacks_total",
        "agf_ingest_coldarchive_events_total",
        "agf_ingest_coldarchive_parquet_objects_total",
    ] {
        assert!(text.contains(&format!("# TYPE {family} counter")), "缺少 {family}");
    }
    assert_eq!(ColdFormat::default(), ColdFormat::Parquet);
    assert_eq!(ColdFormat::from_env(), ColdFormat::Parquet, "未设置 AGF_ARCHIVE_FORMAT 时默认 parquet");
}

// ---------------------------------------------------------------------------
// 4) SQL 拉取：MySQL 方言（SQL 拼装 + 驱动选择）
// ---------------------------------------------------------------------------

#[test]
fn mysql_dialect_composes_reusable_cursor_sql() {
    // 同一个基础查询，两种方言：游标语义一致，只有占位符/转型/引号/行 JSON 方式不同
    let base = "SELECT id, ts, severity, message FROM audit_log;";
    let pg = build_pull_sql_for(SqlDialect::Postgres, base, Some("id"), CursorType::Int, 500).unwrap_or_default();
    let my = build_pull_sql_for(SqlDialect::MySql, base, Some("id"), CursorType::Int, 500).unwrap_or_default();
    assert!(pg.contains("row_to_json(t)::text"), "{pg}");
    assert!(pg.contains(r#"WHERE ("id")::bigint > $1::bigint"#), "{pg}");
    assert!(my.contains("SELECT * FROM (SELECT id, ts, severity, message FROM audit_log) t"), "{my}");
    assert!(my.contains("WHERE CAST(`id` AS signed) > CAST(? AS signed)"), "{my}");
    assert!(my.ends_with("LIMIT 500"), "{my}");
    assert!(!my.contains("row_to_json") && !my.contains("$1"));

    // 时间游标：MySQL 没有 timestamptz ⇒ CAST(... AS datetime)（TIMESTAMP/DATETIME 列都适用）
    let ts = build_pull_sql_for(SqlDialect::MySql, "SELECT * FROM audit_log", Some("ts"), CursorType::Timestamp, 10)
        .unwrap_or_default();
    assert!(ts.contains("CAST(`ts` AS datetime)"), "{ts}");
    // 文本游标
    let text =
        build_pull_sql_for(SqlDialect::MySql, "SELECT * FROM t", Some("k"), CursorType::Text, 10).unwrap_or_default();
    assert!(text.contains("CAST(`k` AS char)"), "{text}");
    // 标识符校验在两种方言下都拦注入
    assert_eq!(quote_identifier_for("audit_log.id", SqlDialect::MySql).unwrap_or_default(), "`audit_log`.`id`");
    assert!(quote_identifier_for("id`; DROP TABLE audit_log", SqlDialect::MySql).is_err());
    assert!(build_pull_sql_for(SqlDialect::MySql, "SELECT 1", Some("id; --"), CursorType::Int, 1).is_err());
}

#[test]
fn dsn_scheme_selects_driver_and_reports_unsupported_scheme() {
    assert_eq!(SqlDialect::from_dsn("mysql://agf:pw@127.0.0.1:13306/aiguardfabric").ok(), Some(SqlDialect::MySql));
    assert_eq!(SqlDialect::from_dsn("postgres://agf:pw@127.0.0.1:5432/db").ok(), Some(SqlDialect::Postgres));
    assert_eq!(SqlDialect::from_dsn("postgresql://agf@pg/db").ok(), Some(SqlDialect::Postgres));
    // 口径修正（本轮）：Oracle **已接线**（`oracle` crate / OCI）⇒ `oracle://` 与 `oracle+tcps://`
    // 必须**选到 Oracle 方言**（不再是 NotImplemented/Config 报错），真机取数见
    // `tests/oracle_live.rs`（`AGF_E2E_ORACLE_DSN`）与 `tools/simulators/run_oracle_e2e.ps1`。
    assert_eq!(SqlDialect::from_dsn("oracle://agf:pw@127.0.0.1:1521/orcl").ok(), Some(SqlDialect::Oracle));
    assert_eq!(SqlDialect::from_dsn("oracle+tcps://agf@127.0.0.1:2484/orcl").ok(), Some(SqlDialect::Oracle));
    // 真正不受支持的 scheme 仍必须**显式**报错（绝不静默按 PostgreSQL 连），且错误文本点名它
    let unsupported = SqlDialect::from_dsn("sqlite:///tmp/a.db");
    assert!(unsupported.is_err(), "sqlite 不得静默按其它方言连：{unsupported:?}");
    let error = unsupported.err().map(|e| e.to_string()).unwrap_or_default();
    assert!(error.contains("sqlite"), "错误必须点名 sqlite：{error}");
    assert!(SqlDialect::from_dsn("").is_err());
    assert_eq!(SqlDialect::MySql.driver_label(), "sqlx/MySQL");
    assert_eq!(SqlDialect::MySql.placeholder(), "?");
    assert_eq!(SqlDialect::Postgres.placeholder(), "$1");
    assert_eq!(SqlDialect::Oracle.placeholder(), ":1");
    assert_eq!(CursorType::Timestamp.as_sql_cast_for(SqlDialect::MySql), "datetime");
    assert_eq!(CursorType::Timestamp.as_sql_cast_for(SqlDialect::Postgres), "timestamptz");
}
