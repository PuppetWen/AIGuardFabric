//! 冷归档 **arrow 列式回灌 on MinIO/S3** 真机用例（默认 `#[ignore]`，需 `AGF_S3_*` 与可达的 MinIO）。
//!
//! 覆盖四件事（每一步都打印可观测量，`--nocapture` 即为证据）：
//!   (a) 写出 Parquet → **arrow `RecordBatchReader`** 读回 → 逐列与写出值比对（行数/列名/单元格）；
//!   (b) 回灌 N 条 ⇒ sink 计数 = N；再回灌一次 ⇒ 入库 0（`raw_hash` 账本幂等）；
//!   (c) 时间窗过滤与租户过滤生效（`filtered` 如实计数）；
//!   (d) `AGF_ARCHIVE_FORMAT` 的 gzip 回落对象照样能回灌（不依赖 arrow）。
//!
//! 运行方式（服务端为 `docker compose` 的 `agf-minio`）：
//!
//! ```text
//! set AGF_S3_ENDPOINT=http://127.0.0.1:9000
//! set AGF_S3_ACCESS_KEY=agfminio
//! set AGF_S3_SECRET_KEY=<见 .env>
//! set AGF_S3_BUCKET=agf-evidence
//! set AGF_S3_FORCE_PATH_STYLE=1
//! cargo test -p agf-ingest --test coldarchive_arrow_replay -- --ignored --nocapture
//! ```
//!
//! 未配置 `AGF_S3_*` 时用例直接跳过（不依赖 docker，`cargo test` 默认也不跑 `#[ignore]`）。

#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used, clippy::print_stdout)]

use std::sync::Arc;

use agf_core::enums::{IngestProtocol, Severity};
use agf_core::event::Event;
use agf_core::ids::{Id, TenantId};
use agf_core::time::Timestamp;
use agf_ingest::coldarchive::{
    ColdArchiveConfig, ColdArchiver, ColdFormat, ColdReplayer, PARQUET_COLUMNS, ReplayFilter, ReplayLedger,
    arrow_facts, decode_parquet_arrow, event_column_text, object_store_from_env, parquet_facts, read_parquet_arrow,
};
use agf_ingest::pipeline::{InMemorySink, Sink};

/// 造一条事件（内容含序号，避免流水线/账本侧的意外同源去重）。
fn event(at: &str, severity: Severity, tenant: TenantId, index: usize) -> Event {
    let mut item = Event::new(tenant, Id::new(), IngestProtocol::Webhook);
    item.time = Timestamp::parse_rfc3339(at).expect("时间字面量必须合法");
    item.ingested_at = item.time;
    item.severity = severity;
    item.message = format!("arrow-replay 第 {index} 条事件 {at}");
    item.raw_hash = agf_core::secret::content_hash(&item.message);
    item.source_name = "coldarchive-arrow-live".to_string();
    item.vendor = "generic".to_string();
    item.product = "json".to_string();
    item.host.name = Some(format!("edge-{index}"));
    item
}

fn s3_configured() -> bool {
    ["AGF_S3_ENDPOINT", "AGF_S3_ACCESS_KEY", "AGF_S3_SECRET_KEY", "AGF_S3_BUCKET"]
        .iter()
        .all(|key| std::env::var(key).map(|value| !value.trim().is_empty()).unwrap_or(false))
}

#[tokio::test]
#[ignore = "真机用例：需要 AGF_S3_* 指向可达的 MinIO/S3（见文件头运行方式）"]
async fn arrow_write_read_replay_roundtrip_on_minio() {
    if !s3_configured() {
        println!("[skip] 未配置 AGF_S3_*（endpoint/access/secret/bucket），跳过 MinIO 真机用例");
        return;
    }
    let (store, note) = object_store_from_env().await.expect("对象存储构造失败");
    println!("[env] 对象存储后端={} 说明={:?}", store.backend(), note);
    assert_eq!(store.backend(), "s3", "AGF_S3_* 齐全时必须选中 S3/MinIO 后端");

    // ---- 归档一批事件（Parquet，默认 SNAPPY）----
    let config = ColdArchiveConfig { prefix: "agf-events-verify".to_string(), ..ColdArchiveConfig::default() };
    let archiver = ColdArchiver::new(store, config);
    let tenant_a = TenantId::new();
    let tenant_b = TenantId::new();
    let events = vec![
        event("2026-02-21T10:00:00Z", Severity::High, tenant_a, 1),
        event("2026-02-21T10:30:00Z", Severity::Critical, tenant_a, 2),
        event("2026-02-21T11:00:00Z", Severity::Low, tenant_b, 3),
        event("2026-02-22T09:00:00Z", Severity::Medium, tenant_b, 4),
    ];
    let stored = archiver.archive_batch(&events).await.expect("归档到 MinIO 失败");
    println!("AGF_ARCHIVE_KEY={}", stored.key);
    println!("AGF_ARCHIVE_TENANT_B={tenant_b}");
    println!("AGF_ARCHIVE_TENANT_A={tenant_a}");
    println!(
        "[a] 写出对象 key={} 字节={} 后端={} 内容类型={:?}",
        stored.key, stored.size, stored.backend, stored.content_type
    );
    assert_eq!(stored.backend, "s3");
    assert!(stored.key.ends_with(".parquet"), "默认格式必须是 Parquet：{}", stored.key);

    // ---- (a) arrow 列式读回：逐列与写出值比对 ----
    let bytes = archiver.store().get(&stored.key).await.expect("从 MinIO 下载 Parquet 失败");
    let facts = parquet_facts(&bytes).expect("Parquet 文件级事实读取失败");
    println!(
        "[a] 文件级事实：行数={} 行组={} 压缩={:?} 字节={}",
        facts.rows, facts.row_groups, facts.compressions, facts.file_bytes
    );
    assert_eq!(facts.rows, i64::try_from(events.len()).unwrap_or(-1));
    assert!(facts.columns_match_schema());
    assert!(facts.compressions.iter().all(|entry| entry.contains("SNAPPY")), "{:?}", facts.compressions);

    let readback = read_parquet_arrow(&bytes, 2, events.len()).expect("arrow 读回失败");
    println!("[a] {}", readback.facts.report());
    assert_eq!(readback.facts.rows, events.len());
    assert!(readback.facts.columns_match_schema(), "{:?}", readback.facts.column_names());
    assert_eq!(readback.events.len(), events.len());
    assert!(readback.all_columns_match_events(), "{}", readback.mismatch_summary());
    for (row, original) in events.iter().enumerate() {
        let expected = event_column_text(original).expect("列投影失败");
        assert_eq!(expected.len(), PARQUET_COLUMNS.len());
        for (column, want) in &expected {
            let got = readback.facts.cell(column, row).unwrap_or("<缺失>");
            assert_eq!(got, want, "第 {} 行 {column} 列读回值 != 写出值", row + 1);
        }
        println!(
            "[a] 第 {} 行核对通过：time={} tenant={} severity={} message={:?}",
            row + 1,
            readback.facts.cell("time", row).unwrap_or("-"),
            readback.facts.cell("tenant_id", row).unwrap_or("-"),
            readback.facts.cell("severity", row).unwrap_or("-"),
            readback.facts.cell("message", row).unwrap_or("-"),
        );
    }
    // arrow 读回与低层行式读回逐条一致（口径不漂移）
    let arrow_only = decode_parquet_arrow(&bytes).expect("arrow 事件还原失败");
    assert_eq!(arrow_only.len(), readback.events.len());
    for (left, right) in arrow_only.iter().zip(readback.events.iter()) {
        assert_eq!(left.id, right.id);
        assert_eq!(left.raw_hash, right.raw_hash);
        assert_eq!(left.time, right.time);
    }

    // ---- (b) 回灌：N 条入库；再灌一次 0 条（幂等）----
    let sink = Arc::new(InMemorySink::new());
    let replayer = ColdReplayer::new(archiver, Arc::clone(&sink) as Arc<dyn Sink>);
    let mut ledger = ReplayLedger::in_memory();
    let first = replayer.replay_key(&stored.key, &ReplayFilter::all(), &mut ledger).await.expect("回灌失败");
    println!("[b] 第一次回灌：{}", first.summary());
    assert_eq!(first.objects, 1);
    assert_eq!(first.arrow_objects, 1, "回灌必须走 arrow 列式读回（arrow_objects=1）");
    assert_eq!(first.replayed, events.len());
    assert_eq!(sink.event_count(tenant_a).await.unwrap_or(0), 4, "InMemorySink 计数为全部事件");

    let second = replayer.replay_key(&stored.key, &ReplayFilter::all(), &mut ledger).await.expect("第二次回灌失败");
    println!("[b] 第二次回灌（同账本）：{}", second.summary());
    assert_eq!(second.replayed, 0, "同批不得重复入库");
    assert_eq!(second.duplicates, events.len());
    assert_eq!(sink.event_count(tenant_a).await.unwrap_or(0), 4, "sink 计数不得增长");

    // ---- (c) 过滤：时间窗 + 租户（各自用独立 sink：InMemorySink 自身按事件 id 幂等，
    //          复用同一个 sink 会让"入库数"反映 sink 判重而不是过滤效果）----
    let window_sink = Arc::new(InMemorySink::new());
    let window_replayer = ColdReplayer::new(
        ColdArchiver::new(
            Arc::clone(replayer.archiver().store()),
            ColdArchiveConfig { prefix: "agf-events-verify".to_string(), ..ColdArchiveConfig::default() },
        ),
        Arc::clone(&window_sink) as Arc<dyn Sink>,
    );
    let mut window_ledger = ReplayLedger::in_memory();
    let window = ReplayFilter::window(
        ReplayFilter::parse_time("2026-02-21T10:15:00Z", false).expect("时间字面量"),
        ReplayFilter::parse_time("2026-02-21T11:30:00Z", false).expect("时间字面量"),
        None,
    );
    let filtered = window_replayer.replay_key(&stored.key, &window, &mut window_ledger).await.expect("窗口回灌失败");
    println!("[c] 时间窗回灌：{}", filtered.summary());
    assert_eq!(filtered.replayed, 2);
    assert_eq!(filtered.filtered, 2);
    assert_eq!(window_sink.event_count(tenant_a).await.unwrap_or(0), 2);

    let tenant_sink = Arc::new(InMemorySink::new());
    let tenant_replayer = ColdReplayer::new(
        ColdArchiver::new(
            Arc::clone(replayer.archiver().store()),
            ColdArchiveConfig { prefix: "agf-events-verify".to_string(), ..ColdArchiveConfig::default() },
        ),
        Arc::clone(&tenant_sink) as Arc<dyn Sink>,
    );
    let mut tenant_ledger = ReplayLedger::in_memory();
    let only_b = tenant_replayer
        .replay_key(&stored.key, &ReplayFilter::for_tenant(tenant_b), &mut tenant_ledger)
        .await
        .expect("租户回灌失败");
    println!("[c] 租户回灌：{}", only_b.summary());
    assert_eq!(only_b.replayed, 2);
    assert_eq!(only_b.filtered, 2);
    let landed = tenant_sink.events().expect("读取 sink 事件失败");
    assert!(landed.iter().all(|item| item.tenant_id == tenant_b), "非目标租户不得入库");
    // sink 自身按 id 幂等的口径要如实暴露（第二次同 sink 回灌 ⇒ sink_skipped 而非静默丢）
    let mut again_ledger = ReplayLedger::in_memory();
    let again = tenant_replayer
        .replay_key(&stored.key, &ReplayFilter::for_tenant(tenant_b), &mut again_ledger)
        .await
        .expect("重复回灌同一 sink 失败");
    println!("[c] 同 sink 重复回灌（新账本）：{}", again.summary());
    assert_eq!(again.replayed, 0);
    assert_eq!(again.sink_skipped, 2, "sink 判重必须计入 sink_skipped");

    // ---- (d) gzip 回落对象照样回灌（不依赖 arrow）----
    let gzip_config = ColdArchiveConfig { format: ColdFormat::NdjsonGzip, ..ColdArchiveConfig::default() };
    let gzip_archiver = ColdArchiver::new(Arc::clone(replayer.archiver().store()), gzip_config);
    let gzip_stored = gzip_archiver.archive_batch(&events).await.expect("gzip 归档失败");
    println!("[d] gzip 回落对象 key={}（后缀必须跟随实际格式）", gzip_stored.key);
    println!("AGF_ARCHIVE_GZIP_KEY={}", gzip_stored.key);
    assert!(gzip_stored.key.ends_with(".ndjson.gz"));
    let gzip_sink = Arc::new(InMemorySink::new());
    let gzip_replayer = ColdReplayer::new(gzip_archiver, Arc::clone(&gzip_sink) as Arc<dyn Sink>);
    let mut gzip_ledger = ReplayLedger::in_memory();
    let gzip_report = gzip_replayer
        .replay_key(&gzip_stored.key, &ReplayFilter::all(), &mut gzip_ledger)
        .await
        .expect("gzip 回灌失败");
    println!("[d] gzip 回灌：{}", gzip_report.summary());
    assert_eq!(gzip_report.arrow_objects, 0, "gzip 对象没有列式读回");
    assert_eq!(gzip_report.replayed, events.len());
    assert_eq!(gzip_sink.event_count(tenant_a).await.unwrap_or(0), 4);

    // 单列事实抽样（供报告引用）
    let samples = arrow_facts(&bytes, 2).expect("arrow 列事实失败");
    for name in ["time", "tenant_id", "severity", "raw_hash"] {
        println!(
            "[a] 列 {name} 前两格：{:?}",
            samples.columns.iter().find(|column| column.name == name).map(|column| column.samples.clone())
        );
    }
}
