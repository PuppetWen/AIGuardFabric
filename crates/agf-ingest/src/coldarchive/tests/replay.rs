//! 冷归档**回灌**用例：入库计数、幂等账本（含跨进程落盘）、时间/租户过滤、回落对象、前缀回灌与报告。
//!
//! 夹具（`event` / `sample` / `archiver`）来自父模块 `coldarchive::tests`。

use super::*;
use crate::pipeline::{InMemorySink, Sink};

/// 造一个"归档器 + 内存 sink"的回灌环境。
fn replayer(format: ColdFormat) -> (ColdArchiver, Arc<InMemorySink>, Arc<dyn Sink>) {
    let cfg = ColdArchiveConfig { format, ..ColdArchiveConfig::default() };
    let archiver = ColdArchiver::new(Arc::new(agf_storage::objectstore::MemoryObjectStore::new()), cfg);
    let sink = Arc::new(InMemorySink::new());
    let boxed: Arc<dyn Sink> = Arc::clone(&sink) as Arc<dyn Sink>;
    (archiver, sink, boxed)
}

/// 回灌 N 条后 sink 计数 = N；用**同一账本**再灌一次 = 0（幂等，raw_hash 去重）。
#[tokio::test]
async fn replay_lands_n_events_then_second_run_is_idempotent() {
    let (archiver, sink, boxed) = replayer(ColdFormat::Parquet);
    let events = sample();
    let stored = archiver.archive_batch(&events).await;
    assert!(stored.is_ok(), "{stored:?}");
    let Ok(stored) = stored else { return };
    assert!(stored.key.ends_with(".parquet"), "{}", stored.key);

    let replayer = ColdReplayer::new(archiver, boxed);
    assert_eq!(replayer.sink_backend(), "memory");
    let mut ledger = ReplayLedger::in_memory();
    let first = replayer.replay_key(&stored.key, &ReplayFilter::all(), &mut ledger).await;
    assert!(first.is_ok(), "{first:?}");
    let Ok(first) = first else { return };
    assert_eq!(first.objects, 1);
    assert_eq!(first.arrow_objects, 1, "Parquet 对象必须走 arrow 列式读回");
    assert_eq!(first.rows, events.len());
    assert_eq!(first.decoded, events.len());
    assert_eq!(first.replayed, events.len(), "{}", first.summary());
    assert_eq!(first.duplicates, 0);
    assert_eq!(first.filtered, 0);
    assert!(first.failures.is_empty(), "{}", first.summary());
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(3));

    // 第二次：同批必须**一条都不再入库**
    let second = replayer.replay_key(&stored.key, &ReplayFilter::all(), &mut ledger).await;
    assert!(second.is_ok(), "{second:?}");
    let Ok(second) = second else { return };
    assert_eq!(second.replayed, 0, "{}", second.summary());
    assert_eq!(second.duplicates, events.len(), "{}", second.summary());
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(3), "sink 计数不得增长");
    assert_eq!(ledger.len(), events.len());
    assert_eq!(ledger.counts().1, events.len(), "账本本次新增 = 事件数");
    // 回灌事件与归档事件逐字段一致（无损：走 raw_json 列）
    let landed = sink.events().unwrap_or_default();
    assert_eq!(landed.len(), events.len());
    for (original, restored) in events.iter().zip(landed.iter()) {
        assert_eq!(original.id, restored.id);
        assert_eq!(original.time, restored.time);
        assert_eq!(original.message, restored.message);
        assert_eq!(original.raw_hash, restored.raw_hash);
    }
}

/// 时间窗过滤：只回灌窗口内的事件，窗口外计 `filtered`（不静默丢）。
#[tokio::test]
async fn replay_filter_by_time_window_only_lands_events_in_window() {
    let (archiver, sink, boxed) = replayer(ColdFormat::Parquet);
    let events = sample(); // 10:00 / 10:30 / 11:00
    let stored = archiver.archive_batch(&events).await;
    assert!(stored.is_ok(), "{stored:?}");
    let Ok(stored) = stored else { return };
    let replayer = ColdReplayer::new(archiver, boxed);
    let filter = ReplayFilter::window(
        ReplayFilter::parse_time("2026-02-21T10:15:00Z", false).unwrap_or_else(|_| Timestamp::now()),
        ReplayFilter::parse_time("2026-02-21T10:45:00Z", false).unwrap_or_else(|_| Timestamp::now()),
        None,
    );
    let mut ledger = ReplayLedger::in_memory();
    let report = replayer.replay_key(&stored.key, &filter, &mut ledger).await;
    assert!(report.is_ok(), "{report:?}");
    let Ok(report) = report else { return };
    assert_eq!(report.replayed, 1, "{}", report.summary());
    assert_eq!(report.filtered, 2, "{}", report.summary());
    assert_eq!(report.decoded, 3, "解码仍是全量（过滤发生在解码之后）");
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(1));
    let landed = sink.events().unwrap_or_default();
    assert_eq!(landed.first().map(|e| e.severity), Some(Severity::Critical));
    // 日期形式（YYYY-MM-DD）的 `to` 取当天结束 ⇒ 三条全在窗口内
    let whole_day = ReplayFilter::window(
        ReplayFilter::parse_time("2026-02-21", false).unwrap_or_else(|_| Timestamp::now()),
        ReplayFilter::parse_time("2026-02-21", true).unwrap_or_else(|_| Timestamp::now()),
        None,
    );
    assert!(events.iter().all(|event| whole_day.matches(event)));
    assert!(whole_day.describe().contains("全部租户"), "{}", whole_day.describe());
    // 非法时间文本必须显式报错（不静默变成全量）
    assert!(ReplayFilter::parse_time("昨天", false).is_err());
}

/// 租户过滤：只回灌目标租户的事件。
#[tokio::test]
async fn replay_filter_by_tenant_keeps_only_that_tenant() {
    let (archiver, sink, boxed) = replayer(ColdFormat::Parquet);
    let mut alpha = event("2026-02-21T09:00:00Z", Severity::High);
    let mut beta = event("2026-02-21T09:05:00Z", Severity::Low);
    let tenant_a = agf_core::ids::TenantId::new();
    let tenant_b = agf_core::ids::TenantId::new();
    alpha.tenant_id = tenant_a;
    beta.tenant_id = tenant_b;
    let events = vec![alpha, beta];
    let stored = archiver.archive_batch(&events).await;
    assert!(stored.is_ok(), "{stored:?}");
    let Ok(stored) = stored else { return };
    let replayer = ColdReplayer::new(archiver, boxed);
    let mut ledger = ReplayLedger::in_memory();
    let report =
        replayer.replay_key(&stored.key, &ReplayFilter::for_tenant(tenant_a), &mut ledger).await.unwrap_or_default();
    assert_eq!(report.replayed, 1, "{}", report.summary());
    assert_eq!(report.filtered, 1, "{}", report.summary());
    // 回放内容和计数都必须按租户过滤。
    let landed = sink.events().unwrap_or_default();
    assert_eq!(landed.iter().filter(|event| event.tenant_id == tenant_a).count(), 1);
    assert_eq!(landed.iter().filter(|event| event.tenant_id == tenant_b).count(), 0, "非目标租户不得入库");
    // 租户过滤 + 时间过滤叠加：窗口命中但租户不命中 ⇒ 依然过滤掉
    let both = ReplayFilter::window(
        ReplayFilter::parse_time("2026-02-21T00:00:00Z", false).unwrap_or_else(|_| Timestamp::now()),
        ReplayFilter::parse_time("2026-02-21T23:59:59Z", false).unwrap_or_else(|_| Timestamp::now()),
        Some(tenant_b),
    );
    let mut ledger_b = ReplayLedger::in_memory();
    let report_b = replayer.replay_key(&stored.key, &both, &mut ledger_b).await.unwrap_or_default();
    assert_eq!(report_b.replayed, 1, "{}", report_b.summary());
    let landed_b = sink.events().unwrap_or_default();
    assert_eq!(landed_b.iter().filter(|event| event.tenant_id == tenant_b).count(), 1);
    assert_eq!(sink.event_count(tenant_a).await.ok(), Some(1));
    assert_eq!(sink.event_count(tenant_b).await.ok(), Some(1));
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(0), "第三个租户看不到任何计数");
}

/// 账本落盘 ⇒ **跨进程**幂等（重开账本文件后第二次回灌仍为 0）；坏账本文件显式报错。
#[tokio::test]
async fn replay_ledger_persists_across_runs() {
    let dir = tempfile::tempdir();
    assert!(dir.is_ok(), "{dir:?}");
    let Ok(dir) = dir else { return };
    let path = dir.path().join("ledger/state.json");

    let (archiver, sink, boxed) = replayer(ColdFormat::Parquet);
    let events = sample();
    let stored = archiver.archive_batch(&events).await;
    assert!(stored.is_ok(), "{stored:?}");
    let Ok(stored) = stored else { return };
    let replayer = ColdReplayer::new(archiver, boxed);

    // 第一次（进程 A）：落盘账本
    let mut ledger = ReplayLedger::open(&path).unwrap_or_else(|_| ReplayLedger::in_memory());
    assert!(ledger.path().is_some());
    let first = replayer.replay_key(&stored.key, &ReplayFilter::all(), &mut ledger).await.unwrap_or_default();
    assert_eq!(first.replayed, 3, "{}", first.summary());
    assert!(ledger.save().is_ok());
    assert!(path.exists(), "账本必须落盘到 {}", path.display());
    drop(ledger);

    // 第二次（进程 B）：重新读账本 ⇒ 全部判定为重复
    let mut reopened = ReplayLedger::open(&path).unwrap_or_else(|_| ReplayLedger::in_memory());
    assert_eq!(reopened.len(), 3, "落盘账本必须含 3 条 raw_hash");
    assert_eq!(reopened.counts(), (3, 0));
    let second = replayer.replay_key(&stored.key, &ReplayFilter::all(), &mut reopened).await.unwrap_or_default();
    assert_eq!(second.replayed, 0, "{}", second.summary());
    assert_eq!(second.duplicates, 3, "{}", second.summary());
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(3));

    // 坏账本 ⇒ 显式报错（不静默当成空账本重新灌一遍）
    let bad = dir.path().join("bad.json");
    assert!(std::fs::write(&bad, b"{ not json").is_ok());
    assert!(ReplayLedger::open(&bad).is_err());
    // 文件不存在 ⇒ 空账本（不是错误）
    let missing = ReplayLedger::open(dir.path().join("nope.json"));
    assert!(missing.is_ok(), "{missing:?}");
    assert!(missing.map(|ledger| ledger.is_empty()).unwrap_or(false));
}

/// 回落对象（gzip NDJSON）照样能回灌：不走 arrow，但计数与幂等一致；单个坏对象只进 failures。
#[tokio::test]
async fn replay_handles_gzip_fallback_objects_and_records_failures() {
    let (archiver, sink, boxed) = replayer(ColdFormat::NdjsonGzip);
    let events = vec![event("2026-02-21T08:00:00Z", Severity::Medium), event("2026-02-21T08:30:00Z", Severity::Low)];
    let stored = archiver.archive_batch(&events).await;
    assert!(stored.is_ok(), "{stored:?}");
    let Ok(stored) = stored else { return };
    assert!(stored.key.ends_with(".ndjson.gz"), "{}", stored.key);
    let replayer = ColdReplayer::new(archiver, boxed);
    let mut ledger = ReplayLedger::in_memory();
    let report = replayer.replay_key(&stored.key, &ReplayFilter::all(), &mut ledger).await.unwrap_or_default();
    assert_eq!(report.objects, 1);
    assert_eq!(report.arrow_objects, 0, "gzip 回落对象没有列式读回");
    assert_eq!(report.replayed, 2, "{}", report.summary());
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(2));

    // 不存在的对象：记进 failures（键 + 原因），不 panic、不静默
    let missing =
        replayer.replay_keys(&["no/such/object.parquet".to_string()], &ReplayFilter::all(), &mut ledger).await;
    assert!(missing.is_ok(), "{missing:?}");
    let Ok(missing) = missing else { return };
    assert_eq!(missing.objects, 1);
    assert_eq!(missing.replayed, 0);
    assert_eq!(missing.failures.len(), 1);
    assert!(missing.failures.first().is_some_and(|failure| failure.key.contains("no/such/object")));
    assert!(missing.summary().contains("失败对象 1"), "{}", missing.summary());
    assert!(missing.to_json().contains("\"replayed\":0"), "{}", missing.to_json());
}

/// 前缀回灌（跨天目录）+ 报告合并：`replay_prefix` 扫到全部对象，`merge` 累计计数。
#[tokio::test]
async fn replay_prefix_scans_all_objects_and_merges_reports() {
    let (archiver, sink, boxed) = replayer(ColdFormat::Parquet);
    let first = archiver.archive_batch(&sample()).await;
    assert!(first.is_ok(), "{first:?}");
    let Ok(first) = first else { return };
    let extra = vec![event("2026-02-22T07:00:00Z", Severity::Info)];
    let second = archiver.archive_batch(&extra).await;
    assert!(second.is_ok(), "{second:?}");
    let Ok(second) = second else { return };
    assert!(first.key.starts_with("agf-events/"), "{}", first.key);
    assert!(second.key.contains("dt=2026-02-22"), "{}", second.key);

    let replayer = ColdReplayer::new(archiver, boxed);
    let mut ledger = ReplayLedger::in_memory();
    let report = replayer.replay_prefix("", 100, &ReplayFilter::all(), &mut ledger).await;
    assert!(report.is_ok(), "{report:?}");
    let Ok(report) = report else { return };
    assert_eq!(report.objects, 2, "两个归档对象都要扫到");
    assert_eq!(report.arrow_objects, 2);
    assert_eq!(report.decoded, 4);
    assert_eq!(report.replayed, 4, "{}", report.summary());
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(4));
    assert!(report.summary().contains("入库 4"), "{}", report.summary());

    // 报告合并语义（多来源汇总）
    let mut merged = ReplayReport::default();
    merged.merge(&report);
    merged.merge(&report);
    assert_eq!(merged.objects, 4);
    assert_eq!(merged.replayed, 8);
}

/// 落盘账本的原子写与 `raw_hash` 兜底：`raw_hash` 为空的事件用事件 JSON 内容哈希去重（仍幂等）。
#[tokio::test]
async fn replay_uses_content_hash_fallback_and_ledger_save_is_atomic() {
    let dir = tempfile::tempdir();
    assert!(dir.is_ok(), "{dir:?}");
    let Ok(dir) = dir else { return };
    let (archiver, sink, boxed) = replayer(ColdFormat::Parquet);
    let mut blank = event("2026-02-21T06:00:00Z", Severity::Low);
    blank.raw_hash = String::new();
    let stored = archiver.archive_batch(&[blank.clone()]).await;
    assert!(stored.is_ok(), "{stored:?}");
    let Ok(stored) = stored else { return };
    let replayer = ColdReplayer::new(archiver, boxed);
    let path = dir.path().join("state.json");
    let mut ledger = ReplayLedger::open(&path).unwrap_or_else(|_| ReplayLedger::in_memory());
    let first = replayer.replay_key(&stored.key, &ReplayFilter::all(), &mut ledger).await.unwrap_or_default();
    assert_eq!(first.hash_fallbacks, 1, "空 raw_hash 必须走内容哈希兜底并计数");
    assert_eq!(first.replayed, 1);
    assert!(ledger.save().is_ok());
    assert!(!path.with_extension("tmp").exists(), "临时文件必须已 rename，不留残骸");
    // 兜底哈希仍然幂等
    let second = replayer.replay_key(&stored.key, &ReplayFilter::all(), &mut ledger).await.unwrap_or_default();
    assert_eq!(second.replayed, 0, "{}", second.summary());
    assert_eq!(second.duplicates, 1);
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(1));
    // dedup_key 语义：raw_hash 非空直接用它；为空时用内容哈希（确定性）
    let (key_a, fallback_a) = dedup_key(&blank);
    let (key_b, fallback_b) = dedup_key(&blank);
    assert!(fallback_a && fallback_b);
    assert_eq!(key_a, key_b);
    let filled = event("2026-02-21T06:00:00Z", Severity::Low);
    assert_eq!(dedup_key(&filled).0, filled.raw_hash);
    assert!(!dedup_key(&filled).1);
}
