//! 流水线单元测试：去重、限流、脱敏、投递与 SQL sink 行为。

use super::*;
use crate::bus::InMemoryEventBus;
use agf_core::enums::{HealthState, Severity};
use agf_core::ids::TenantId;
use agf_core::source::{CollectionMode, SourceConnection};

const SYSLOG: &str =
    "<34>Feb 21 10:23:45 web-prod-01 sshd[2311]: Failed password for root from 203.0.113.77 port 51234 ssh2";

fn source(max_eps: u32, max_message_bytes: usize) -> LogSource {
    let now = Timestamp::now();
    LogSource {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        name: "syslog-edge".to_string(),
        protocol: IngestProtocol::Syslog,
        vendor: "深信服".to_string(),
        product: "AF".to_string(),
        enabled: true,
        parser_id: None,
        connection: SourceConnection::default(),
        mode: CollectionMode::Push,
        poll_interval_secs: None,
        require_mtls: false,
        allowed_cidrs: vec![],
        max_message_bytes,
        max_eps,
        tags: vec!["edge".to_string()],
        health: HealthState::Healthy,
        last_event_at: None,
        total_events: 0,
        last_error: None,
        created_at: now,
        updated_at: now,
    }
}

fn pipeline() -> (IngestPipeline, Arc<InMemorySink>, Arc<InMemoryEventBus>) {
    let sink = Arc::new(InMemorySink::new());
    let bus = Arc::new(InMemoryEventBus::new(128));
    let pipeline = IngestPipeline::new(
        ParserRegistry::with_builtins(),
        Arc::clone(&sink) as Arc<dyn Sink>,
        Arc::clone(&bus) as Arc<dyn EventBus>,
        IngestConfig::default(),
    );
    (pipeline, sink, bus)
}

#[tokio::test]
async fn ingest_raw_persists_raw_event_and_publishes() {
    let (pipeline, sink, bus) = pipeline();
    let src = source(10_000, 65_536);
    let outcome = pipeline.ingest_raw(&src, IngestProtocol::Syslog, SYSLOG.as_bytes(), "10.0.0.1:5514").await;
    assert!(outcome.is_ok(), "{outcome:?}");
    let Ok(outcome) = outcome else { return };
    assert!(outcome.matched);
    assert!(!outcome.deduped);
    assert!(outcome.parser_key.is_some(), "应命中通用 syslog 模板");
    assert!(outcome.event_id.is_some());
    assert_eq!(outcome.origin, "10.0.0.1:5514");

    let raws = sink.raws().unwrap_or_default();
    assert_eq!(raws.len(), 1);
    assert_eq!(raws.first().map(|r| r.parsed), Some(true));
    assert_eq!(raws.first().map(|r| r.bytes), Some(SYSLOG.len()));
    assert!(raws.first().and_then(|r| r.event_id).is_some());
    let decoded = raws.first().map(decode_payload);
    assert_eq!(decoded.and_then(Result::ok).as_deref(), Some(SYSLOG));

    let events = sink.events().unwrap_or_default();
    assert_eq!(events.len(), 1);
    assert!(events.first().map(|e| e.message.contains("Failed password")).unwrap_or(false));
    assert_eq!(events.first().map(|e| e.severity), Some(Severity::Critical));
    assert_eq!(events.first().and_then(|e| e.host.name.clone()), Some("web-prod-01".to_string()));
    assert_eq!(bus.pending(), 1);
    assert_eq!(pipeline.stats().persisted, 1);
}

#[tokio::test]
async fn oversized_payload_is_rejected_before_storage() {
    let (pipeline, sink, _bus) = pipeline();
    let src = source(10_000, 32);
    let err = pipeline.ingest_raw(&src, IngestProtocol::Syslog, SYSLOG.as_bytes(), "x").await;
    assert!(matches!(err, Err(DomainError::Validation(_))), "{err:?}");
    assert_eq!(pipeline.stats().oversized, 1);
    assert!(sink.raws().unwrap_or_default().is_empty());
}

#[tokio::test]
async fn eps_guard_rejects_second_message() {
    let (pipeline, _sink, _bus) = pipeline();
    let src = source(1, 65_536);
    let first = pipeline.ingest_raw(&src, IngestProtocol::Syslog, SYSLOG.as_bytes(), "x").await;
    assert!(first.is_ok(), "{first:?}");
    let second = pipeline.ingest_raw(&src, IngestProtocol::Syslog, SYSLOG.as_bytes(), "x").await;
    assert!(matches!(second, Err(DomainError::RateLimited(_))), "{second:?}");
    assert_eq!(pipeline.stats().rate_limited, 1);
}

#[tokio::test]
async fn zero_eps_means_unlimited() {
    let (pipeline, _sink, _bus) = pipeline();
    let src = source(0, 65_536);
    for _ in 0..5 {
        assert!(pipeline.ingest_raw(&src, IngestProtocol::Syslog, SYSLOG.as_bytes(), "x").await.is_ok());
    }
    assert_eq!(pipeline.stats().rate_limited, 0);
}

#[tokio::test]
async fn duplicate_is_dropped_within_window() {
    let (pipeline, sink, bus) = pipeline();
    let src = source(0, 65_536);
    let first = pipeline.ingest_raw(&src, IngestProtocol::Syslog, SYSLOG.as_bytes(), "x").await;
    let second = pipeline.ingest_raw(&src, IngestProtocol::Syslog, SYSLOG.as_bytes(), "x").await;
    assert!(!first.map(|o| o.deduped).unwrap_or(true), "首条不应被判重");
    let Ok(second) = second else { return };
    assert!(second.deduped, "同源同时间同哈希必须去重");
    assert!(second.event_id.is_none());
    assert_eq!(sink.events().unwrap_or_default().len(), 1, "去重后只应有一个事件");
    assert_eq!(sink.raws().unwrap_or_default().len(), 2, "原始日志仍全部保留");
    assert_eq!(bus.pending(), 1);
    assert_eq!(pipeline.stats().deduped, 1);
}

#[tokio::test]
async fn dedup_can_be_disabled() {
    let sink = Arc::new(InMemorySink::new());
    let pipeline = IngestPipeline::new(
        ParserRegistry::with_builtins(),
        Arc::clone(&sink) as Arc<dyn Sink>,
        Arc::new(NoopEventBus),
        IngestConfig { dedup_window_secs: 0, emit_to_bus: false, ..IngestConfig::default() },
    );
    let src = source(0, 65_536);
    for _ in 0..3 {
        let outcome = pipeline.ingest_raw(&src, IngestProtocol::Syslog, SYSLOG.as_bytes(), "x").await;
        assert!(!outcome.map(|o| o.deduped).unwrap_or(true));
    }
    assert_eq!(sink.events().unwrap_or_default().len(), 3);
}

#[tokio::test]
async fn credentials_are_redacted_but_raw_is_preserved() {
    let (pipeline, sink, _bus) = pipeline();
    let src = source(0, 65_536);
    let payload = r#"{"msg":"调用模型","api_key":"sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz012345"}"#;
    let outcome = pipeline.ingest_raw(&src, IngestProtocol::Webhook, payload.as_bytes(), "webhook").await;
    assert!(outcome.is_ok(), "{outcome:?}");
    let Ok(outcome) = outcome else { return };
    assert!(outcome.redacted, "含凭据的日志必须脱敏");
    let events = sink.events().unwrap_or_default();
    let event = events.first();
    assert_eq!(event.map(|e| e.redacted), Some(true));
    let rendered = event.map(|e| e.raw.to_string()).unwrap_or_default();
    assert!(!rendered.contains("sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz012345"), "事件副本不得含明文凭据");
    assert!(rendered.contains("[[AGF_"), "应替换为占位符: {rendered}");
    // 原始日志保真：base64 解码后仍含明文，供有权限的运维回放
    let raws = sink.raws().unwrap_or_default();
    let raw_text = raws.first().map(decode_payload).and_then(Result::ok).unwrap_or_default();
    assert!(raw_text.contains("sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz012345"));
    assert_eq!(pipeline.stats().redacted, 1);
}

#[tokio::test]
async fn redaction_mode_none_leaves_event_untouched() {
    let sink = Arc::new(InMemorySink::new());
    let pipeline = IngestPipeline::new(
        ParserRegistry::with_builtins(),
        Arc::clone(&sink) as Arc<dyn Sink>,
        Arc::new(NoopEventBus),
        IngestConfig { redaction: RedactionMode::None, emit_to_bus: false, ..IngestConfig::default() },
    );
    let src = source(0, 65_536);
    let payload = r#"{"api_key":"sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz012345"}"#;
    let outcome = pipeline.ingest_raw(&src, IngestProtocol::Webhook, payload.as_bytes(), "w").await;
    assert!(!outcome.map(|o| o.redacted).unwrap_or(true), "None 模式不应脱敏");
    let events = sink.events().unwrap_or_default();
    assert!(events.first().map(|e| e.raw.to_string().contains("sk-proj")).unwrap_or(false));
}

#[tokio::test]
async fn batch_mode_persists_all_and_respects_limit() {
    let sink = Arc::new(InMemorySink::new());
    let bus = Arc::new(InMemoryEventBus::new(64));
    let pipeline = IngestPipeline::new(
        ParserRegistry::with_builtins(),
        Arc::clone(&sink) as Arc<dyn Sink>,
        Arc::clone(&bus) as Arc<dyn EventBus>,
        IngestConfig { batch_limit: 3, dedup_window_secs: 0, ..IngestConfig::default() },
    );
    let src = source(0, 65_536);
    let items: Vec<(Vec<u8>, String)> = (0..5)
            .map(|i| {
                (
                    format!("<34>Feb 21 10:23:4{i} web-prod-0{i} sshd[2311]: Failed password for root from 203.0.113.7{i} port 51234 ssh2").into_bytes(),
                    format!("src-{i}"),
                )
            })
            .collect();
    let outcomes = pipeline.ingest_batch(&src, IngestProtocol::Syslog, &items).await;
    assert!(outcomes.is_ok(), "{outcomes:?}");
    let Ok(outcomes) = outcomes else { return };
    assert_eq!(outcomes.len(), 5);
    assert_eq!(outcomes.iter().filter(|o| o.error.is_none()).count(), 3);
    assert_eq!(outcomes.iter().filter(|o| o.error.is_some()).count(), 2);
    // `persisted` 与 `error` 正交：超限被拒的 2 条未落库，其余 3 条已落库
    assert_eq!(outcomes.iter().filter(|o| o.persisted).count(), 3, "落库条数按 persisted 统计");
    assert_eq!(sink.events().unwrap_or_default().len(), 3);
    assert_eq!(bus.pending(), 3);
    assert_eq!(pipeline.stats().persisted, 3);
}

#[tokio::test]
async fn unmatched_payload_is_kept_as_raw_and_left_unparsed() {
    let (pipeline, sink, _bus) = pipeline();
    let src = source(0, 65_536);
    let payload = "完全无法识别的自由文本，没有分隔符也没有结构";
    let outcome = pipeline.ingest_raw(&src, IngestProtocol::Webhook, payload.as_bytes(), "w").await;
    let Ok(outcome) = outcome else { return };
    assert!(!outcome.matched);
    assert!(outcome.event_id.is_some(), "未命中模板仍要保存事件（保真优先）");
    assert!(outcome.persisted, "未命中模板的载荷仍然落库（persisted=true）");
    assert!(
        outcome.error.is_some(),
        "未命中必须在结果里回填原因（修复前恒为 None，导致'全量未命中'看起来和'全部命中'一样成功）"
    );
    assert_eq!(pipeline.stats().unmatched, 1);
    let raws = sink.raws().unwrap_or_default();
    assert_eq!(raws.first().map(|r| r.parsed), Some(false), "未命中模板的原始日志必须留给回放");
    let unparsed = sink.unparsed_raw(TenantId::default_tenant(), 10).await.unwrap_or_default();
    assert_eq!(unparsed.len(), 1);
    assert!(unparsed.first().and_then(|r| r.event_id).is_some(), "回放需要旧事件 id 做差分");
}

/// 新协议（模板未声明的协议）进来的载荷：命中后 `/stats` 必须能把**放宽命中**单独读出来。
#[tokio::test]
async fn relaxed_protocol_hit_is_counted_separately_in_stats() {
    let (pipeline, sink, _bus) = pipeline();
    // 日志源带厂商提示时会**同时**作用于严格趟与放宽趟（放宽只放宽协议白名单），
    // 因此这里用阿里云的源，避免"深信服"提示把阿里云模板挡掉。
    let mut src = source(0, 65_536);
    src.vendor = "阿里云".to_string();
    src.product = "Web应用防火墙".to_string();
    let raw = crate::template::repo_fixture_dir().join("aliyun-waf-1.log");
    let text = std::fs::read_to_string(&raw).unwrap_or_default();
    let line = crate::template::first_data_line(&text);
    assert!(!line.is_empty(), "样本 aliyun-waf-1.log 必须存在");

    // 内置模板只声明了 webhook/http-pull/beats → 经 MQTT 投递只能靠放宽趟
    let outcome = pipeline.ingest_raw(&src, IngestProtocol::Mqtt, line.as_bytes(), "mqtt").await;
    let Ok(outcome) = outcome else { return };
    assert!(outcome.matched, "经 MQTT 投递的阿里云 WAF JSON 必须命中: {:?}", outcome.error);
    assert_eq!(outcome.parser_key.as_deref(), Some("aliyun-waf-webhook"));
    // **逐条**趟次（修复前只有聚合统计，拿不到"这一条凭什么命中"）
    assert_eq!(outcome.matched_by.as_deref(), Some("protocol-relaxed"));
    let stats = pipeline.stats();
    assert_eq!(stats.matched, 1, "命中总数必须可见");
    assert_eq!(stats.matched_relaxed, 1, "放宽命中必须单独计数（可解释命中率变化）");
    assert_eq!(stats.matched_by.get("protocol-relaxed"), Some(&1), "全量分项里也要能看到该趟");
    assert_eq!(stats.unmatched, 0);
    assert_eq!(sink.raws().unwrap_or_default().len(), 1);
}

/// 逐条 `matched_by` 在**严格趟**下的取值，以及 `/stats` 的 `pipeline.matched_by` 分项。
#[tokio::test]
async fn strict_hit_reports_matched_by_and_mode_breakdown() {
    let (pipeline, _sink, _bus) = pipeline();
    let metric_before = crate::metrics::matched_by_snapshot().get("protocol").copied().unwrap_or(0);
    // 阿里云源 + 模板声明过的 webhook 协议 → 严格趟
    let mut src = source(0, 65_536);
    src.vendor = "阿里云".to_string();
    src.product = "Web应用防火墙".to_string();
    let raw = crate::template::repo_fixture_dir().join("aliyun-waf-1.log");
    let text = std::fs::read_to_string(&raw).unwrap_or_default();
    let line = crate::template::first_data_line(&text);
    let outcome = pipeline.ingest_raw(&src, IngestProtocol::Webhook, line.as_bytes(), "webhook").await;
    let Ok(outcome) = outcome else { return };
    assert!(outcome.matched, "{:?}", outcome.error);
    assert_eq!(outcome.matched_by.as_deref(), Some("protocol"));

    // 通用 syslog：日志源不带厂商提示 ⇒ 内置 `syslog-generic`（不限厂商）在严格趟命中。
    // 带厂商提示时该模板会被 `vendor_accepts` 挡到第 4 步（样本打分），这正是第 4 步
    // 修好后承担的场景——本用例要的是"严格趟"这一格，因此显式清空厂商提示。
    let mut syslog_src = source(0, 65_536);
    syslog_src.vendor = String::new();
    let second = pipeline.ingest_raw(&syslog_src, IngestProtocol::Syslog, SYSLOG.as_bytes(), "syslog").await;
    let Ok(second) = second else { return };
    assert!(second.matched, "{:?}", second.error);
    assert_eq!(second.matched_by.as_deref(), Some("protocol"));

    let stats = pipeline.stats();
    assert_eq!(stats.matched, 2);
    assert_eq!(stats.matched_by.get("protocol"), Some(&2), "严格趟必须能在全量分项里读到");
    assert_eq!(stats.matched_relaxed, 0);
    // `/metrics` 的**进程级**分项（`agf_ingest_matched_by_total`）必须同步累加：
    // 计数与实例级统计是两条独立通路，漏掉任何一条都会让指标"永远是 0"（实测踩过）。
    let metric_after = crate::metrics::matched_by_snapshot().get("protocol").copied().unwrap_or(0);
    assert!(metric_after >= metric_before + 2, "进程级分项未累加: {metric_before} -> {metric_after}");
}

/// 未命中的载荷：`matched_by` 必须为 `None`（不写空串、不臆造趟次）。
#[tokio::test]
async fn unmatched_reports_no_matched_by() {
    let (pipeline, _sink, _bus) = pipeline();
    let src = source(0, 65_536);
    let payload = "完全无法识别的自由文本，没有分隔符也没有结构";
    let outcome = pipeline.ingest_raw(&src, IngestProtocol::Webhook, payload.as_bytes(), "w").await;
    let Ok(outcome) = outcome else { return };
    assert!(!outcome.matched);
    assert_eq!(outcome.matched_by, None);
    assert!(pipeline.stats().matched_by.is_empty(), "未命中不得写任何趟次分项");
}

#[tokio::test]
async fn bus_failure_does_not_lose_events() {
    #[derive(Debug)]
    struct BrokenBus;
    #[async_trait]
    impl EventBus for BrokenBus {
        fn name(&self) -> &'static str {
            "broken"
        }
        async fn publish(&self, _event: &Event) -> DomainResult<()> {
            Err(DomainError::DependencyUnavailable { dependency: "bus".to_string(), cause: "down".to_string() })
        }
        async fn publish_batch(&self, _events: &[Event]) -> DomainResult<usize> {
            Err(DomainError::DependencyUnavailable { dependency: "bus".to_string(), cause: "down".to_string() })
        }
        async fn health(&self) -> DomainResult<()> {
            Ok(())
        }
    }
    let sink = Arc::new(InMemorySink::new());
    let pipeline = IngestPipeline::new(
        ParserRegistry::with_builtins(),
        Arc::clone(&sink) as Arc<dyn Sink>,
        Arc::new(BrokenBus) as Arc<dyn EventBus>,
        IngestConfig::default(),
    );
    let src = source(0, 65_536);
    let outcome = pipeline.ingest_raw(&src, IngestProtocol::Syslog, SYSLOG.as_bytes(), "x").await;
    assert!(outcome.is_ok(), "总线故障不应影响接入");
    assert_eq!(sink.events().unwrap_or_default().len(), 1);
    assert_eq!(pipeline.stats().bus_failed, 1);
}

#[tokio::test]
async fn in_memory_sink_counts_and_lookup() {
    let sink = InMemorySink::new();
    let tenant = TenantId::default_tenant();
    assert_eq!(Sink::backend(&sink), "memory");
    assert_eq!(sink.event_count(tenant).await.ok(), Some(0));
    assert_eq!(sink.raw_count(tenant).await.ok(), Some(0));
    let mut event = Event::new(TenantId::default_tenant(), Id::new(), IngestProtocol::Syslog);
    event.message = "m".to_string();
    assert!(sink.put_event(&event).await.is_ok());
    assert!(sink.put_event(&event).await.is_err(), "同 id 重复写入应冲突");
    assert_eq!(sink.get_event(tenant, event.id).await.ok().flatten().map(|e| e.message), Some("m".to_string()));
    assert_eq!(sink.event_count(tenant).await.ok(), Some(1));
    let missing = sink.mark_raw(tenant, Id::new(), true, None, None).await;
    assert!(matches!(missing, Err(DomainError::NotFound { .. })));
}

#[test]
fn token_bucket_refills_over_time() {
    let mut bucket = TokenBucket::new(1);
    assert!(bucket.try_acquire());
    assert!(!bucket.try_acquire());
    bucket.tokens = 0.0;
    let now = Instant::now();
    bucket.last = now.checked_sub(std::time::Duration::from_millis(1_500)).unwrap_or(now);
    assert!(bucket.try_acquire(), "1.5 秒后应补满 1 个令牌");
}

#[test]
fn decode_payload_rejects_bad_base64() {
    let raw = RawLog {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        source_id: Id::new(),
        received_at: Timestamp::now(),
        protocol: IngestProtocol::File,
        payload_b64: "!!!not-base64!!!".to_string(),
        payload_hash: String::new(),
        bytes: 0,
        origin: String::new(),
        parsed: false,
        parse_error: None,
        event_id: None,
    };
    assert!(decode_payload(&raw).is_err());
}

#[test]
fn default_config_is_conservative() {
    let cfg = IngestConfig::default();
    assert_eq!(cfg.redaction, RedactionMode::CredentialsOnly);
    assert_eq!(cfg.dedup_window_secs, 300);
    assert!(cfg.emit_to_bus);
    assert_eq!(cfg.batch_limit, 512);
}

#[path = "retry_tests.rs"]
mod retry;
