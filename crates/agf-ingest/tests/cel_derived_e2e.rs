//! CEL 派生字段（模板 `derived` 段）的**端到端**锁定：表达式求值 → 编译缓存 →
//! 非法表达式降级 → 打 webhook → **断言落库 Event 里的派生字段值**。
//!
//! ## 为什么单列这个文件
//!
//! `cel.rs` 的实现早已接线（`engine::apply_mapping` 的末尾调用 `cel::apply_derived`），
//! 但此前只有 engine 内部的 3 个用例，**没有任何一条用例从"入向请求"走到"存储事件"**——
//! 也就是说"派生字段真的进了数据库的那一行"从未被证明过。本文件补齐这一段：
//!
//! | 用例 | 钉住的事实 |
//! |---|---|
//! | [`expressions_evaluate_and_compile_only_once`] | ① 表达式真求值；② 同一表达式**只编译一次**（编译缓存）；非法表达式同样只编译一次 |
//! | [`illegal_derived_expressions_are_recorded_and_the_event_is_still_persisted`] | ③ 非法表达式落 `derived_errors`，**其余派生字段照常生效**，事件与原始日志照常落库（派生失败不丢数据） |
//! | [`derived_fields_reach_the_stored_event_through_the_webhook_path`] | ④ 带 `derived` 的模板 → `POST /ingest/webhook` → **落库 Event 的派生字段值逐项断言** |
//!
//! 不依赖 docker：`POST /ingest/webhook` 用 [`WebhookReceiver::ingest`] 直接打（与 axum handler
//! 走的是同一个函数），落库走 `InMemorySink`。
#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used, clippy::print_stdout)]

use std::collections::BTreeMap;
use std::sync::Arc;

use agf_core::enums::{HealthState, IngestProtocol};
use agf_core::event::EventCategory;
use agf_core::ids::{Id, TenantId};
use agf_core::parser::{FieldMapping, ParserDefinition, ParserEngine};
use agf_core::source::{CollectionMode, LogSource, SourceConnection};
use agf_core::time::Timestamp;
use agf_ingest::bus::NoopEventBus;
use agf_ingest::pipeline::{InMemorySink, IngestConfig, IngestPipeline, Sink};
use agf_ingest::receiver::WebhookReceiver;
use agf_ingest::registry::ParserRegistry;
use serde_json::Value;

/// 一条 JSON 日志：`severity_num` **故意不进映射表**，因此它落在 `extra`，
/// 供 CEL 用 `extra['severity_num']` 读取（与文档里的变量口径一致）。
const PAYLOAD: &str =
    r#"{"ts":"2026-02-21T10:23:45Z","user":"root","src":"203.0.113.77","severity_num":9,"action":"block"}"#;

fn log_source() -> LogSource {
    let now = Timestamp::now();
    LogSource {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        name: "cel-derived-e2e".to_string(),
        protocol: IngestProtocol::Webhook,
        vendor: "generic".to_string(),
        product: "json".to_string(),
        enabled: true,
        parser_id: None,
        connection: SourceConnection::default(),
        mode: CollectionMode::Push,
        poll_interval_secs: None,
        require_mtls: false,
        allowed_cidrs: vec![],
        max_message_bytes: 1_048_576,
        max_eps: 0,
        tags: vec![],
        health: HealthState::Healthy,
        last_event_at: None,
        total_events: 0,
        last_error: None,
        created_at: now,
        updated_at: now,
    }
}

/// 带 `derived` 段的模板：四种派生形式（CEL 条件式 / CEL 算术 / `const:` / `copy:`）全覆盖。
fn derived_template() -> ParserDefinition {
    let mut def = ParserDefinition {
        key: "cel-derived-e2e".to_string(),
        name: "CEL 派生字段端到端".to_string(),
        vendor: "generic".to_string(),
        product: "json".to_string(),
        protocols: vec![IngestProtocol::Webhook],
        engine: ParserEngine::JsonPath,
        pattern: ["ts=$.ts", "user=$.user", "src=$.src", "severity_num=$.severity_num", "action=$.action"].join("\n"),
        fallback_patterns: vec![],
        mapping: FieldMapping {
            map: [("ts", "event.time"), ("user", "user.name"), ("src", "source.ip"), ("action", "event.action")]
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            time_field: None,
            time_format: None,
            severity_field: None,
            severity_map: BTreeMap::new(),
            category_map: BTreeMap::new(),
            action_field: None,
            defaults: BTreeMap::new(),
        },
        derived: BTreeMap::new(),
        required_fields: vec!["severity_num".to_string()],
        version: 1,
        builtin: false,
        ai_inferred: false,
        description: "CEL 派生字段端到端用例（非内置模板，仅供测试注册）".to_string(),
        sample_fixture: String::new(),
    };
    // CEL 条件式 → 平台一级字段（`event.category` 被 normalize 识别，真的落到 Event 上）
    def.derived
        .insert("event.category".to_string(), "extra['severity_num'] >= 7 ? 'intrusion' : 'network'".to_string());
    // CEL 算术 → 未识别路径 ⇒ `Event::extra['risk.score']`
    def.derived.insert("risk.score".to_string(), "extra['severity_num'] * 10".to_string());
    // `const:` → 平台一级字段
    def.derived.insert("host.name".to_string(), "const:derived-host-01".to_string());
    // `copy:` → 复制已映射的 ECS 字段
    def.derived.insert("actor".to_string(), "copy:source.ip".to_string());
    def
}

fn pipeline_with(def: ParserDefinition) -> (Arc<IngestPipeline>, Arc<InMemorySink>) {
    let sink = Arc::new(InMemorySink::new());
    let mut registry = ParserRegistry::new();
    registry.register(def, 1).expect("注册测试模板");
    let pipeline = IngestPipeline::new(
        registry,
        Arc::clone(&sink) as Arc<dyn Sink>,
        Arc::new(NoopEventBus),
        IngestConfig { emit_to_bus: false, dedup_window_secs: 0, ..IngestConfig::default() },
    );
    (Arc::new(pipeline), sink)
}

/// ① 表达式真求值 + ② 编译缓存：同一表达式求值 50 次只编译 1 次；非法表达式亦然。
#[test]
fn expressions_evaluate_and_compile_only_once() {
    let fields: BTreeMap<String, Value> = BTreeMap::new();
    let mut extra: BTreeMap<String, Value> = BTreeMap::new();
    // 表达式**本用例独有**：`compile_attempts` 是进程级计数，用独有字符串避免与其他用例互相干扰
    extra.insert("cache_probe".to_string(), Value::from(1_i64));
    let expr = "extra['cache_probe'] + 41";

    assert_eq!(agf_ingest::cel::compile_attempts(expr), 0, "该表达式必须尚未被编译过");
    for round in 0..50 {
        let value = agf_ingest::cel::evaluate("cache.result", expr, &fields, &extra);
        assert_eq!(value.as_ref().ok().and_then(Value::as_i64), Some(42), "第 {round} 轮求值结果不符: {value:?}");
    }
    assert_eq!(agf_ingest::cel::compile_attempts(expr), 1, "50 次求值只允许编译 1 次（编译缓存生效）");
    assert!(agf_ingest::cel::is_cached(expr));

    // 非法表达式同样只编译一次：`cel-parser` 的错误恢复路径（含 panic 兜底）不能被反复触发
    let bad = "? this is not a cel expression ?";
    assert_eq!(agf_ingest::cel::compile_attempts(bad), 0);
    let first = agf_ingest::cel::evaluate("bad.target", bad, &fields, &extra);
    let second = agf_ingest::cel::evaluate("bad.target", bad, &fields, &extra);
    assert!(first.is_err(), "非法表达式必须报错降级（不 panic、不返回 Ok）");
    assert_eq!(first, second, "非法表达式的失败原因必须稳定（命中同一个缓存条目）");
    assert_eq!(agf_ingest::cel::compile_attempts(bad), 1, "非法表达式也只编译一次");
    assert!(agf_ingest::cel::is_cached(bad));
    println!("非法表达式降级原因：{}", first.err().unwrap_or_default());

    // `copy:` / `const:` 是短路分支，不经过 CEL 编译（不得污染缓存/计数）
    let const_expr = "const:cache-const-probe";
    assert_eq!(agf_ingest::cel::evaluate("c", const_expr, &fields, &extra), Ok(Value::from("cache-const-probe")));
    assert_eq!(agf_ingest::cel::compile_attempts(const_expr), 0);
    assert!(!agf_ingest::cel::is_cached(const_expr));
}

/// ③ 非法表达式落 `derived_errors`，其余派生字段照常生效，且**事件仍然落库**。
#[tokio::test]
async fn illegal_derived_expressions_are_recorded_and_the_event_is_still_persisted() {
    let mut def = derived_template();
    // 编译期失败（未声明引用）：无论 cel-interpreter 判在编译还是求值，都必须被记成派生错误
    def.derived.insert("broken.compile".to_string(), "this_is_not_defined == 1".to_string());
    // 求值期失败（除零）：CEL 规范定义为错误，不是 0
    def.derived.insert("broken.eval".to_string(), "1 / 0".to_string());

    // ① 解析层：两条非法表达式都被记下，合法派生字段不受影响
    let outcome = agf_ingest::engine::parse_with(&def, PAYLOAD);
    assert!(outcome.matched, "模板必须命中: {:?}", outcome.error);
    assert_eq!(outcome.derived_errors.len(), 2, "两条非法派生都必须被记录: {:?}", outcome.derived_errors);
    for target in ["broken.compile", "broken.eval"] {
        assert!(
            outcome.derived_errors.iter().any(|e| e.contains(target)),
            "derived_errors 必须点名 {target}: {:?}",
            outcome.derived_errors
        );
        assert!(!outcome.fields.contains_key(target), "失败的派生字段不得写入目标值: {target}");
    }
    assert_eq!(outcome.get_str("event.category"), Some("intrusion"), "单条失败不得影响其余派生字段");
    assert_eq!(outcome.get_str("host.name"), Some("derived-host-01"));
    println!("derived_errors = {:?}", outcome.derived_errors);

    // ② 流水线层：派生失败**不丢数据**——事件与原始日志照常落库
    let (pipeline, sink) = pipeline_with(def);
    let receiver = WebhookReceiver::new(Arc::clone(&pipeline), log_source(), "/ingest/webhook");
    let outcomes = receiver.ingest(PAYLOAD.as_bytes(), "127.0.0.1").await.expect("webhook 接入");
    assert_eq!(outcomes.len(), 1);
    assert!(outcomes[0].matched, "{:?}", outcomes[0].error);
    assert!(outcomes[0].persisted, "派生失败不得阻止落库");
    assert!(outcomes[0].error.is_none(), "命中模板就不该有接入错误: {:?}", outcomes[0].error);
    assert_eq!(sink.events().expect("事件快照").len(), 1, "派生失败绝不丢事件");
    assert_eq!(sink.raws().expect("原始日志快照").len(), 1, "原始日志保真落库");
    let stored = sink.events().expect("事件快照");
    let event = stored.first().expect("恰好一条事件");
    assert_eq!(event.category, EventCategory::Intrusion, "合法派生字段照常落库");
    assert_eq!(event.extra.get("risk.score").and_then(Value::as_i64), Some(90));
}

/// ④ 端到端：带 `derived` 的模板 → 打 webhook → **落库 Event 的派生字段值**逐项断言。
#[tokio::test]
async fn derived_fields_reach_the_stored_event_through_the_webhook_path() {
    let (pipeline, sink) = pipeline_with(derived_template());
    let receiver = WebhookReceiver::new(Arc::clone(&pipeline), log_source(), "/ingest/webhook");

    let outcomes = receiver.ingest(PAYLOAD.as_bytes(), "10.0.0.9").await.expect("webhook 接入");
    assert_eq!(outcomes.len(), 1, "单条 JSON 载荷拆成一条记录");
    let outcome = outcomes.first().expect("一条接入结果");
    assert!(outcome.matched, "必须命中带 derived 的模板: {:?}", outcome.error);
    assert_eq!(outcome.parser_key.as_deref(), Some("cel-derived-e2e"));
    assert!(outcome.persisted);

    let events = sink.events().expect("事件快照");
    assert_eq!(events.len(), 1, "事件必须落库");
    let event = events.first().expect("一条事件");

    // CEL 条件式 → `event.category`（平台一级字段）
    assert_eq!(event.category, EventCategory::Intrusion, "`severity_num >= 7 ? 'intrusion' : 'network'` 未生效");
    // `const:` → `host.name`（平台一级字段）
    assert_eq!(event.host.name.as_deref(), Some("derived-host-01"), "`const:` 派生未生效");
    // CEL 算术 → 未识别路径落 `Event::extra`
    assert_eq!(
        event.extra.get("risk.score").and_then(Value::as_i64),
        Some(90),
        "CEL 算术派生未落库: {:?}",
        event.extra
    );
    // `copy:` → 复制已映射的 ECS 字段
    assert_eq!(
        event.extra.get("actor").and_then(Value::as_str),
        Some("203.0.113.77"),
        "`copy:` 派生未落库: {:?}",
        event.extra
    );
    // 非派生字段照常（证明派生是"追加"而不是"替换"）
    assert_eq!(event.user.name.as_deref(), Some("root"));
    assert_eq!(event.network.source_ip.as_deref(), Some("203.0.113.77"));
    // 原始日志可回放（保真层）
    let raws = sink.raws().expect("原始日志快照");
    assert_eq!(raws.first().and_then(|r| r.event_id), Some(event.id));
    println!(
        "落库事件：category={} host={:?} extra.risk.score={:?} extra.actor={:?}",
        event.category.as_str(),
        event.host.name,
        event.extra.get("risk.score"),
        event.extra.get("actor")
    );
}
