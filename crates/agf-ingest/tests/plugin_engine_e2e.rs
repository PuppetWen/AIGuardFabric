//! `engine: plugin` 的**端到端**锁定：模板声明 → 插件调用 → 落库 Event 字段。
//!
//! ## 为什么单列这个文件
//!
//! `engine/plugin/tests.rs` 只证到"解析层"（`parse_with` 的字段表）。本文件补上
//! "**入向请求 → 流水线 → 落库事件**"这一段，并把三条降级路径钉住：
//!
//! | 用例 | 钉住的事实 |
//! |---|---|
//! | [`plugin_fields_reach_the_stored_event_through_the_webhook_path`] | ① 模板 `engine: plugin` 命中；② **Event 的字段真的来自插件输出**；③ `parser_key` = 模板 key，插件名可在诊断里核对 |
//! | [`illegal_json_is_counted_as_parse_failed_and_the_raw_log_is_still_persisted`] | ④ 非法 JSON ⇒ `parse_failed` 计数 + 事件仍落库（raw 保真）+ **不 panic** |
//! | [`missing_runtime_degrades_instead_of_panicking`] | ⑤ 未配插件目录 ⇒ 如实报错/未命中，raw 照常落库（与原"未接线"行为一致：都是不命中 + 保真） |
//! | [`yaml_template_with_plugin_engine_is_accepted_by_the_registry`] | ⑥ YAML 里 `engine: plugin` 的模板能被注册表装载（声明解析） |
//! | [`real_plugin_dll_feeds_the_pipeline`]（`#[ignore]`） | ⑦ **真机**：真 `.dll` + 真 ABI ⇒ 真字段落库（由 `--ignored` 门控，CI 不依赖 cdylib 构建） |
//!
//! 不依赖 docker / PostgreSQL：`POST /ingest/webhook` 走 [`WebhookReceiver::ingest`]
//! （与 axum handler 同一个函数），落库走 `InMemorySink`。
#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used, clippy::print_stdout)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use agf_core::enums::{HealthState, IngestProtocol};
use agf_core::event::EventAction;
use agf_core::ids::{Id, TenantId};
use agf_core::parser::{FieldMapping, ParserDefinition, ParserEngine};
use agf_core::source::{CollectionMode, LogSource, SourceConnection};
use agf_core::time::Timestamp;
use agf_ingest::bus::NoopEventBus;
use agf_ingest::engine::plugin::{
    DEFAULT_PLUGIN_TIMEOUT_MS, DynamicPluginInvoker, PluginCallError, PluginInvoker, PluginLoadFailureInfo,
    PluginLoadedInfo, PluginRuntime, clear_plugin_runtime, install_plugin_runtime, plugin_runtime_status,
    resolve_plugin_dir,
};
use agf_ingest::metrics::MetricsRegistry;
use agf_ingest::pipeline::{InMemorySink, IngestConfig, IngestPipeline, Sink};
use agf_ingest::receiver::WebhookReceiver;
use agf_ingest::registry::{ParserRegistry, parse_template_file};
use agf_plugin::plugin_file_suffix;
use serde_json::Value;

/// 串行闸门：插件运行时是**进程级全局状态**（生产语义如此），而同一测试二进制里的用例
/// 是并行跑的 ⇒ 碰它的用例必须互斥，否则计数会被别的用例串进来（实测过，别删）。
static GLOBAL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn lock_globals() -> std::sync::MutexGuard<'static, ()> {
    GLOBAL_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// 一条 `k=v` 访问日志（与示例插件的输入形态一致）。
const LOG_LINE: &str = r#"ts=2026-02-21T10:00:00Z src=10.1.2.3 dst=10.9.9.9 dpt=443 action=block rule=WAF-1001 msg="SQL injection attempt""#;

/// 假插件：返回固定的 AGF-ECS JSON（字段值与 [`LOG_LINE`] 的语义对应）。
/// **所有用例共享一个假插件实现**，只有"真机"用例换成真 dll。
#[derive(Debug)]
struct FakeNormalizer {
    reply: String,
    loaded: [PluginLoadedInfo; 1],
}

impl FakeNormalizer {
    fn new(reply: &str) -> Self {
        Self {
            reply: reply.to_string(),
            loaded: [PluginLoadedInfo {
                name: "fake-normalizer".to_string(),
                version: "1.0.0".to_string(),
                kind: "normalizer".to_string(),
                path: "plugins/fake_normalizer.dll".to_string(),
            }],
        }
    }
}

impl PluginInvoker for FakeNormalizer {
    fn invoke(&self, plugin: &str, payload: &str) -> Result<String, PluginCallError> {
        println!("[fake-plugin] plugin={plugin} payload={payload}");
        if payload.contains("非法") {
            return Err(PluginCallError::Call {
                plugin: plugin.to_string(),
                reason: "输入里没有任何 k=v 字段".to_string(),
            });
        }
        Ok(self.reply.clone())
    }

    fn loaded(&self) -> &[PluginLoadedInfo] {
        &self.loaded
    }

    fn failures(&self) -> &[PluginLoadFailureInfo] {
        &[]
    }
}

/// 插件输出的 AGF-ECS JSON（嵌套对象 ⇒ 宿主扁平化后走既有映射）。
const PLUGIN_ECS_JSON: &str = r#"{"@timestamp":"2026-02-21T10:00:00Z","source":{"ip":"10.1.2.3"},"destination":{"ip":"10.9.9.9","port":443},"event":{"action":"block","rule":"WAF-1001"},"message":"SQL injection attempt","labels":{"tenant":"acme"}}"#;

fn log_source() -> LogSource {
    let now = Timestamp::now();
    LogSource {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        name: "plugin-engine-e2e".to_string(),
        protocol: IngestProtocol::Webhook,
        vendor: "generic".to_string(),
        product: "kv".to_string(),
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

/// `engine: plugin` 模板：`pattern` 就是插件规格；`mapping` 用**源字段名**声明改写。
fn plugin_template(spec: &str) -> ParserDefinition {
    ParserDefinition {
        key: "kv-plugin-access".to_string(),
        name: "插件解析：KV 访问日志".to_string(),
        vendor: "generic".to_string(),
        product: "kv".to_string(),
        protocols: vec![IngestProtocol::Webhook],
        engine: ParserEngine::Plugin,
        pattern: spec.to_string(),
        fallback_patterns: vec![],
        mapping: FieldMapping {
            map: std::iter::once(("agf.plugin", "observer.name"))
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            time_field: Some("@timestamp".to_string()),
            ..FieldMapping::default()
        },
        derived: std::collections::BTreeMap::new(),
        required_fields: vec!["source.ip".to_string()],
        version: 1,
        builtin: false,
        ai_inferred: false,
        description: "端到端用例：插件输出 → 落库事件（非内置模板，仅供测试注册）".to_string(),
        sample_fixture: String::new(),
    }
}

fn pipeline_with(def: ParserDefinition) -> (Arc<IngestPipeline>, Arc<InMemorySink>) {
    let sink = Arc::new(InMemorySink::new());
    let mut registry = ParserRegistry::new();
    registry.register(def, 1).expect("注册插件模板");
    let pipeline = IngestPipeline::new(
        registry,
        Arc::clone(&sink) as Arc<dyn Sink>,
        Arc::new(NoopEventBus),
        IngestConfig { emit_to_bus: false, dedup_window_secs: 0, ..IngestConfig::default() },
    );
    (Arc::new(pipeline), sink)
}

/// 装载假插件运行时（`timeout_ms = 0` 表示不启用超时）。
fn install_fake(reply: &str, timeout_ms: u64) {
    clear_plugin_runtime();
    install_plugin_runtime(PluginRuntime::new(
        Arc::new(FakeNormalizer::new(reply)),
        Some(PathBuf::from("plugins")),
        true,
        Duration::from_millis(timeout_ms),
    ));
}

/// ① 插件输出 → 落库 Event：**字段逐项来自插件**，`parser_key` = 模板 key。
// 刻意跨 await 持有全局互斥锁：插件运行时是进程级状态，这几个用例必须串行（见 GLOBAL_LOCK）
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn plugin_fields_reach_the_stored_event_through_the_webhook_path() {
    let _guard = lock_globals();
    install_fake(PLUGIN_ECS_JSON, DEFAULT_PLUGIN_TIMEOUT_MS);
    let (pipeline, sink) = pipeline_with(plugin_template("plugin=fake-normalizer"));
    let receiver = WebhookReceiver::new(Arc::clone(&pipeline), log_source(), "/ingest/webhook");

    let outcomes = receiver.ingest(LOG_LINE.as_bytes(), "10.0.0.9").await.expect("webhook 接入");
    let status = plugin_runtime_status();
    clear_plugin_runtime();

    assert_eq!(outcomes.len(), 1);
    let outcome = outcomes.first().expect("一条接入结果");
    assert!(outcome.matched, "插件模板必须命中: {:?}", outcome.error);
    assert_eq!(outcome.parser_key.as_deref(), Some("kv-plugin-access"));
    assert!(outcome.persisted);
    assert_eq!(status.calls, 1, "一次解析只调一次插件: {status:?}");
    assert_eq!(status.ok, 1);
    assert_eq!(status.loaded.first().map(|p| p.name.as_str()), Some("fake-normalizer"));

    // 事件侧：**字段来自插件输出**（不是从原始行正则抽出来的）
    let events = sink.events().expect("事件快照");
    assert_eq!(events.len(), 1, "事件必须落库");
    let event = events.first().expect("一条事件");
    assert_eq!(event.network.source_ip.as_deref(), Some("10.1.2.3"), "source.ip 来自插件");
    assert_eq!(event.network.destination_ip.as_deref(), Some("10.9.9.9"), "destination.ip 来自插件");
    assert_eq!(event.network.destination_port, Some(443), "destination.port 来自插件");
    assert_eq!(event.action, EventAction::Denied, "event.action 来自插件（block ⇒ denied）");
    assert_eq!(event.action_raw, "block", "原始动作值保真");
    assert_eq!(event.message, "SQL injection attempt", "message 来自插件");
    assert_eq!(
        event.extra.get("labels.tenant").and_then(Value::as_str),
        Some("acme"),
        "未识别路径进 extra（不丢数据）: {:?}",
        event.extra
    );
    assert!(event.time.to_rfc3339().starts_with("2026-02-21T10:00:00"), "插件 @timestamp → event.time");
    // 原始日志保真
    assert_eq!(sink.raws().expect("原始日志快照").len(), 1);
    println!(
        "落库事件：src={:?} dst={:?}:{:?} action={:?} message={:?}",
        event.network.source_ip,
        event.network.destination_ip,
        event.network.destination_port,
        event.action,
        event.message
    );
}

/// ④ 插件返回非法 JSON：**计入 parse_failed**、事件仍落库、进程不 panic。
// 同上：跨 await 持有全局锁是刻意的（进程级插件运行时）
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn illegal_json_is_counted_as_parse_failed_and_the_raw_log_is_still_persisted() {
    let _guard = lock_globals();
    install_fake("这不是 JSON", DEFAULT_PLUGIN_TIMEOUT_MS);
    let (pipeline, sink) = pipeline_with(plugin_template("plugin=fake-normalizer"));
    let receiver = WebhookReceiver::new(Arc::clone(&pipeline), log_source(), "/ingest/webhook");
    let metrics = MetricsRegistry::new();

    let outcomes = receiver.ingest(LOG_LINE.as_bytes(), "10.0.0.9").await.expect("webhook 接入");
    // 与生产同一口径：接收器把 outcomes 折算成"收到/命中/解析失败/丢弃"
    metrics.counters("webhook").add_received(u64::try_from(outcomes.len()).unwrap_or(0));
    metrics.counters("webhook").record_outcomes(&outcomes);
    let snapshot = metrics.counters("webhook").snapshot();
    let status = plugin_runtime_status();
    clear_plugin_runtime();

    let outcome = outcomes.first().expect("一条接入结果");
    assert!(!outcome.matched, "非法 JSON 不得算命中");
    assert!(outcome.persisted, "插件失败不得阻止落库");
    assert_eq!(snapshot.parse_failed, 1, "未命中 ⇒ parse_failed 如实计数: {snapshot:?}");
    assert_eq!(snapshot.matched, 0);
    assert_eq!(status.bad_output, 1, "{status:?}");
    assert!(
        status.recent_diagnostics.iter().any(|line| line.contains("bad_output") && line.contains("合法 JSON")),
        "插件失败的**具体原因**必须落诊断（注册表返回给流水线的 miss 原因是通用的，见下方注释）: {:?}",
        status.recent_diagnostics
    );

    // 事件仍照常生成（按 raw 兜底），原始日志保真
    assert_eq!(sink.events().expect("事件快照").len(), 1, "插件失败绝不丢事件（raw 兜底）");
    assert_eq!(sink.raws().expect("原始日志快照").len(), 1);
    // 口径说明（如实）：`IngestOutcome.error` 是**注册表级**的 miss 原因（"无模板命中"），
    // 与其它引擎一致；插件**分类原因**在 `plugin_runtime_status()` 的五类计数 + 最近诊断里，
    // 并经 `tracing::debug!` 打到进程日志（e2e 脚本按 RUST_LOG 的 debug 目标抓取）。
    println!(
        "插件失败后的接入结果：matched={} registry_error={:?} parse_failed={} plugin_bad_output={} diagnosis={:?}",
        outcome.matched, outcome.error, snapshot.parse_failed, status.bad_output, status.recent_diagnostics
    );
}

/// ⑤ 未配插件目录（未装载运行时）：如实报错/未命中，原始日志照常落库 —— 不 panic。
// 同上：跨 await 持有全局锁是刻意的（进程级插件运行时）
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn missing_runtime_degrades_instead_of_panicking() {
    let _guard = lock_globals();
    clear_plugin_runtime();
    let before = plugin_runtime_status();
    assert!(!before.configured, "本用例要求「关闭插件」的初始状态");

    let (pipeline, sink) = pipeline_with(plugin_template("plugin=fake-normalizer"));
    let receiver = WebhookReceiver::new(Arc::clone(&pipeline), log_source(), "/ingest/webhook");
    let outcomes = receiver.ingest(LOG_LINE.as_bytes(), "10.0.0.9").await.expect("webhook 接入");
    let stats = pipeline.stats();
    let after = plugin_runtime_status();

    let outcome = outcomes.first().expect("一条接入结果");
    assert!(!outcome.matched, "未装载插件 ⇒ 该模板未命中（降级路径）");
    assert_eq!(stats.unmatched, 1, "未命中如实计入流水线统计: {stats:?}");
    assert!(outcome.persisted && !sink.raws().expect("原始日志快照").is_empty(), "原始日志保真落库");
    assert!(after.unavailable > before.unavailable, "未装载导致的失败同样计数: {after:?}");
    assert!(after.describe().contains("未装载"), "运行态描述必须说明「未装载」: {}", after.describe());
    // 与 (c) 同一口径：注册表给的 miss 原因是通用的，插件级原因在计数/诊断/日志里
    println!(
        "未装载插件时的接入结果：matched={} registry_error={:?} unavailable_before={} unavailable_after={}",
        outcome.matched, outcome.error, before.unavailable, after.unavailable
    );
    println!("未装载插件时的接入结果：matched={} error={:?}", outcome.matched, outcome.error);
}

/// ⑥ YAML 里 `engine: plugin` 的模板能被注册表装载（声明解析 + 落注册表）。
#[test]
fn yaml_template_with_plugin_engine_is_accepted_by_the_registry() {
    let yaml = r#"
key: yaml-plugin-template
name: YAML 声明的插件模板
vendor: generic
product: kv
protocols: [webhook]
engine: plugin
pattern: "plugin=fake-normalizer entry=normalize ctx=raw"
mapping:
  time_field: "@timestamp"
required_fields: ["source.ip"]
description: 插件模板声明解析用例
"#;
    let defs = parse_template_file(yaml).expect("YAML 应能解析");
    assert_eq!(defs.len(), 1);
    let def = defs.first().expect("一个模板");
    assert_eq!(def.engine, ParserEngine::Plugin);
    assert_eq!(def.pattern, "plugin=fake-normalizer entry=normalize ctx=raw");

    let mut registry = ParserRegistry::new();
    registry.register(def.clone(), 1).expect("插件模板应被注册（加载期只校验规格，不要求插件已装载）");
    assert_eq!(registry.all().len(), 1);
    assert_eq!(registry.stats().invalid, 0, "{:?}", registry.invalid_templates());

    // 坏规格的 YAML 模板必须被**拒绝**并留下原因（不静默进匹配集）
    let mut broken = def.clone();
    broken.key = "yaml-plugin-broken".to_string();
    broken.pattern = "plugin=fake-normalizer entry=dump".to_string();
    let err = registry.register(broken, 2);
    assert!(err.is_err(), "非法插件入口不得注册");
    assert_eq!(registry.stats().invalid, 1, "{:?}", registry.invalid_templates());
    println!("非法插件模板被拒绝：{:?}", registry.invalid_templates());
}

/// ⑦ 真机（`#[ignore]`）：真 cdylib + 真 ABI ⇒ 真字段落库。
///
/// 跑法：`cargo test -p agf-ingest --test plugin_engine_e2e -- --ignored --nocapture`
// 同上：跨 await 持有全局锁是刻意的（进程级插件运行时）
#[allow(clippy::await_holding_lock)]
#[tokio::test]
#[ignore = "需要真实 cdylib（target/debug/agf_plugin_example.dll）：由 --ignored 显式门控"]
async fn real_plugin_dll_feeds_the_pipeline() {
    let _guard = lock_globals();
    let dll = locate_example_plugin();
    let dir = dll.parent().expect("动态库所在目录").to_path_buf();
    // 插件目录直接指向产物目录：`DynamicPluginInvoker` 真的用 libloading 装载它
    let invoker = DynamicPluginInvoker::load_dir(&dir).expect("装载插件目录");
    let names: Vec<String> = invoker.loaded().iter().map(|p| p.name.clone()).collect();
    assert!(names.iter().any(|n| n == "agf-plugin-example"), "已装载：{names:?}");
    install_plugin_runtime(PluginRuntime::new(
        Arc::new(invoker),
        Some(dir.clone()),
        true,
        Duration::from_millis(DEFAULT_PLUGIN_TIMEOUT_MS),
    ));

    let (pipeline, sink) = pipeline_with(plugin_template("plugin=agf-plugin-example"));
    let receiver = WebhookReceiver::new(Arc::clone(&pipeline), log_source(), "/ingest/webhook");
    let outcomes = receiver.ingest(LOG_LINE.as_bytes(), "10.0.0.9").await.expect("webhook 接入");
    let status = plugin_runtime_status();
    clear_plugin_runtime();

    let outcome = outcomes.first().expect("一条接入结果");
    assert!(outcome.matched, "真插件必须命中: {:?}", outcome.error);
    assert_eq!(status.calls, 1, "{status:?}");
    assert_eq!(status.call_errors, 0, "{status:?}");
    assert_eq!(status.bad_output, 0, "{status:?}");

    let events = sink.events().expect("事件快照");
    let event = events.first().expect("一条事件");
    assert_eq!(event.network.source_ip.as_deref(), Some("10.1.2.3"), "真插件产出的 source.ip");
    assert_eq!(event.network.destination_ip.as_deref(), Some("10.9.9.9"));
    assert_eq!(event.network.destination_port, Some(443));
    assert_eq!(event.action, EventAction::Denied);
    assert_eq!(event.action_raw, "block");
    assert_eq!(event.message, "SQL injection attempt");
    assert!(event.time.to_rfc3339().starts_with("2026-02-21T10:00:00"), "event.time 来自插件 @timestamp");
    // 插件的自述（`agf.plugin`）经模板 `mapping.map` 改写到 `observer.name` ——
    // 这条断言同时证明两件事：① 事件真的来自插件（不是内置引擎）；② `mapping.map` 对插件输出同样生效
    assert_eq!(
        event.extra.get("observer.name").and_then(Value::as_str),
        Some("agf-plugin-example"),
        "extra 里必须有插件的自述（经 mapping 改写）: {:?}",
        event.extra
    );
    println!(
        "真插件落库事件：src={:?} dst={:?}:{:?} action={:?}/{:?} time={} observer.name={:?}",
        event.network.source_ip,
        event.network.destination_ip,
        event.network.destination_port,
        event.action,
        event.action_raw,
        event.time.to_rfc3339(),
        event.extra.get("observer.name")
    );
}

/// 定位示例插件动态库（找不到就**自己构建一份**，且绝不静默跳过）。
fn locate_example_plugin() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().and_then(Path::parent).expect("仓库根").to_path_buf();
    let target = std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| root.join("target"), PathBuf::from);
    if let Some(path) = find_plugin_artifact(&target) {
        return path;
    }
    // `cargo test` 不会构建 cdylib ⇒ 换一个 target 目录构建（换锁，避免与正在运行的 cargo 死锁）
    let fallback = root.join("target").join("plugin-e2e");
    let status = std::process::Command::new(env!("CARGO"))
        .current_dir(&root)
        .args(["build", "-p", "agf-plugin-example", "--target-dir"])
        .arg(&fallback)
        .status()
        .expect("执行 cargo build -p agf-plugin-example");
    assert!(status.success(), "`cargo build -p agf-plugin-example` 失败（{status}）：真机用例需要真实 cdylib");
    find_plugin_artifact(&fallback).unwrap_or_else(|| panic!("已执行 cargo build，仍未找到示例插件动态库"))
}

fn find_plugin_artifact(target: &Path) -> Option<PathBuf> {
    let suffix = format!(".{}", plugin_file_suffix());
    for sub in ["debug", "debug/deps"] {
        let dir = target.join(sub);
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        let mut found: Vec<PathBuf> = entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.is_file())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.contains("agf_plugin_example") && name.ends_with(&suffix))
            })
            .collect();
        found.sort();
        if let Some(path) = found.into_iter().next() {
            return Some(path);
        }
    }
    None
}

/// 插件目录解析口径（`AGF_INGEST_PLUGIN_DIR` 优先，缺省 `<项目根>/plugins`）。
#[test]
fn plugin_dir_is_resolved_from_env_or_project_root() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().and_then(Path::parent).expect("仓库根");
    assert_eq!(resolve_plugin_dir(None, root), root.join("plugins"));
    assert_eq!(resolve_plugin_dir(Some("D:\\custom\\plugins"), root), PathBuf::from("D:\\custom\\plugins"));
}
