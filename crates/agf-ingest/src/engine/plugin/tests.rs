//! `engine::plugin` 单元测试：规格解析、字段映射、失败五分类、超时、降级与能力矩阵口径。
//!
//! 这里用 [`PluginInvoker`] 的**假实现**钉住接线层（超时、计数、诊断、映射口径），
//! 真 dll 路径由 `crates/agf-plugin/tests/plugin_loading.rs` 与
//! `crates/agf-ingest/tests/plugin_engine_e2e.rs` 的 `#[ignore]` 用例覆盖 ——
//! CI 因此不依赖"能不能编出 cdylib"这件与接线逻辑无关的事。
//!
//! 插件运行时是**进程级**的（生产语义如此），所以会装载/卸载它的用例必须串行：
//! 先取 [`GLOBAL_LOCK`]，退出前 `clear_plugin_runtime()`。
#![allow(clippy::panic)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::*;

use crate::engine::{engine_support_matrix, parse_with, validate_pattern};
use crate::registry::{ParserRegistry, engine_support_matrix as registry_engine_matrix};
use agf_core::enums::IngestProtocol;
use agf_core::parser::{FieldMapping, ParserDefinition, ParserEngine};

/// 串行闸门：插件运行时是进程级全局状态，本文件的用例必须互斥执行。
static GLOBAL_LOCK: Mutex<()> = Mutex::new(());

fn lock_globals() -> std::sync::MutexGuard<'static, ()> {
    GLOBAL_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// 假插件的行为。
enum FakeBehaviour {
    /// 正常返回一段 JSON 文本（合法 / 非法由用例决定）。
    Reply(String),
    /// 业务失败（模拟插件 `last_error`）。
    Business(String),
    /// 先睡 `millis` 毫秒再返回（用于超时用例）。
    SleepThenReply { millis: u64, json: String },
}

/// 假插件：记录调用次数、完成计数与收到的载荷。
struct FakePlugin {
    /// 装载信息（运行时的"已装载清单"直接取它）。
    info: PluginLoadedInfo,
    behaviour: FakeBehaviour,
    calls: AtomicU64,
    finished: AtomicU64,
    payloads: Mutex<Vec<String>>,
}

impl std::fmt::Debug for FakePlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakePlugin").field("name", &self.info.name).finish_non_exhaustive()
    }
}

impl FakePlugin {
    fn new(name: &str, behaviour: FakeBehaviour) -> Arc<Self> {
        Arc::new(Self {
            info: PluginLoadedInfo {
                name: name.to_string(),
                version: "1.2.3".to_string(),
                kind: "normalizer".to_string(),
                path: format!("plugins/{name}.dll"),
            },
            behaviour,
            calls: AtomicU64::new(0),
            finished: AtomicU64::new(0),
            payloads: Mutex::new(Vec::new()),
        })
    }

    fn calls(&self) -> u64 {
        self.calls.load(Ordering::Relaxed)
    }

    fn finished(&self) -> u64 {
        self.finished.load(Ordering::Relaxed)
    }

    fn last_payload(&self) -> Option<String> {
        self.payloads.lock().ok().and_then(|list| list.last().cloned())
    }
}

impl PluginInvoker for FakePlugin {
    fn invoke(&self, plugin: &str, payload: &str) -> Result<String, PluginCallError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut list) = self.payloads.lock() {
            list.push(payload.to_string());
        }
        let result = match &self.behaviour {
            FakeBehaviour::Reply(text) => Ok(text.clone()),
            FakeBehaviour::Business(reason) => {
                Err(PluginCallError::Call { plugin: plugin.to_string(), reason: reason.clone() })
            }
            FakeBehaviour::SleepThenReply { millis, json } => {
                std::thread::sleep(Duration::from_millis(*millis));
                Ok(json.clone())
            }
        };
        self.finished.fetch_add(1, Ordering::Relaxed);
        result
    }

    fn loaded(&self) -> &[PluginLoadedInfo] {
        std::slice::from_ref(&self.info)
    }

    fn failures(&self) -> &[PluginLoadFailureInfo] {
        &[]
    }
}

/// 装载一个假插件运行时（调用方必须已持有 [`GLOBAL_LOCK`]）。
fn install_fake(plugin: &Arc<FakePlugin>, timeout_ms: u64) -> Arc<PluginRuntime> {
    install_plugin_runtime(PluginRuntime::new(
        Arc::clone(plugin) as Arc<dyn PluginInvoker>,
        Some(PathBuf::from("plugins")),
        true,
        Duration::from_millis(timeout_ms),
    ))
}

/// 一条 `engine: plugin` 模板（`mapping` 把插件输出的源字段改写成 ECS 路径）。
fn plugin_template(pattern: &str) -> ParserDefinition {
    let mut def = ParserDefinition {
        key: "plugin-e2e".to_string(),
        name: "插件模板".to_string(),
        vendor: "generic".to_string(),
        product: "plugin".to_string(),
        protocols: vec![IngestProtocol::Webhook],
        engine: ParserEngine::Plugin,
        pattern: pattern.to_string(),
        fallback_patterns: vec![],
        mapping: FieldMapping {
            map: [("src", "source.ip"), ("actor", "user.name")]
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            time_field: Some("@timestamp".to_string()),
            ..FieldMapping::default()
        },
        derived: std::collections::BTreeMap::new(),
        required_fields: vec!["src".to_string()],
        version: 1,
        builtin: false,
        ai_inferred: false,
        description: String::new(),
        sample_fixture: String::new(),
    };
    def.mapping.defaults.insert("event.dataset".to_string(), Value::from("plugin.test"));
    def
}

const PLUGIN_JSON: &str = r#"{"@timestamp":"2026-02-21T10:00:00Z","src":"10.1.2.3","event":{"action":"block"},"destination":{"port":443},"message":"SQL injection attempt"}"#;

// ---- 1. 规格解析（模板声明） ----

#[test]
fn plugin_spec_parses_name_entry_and_ctx() {
    let bare = parse_plugin_spec("agf-plugin-example").unwrap_or_else(|e| unreachable!("裸插件名应合法: {e}"));
    assert_eq!(bare.name, "agf-plugin-example");
    assert_eq!(bare.entry, "normalize");
    assert_eq!(bare.input, PluginInput::Raw);

    let full = parse_plugin_spec("plugin=demo entry=normalize ctx=envelope").unwrap_or_else(|e| unreachable!("{e}"));
    assert_eq!(full.name, "demo");
    assert_eq!(full.input, PluginInput::Envelope);
    assert!(full.describe().contains("plugin=demo"));

    // 多行 / 逗号 / `#` 注释都接受（YAML 里怎么写都行）
    let multi = parse_plugin_spec("# 说明\nplugin=demo,\nctx=raw").unwrap_or_else(|e| unreachable!("{e}"));
    assert_eq!(multi.name, "demo");

    // 非法规格必须**明确**报错（坏模板不进匹配集）
    let bad_cases = [
        "",
        "entry=normalize",
        "plugin=demo entry=parse",
        "plugin=demo ctx=json",
        "plugin=bad name",
        "plugin=demo unknown=1",
        "plugin=a plugin=b",
        "plugin=a b",
    ];
    for bad in bad_cases {
        assert!(parse_plugin_spec(bad).is_err(), "`{bad}` 应被拒绝");
    }
    let Err(error) = parse_plugin_spec("plugin=demo entry=parse") else { unreachable!("entry=parse 必须被拒") };
    assert!(error.contains("ABI v1"), "{error}");
}

#[test]
fn plugin_template_declaration_is_validated_by_pattern_rules() {
    assert!(validate_pattern(&plugin_template("plugin=agf-plugin-example")).is_ok());
    let broken = validate_pattern(&plugin_template("plugin=agf-plugin-example entry=parse"));
    assert!(broken.is_err(), "入口不是 normalize 必须加载期拒绝");
    assert!(broken.err().unwrap_or_default().contains("entry=parse"));
}

// ---- 2. 插件输出 → 扁平字段（映射前口径） ----

#[test]
fn plugin_json_flattens_nested_objects_and_rejects_bad_payloads() {
    let fields = plugin_json_to_fields(PLUGIN_JSON).unwrap_or_else(|e| unreachable!("{e}"));
    assert_eq!(fields.get("src").and_then(Value::as_str), Some("10.1.2.3"));
    assert_eq!(fields.get("event.action").and_then(Value::as_str), Some("block"));
    assert_eq!(fields.get("destination.port").and_then(Value::as_i64), Some(443));
    // 数组按原值保留（不展开），便于模板用 `mapping.map` 处理
    let with_array = plugin_json_to_fields(r#"{"tags":["a","b"],"n":1}"#).unwrap_or_else(|e| unreachable!("{e}"));
    assert_eq!(with_array.get("tags").and_then(Value::as_array).map(Vec::len), Some(2));

    assert!(plugin_json_to_fields("not json").is_err());
    assert!(plugin_json_to_fields("[1,2,3]").is_err(), "顶层数组不是 AGF-ECS 字段表");
    assert!(plugin_json_to_fields("{}").is_err(), "空对象等于什么都没抽到");
    assert!(plugin_json_to_fields("null").is_err());
}

// ---- 3. 调用与字段映射（走既有 apply_mapping） ----

#[test]
fn plugin_engine_maps_fields_through_existing_mapping_path() {
    let _guard = lock_globals();
    clear_plugin_runtime();
    let plugin = FakePlugin::new("fake", FakeBehaviour::Reply(PLUGIN_JSON.to_string()));
    install_fake(&plugin, 500);

    let def = plugin_template("plugin=fake");
    let outcome = parse_with(&def, "src=10.1.2.3 action=block");
    clear_plugin_runtime();

    assert!(outcome.matched, "插件成功返回时必须命中: {:?}", outcome.error);
    assert_eq!(outcome.parser_key.as_deref(), Some("plugin-e2e"));
    // 插件直出的 ECS 路径原样保留
    assert_eq!(outcome.get_str("message"), Some("SQL injection attempt"));
    assert_eq!(outcome.get_str("event.action"), Some("block"));
    assert_eq!(outcome.fields.get("destination.port").and_then(Value::as_i64), Some(443));
    // 模板 `mapping.map` 的源字段名改写照常生效
    assert_eq!(outcome.get_str("source.ip"), Some("10.1.2.3"));
    // `mapping.time_field` 把插件的 `@timestamp` 落到 `event.time`（复用既有时间映射）
    assert!(outcome.get_str("event.time").unwrap_or_default().starts_with("2026-02-21T10:00:00"));
    // `mapping.defaults` 照常补值
    assert_eq!(outcome.get_str("event.dataset"), Some("plugin.test"));
    // 一次解析只调一次插件（插件不参与样本打分 ⇒ 不会重复调用/重复计数）
    assert_eq!(plugin.calls(), 1, "插件只应被调用一次");
    // `ctx=raw`（默认）：插件收到的是**原始日志行**
    assert_eq!(plugin.last_payload().as_deref(), Some("src=10.1.2.3 action=block"));
}

#[test]
fn envelope_mode_carries_protocol_source_and_time_to_the_plugin() {
    let _guard = lock_globals();
    clear_plugin_runtime();
    let plugin = FakePlugin::new("fake", FakeBehaviour::Reply(r#"{"src":"10.0.0.1"}"#.to_string()));
    install_fake(&plugin, 500);

    let context_guard = set_plugin_context(PluginContext {
        protocol: "webhook".to_string(),
        source: "generic".to_string(),
        received_at: "2026-02-21T10:23:45Z".to_string(),
    });
    let outcome = parse_with(&plugin_template("plugin=fake ctx=envelope"), "src=10.0.0.1");
    drop(context_guard);
    clear_plugin_runtime();

    assert!(outcome.matched, "{:?}", outcome.error);
    let payload = plugin.last_payload().unwrap_or_default();
    let envelope: Value = serde_json::from_str(&payload).unwrap_or_else(|e| unreachable!("信封必须是合法 JSON: {e}"));
    assert_eq!(envelope["input"], "src=10.0.0.1");
    assert_eq!(envelope["context"]["protocol"], "webhook");
    assert_eq!(envelope["context"]["source"], "generic");
    assert_eq!(envelope["context"]["received_at"], "2026-02-21T10:23:45Z");
}

// ---- 4. 失败分类：非法 JSON / 业务失败 / 插件名不存在 / 超时 ----

#[test]
fn illegal_json_is_counted_and_never_matches_or_panics() {
    let _guard = lock_globals();
    clear_plugin_runtime();
    let plugin = FakePlugin::new("fake", FakeBehaviour::Reply("这不是 JSON".to_string()));
    install_fake(&plugin, 500);

    let outcome = parse_with(&plugin_template("plugin=fake"), "src=10.0.0.1");
    let status = plugin_runtime_status();
    clear_plugin_runtime();

    assert!(!outcome.matched, "非法 JSON 不得算命中");
    let error = outcome.error.unwrap_or_default();
    assert!(error.contains("载荷不可用") && error.contains("合法 JSON"), "{error}");
    assert_eq!(status.bad_output, 1, "非法 JSON 必须计入 bad_output: {status:?}");
    assert_eq!(status.call_errors, 0);
    assert_eq!(status.timeouts, 0);
    assert_eq!(status.failures, 1);
    assert!(
        status.recent_diagnostics.iter().any(|line| line.contains("bad_output")),
        "{:?}",
        status.recent_diagnostics
    );
}

#[test]
fn plugin_business_failure_is_counted_as_call_error() {
    let _guard = lock_globals();
    clear_plugin_runtime();
    let plugin = FakePlugin::new("fake", FakeBehaviour::Business("没有识别出任何已知字段".to_string()));
    install_fake(&plugin, 500);

    let outcome = parse_with(&plugin_template("plugin=fake"), "foo=1 bar=2");
    let status = plugin_runtime_status();
    clear_plugin_runtime();

    assert!(!outcome.matched);
    let error = outcome.error.unwrap_or_default();
    assert!(error.contains("调用失败") && error.contains("没有识别出任何已知字段"), "{error}");
    assert_eq!(status.call_errors, 1, "{status:?}");
    assert_eq!(status.bad_output, 0);
}

#[test]
fn unknown_plugin_reports_loaded_names() {
    let _guard = lock_globals();
    clear_plugin_runtime();
    let plugin = FakePlugin::new("fake", FakeBehaviour::Reply(PLUGIN_JSON.to_string()));
    install_fake(&plugin, 500);

    let outcome = parse_with(&plugin_template("plugin=no-such-plugin"), "src=1");
    let status = plugin_runtime_status();
    clear_plugin_runtime();

    assert!(!outcome.matched);
    let error = outcome.error.unwrap_or_default();
    assert!(error.contains("未装载") && error.contains("已装载"), "{error}");
    assert_eq!(status.unknown_plugin, 1, "{status:?}");
    assert_eq!(plugin.calls(), 0, "插件名不存在时不应发生任何真实调用");
}

#[test]
fn timeout_discards_the_result_but_the_plugin_thread_keeps_running() {
    let _guard = lock_globals();
    clear_plugin_runtime();
    let plugin = FakePlugin::new("slow", FakeBehaviour::SleepThenReply { millis: 300, json: PLUGIN_JSON.to_string() });
    install_fake(&plugin, 50);

    let started = std::time::Instant::now();
    let outcome = parse_with(&plugin_template("plugin=slow"), "src=10.0.0.1");
    let elapsed = started.elapsed();
    let status = plugin_runtime_status();

    assert!(!outcome.matched, "超时必须按失败处理");
    let error = outcome.error.unwrap_or_default();
    assert!(error.contains("超时") && error.contains("仍在跑"), "超时说明必须如实写出局限: {error}");
    assert!(elapsed < Duration::from_millis(250), "超时应及时返回（实际 {elapsed:?}）");
    assert_eq!(status.timeouts, 1, "{status:?}");

    // **如实局限**：宿主放弃了结果，但被放弃的插件线程仍在跑完（这里等它跑完再断言）
    std::thread::sleep(Duration::from_millis(400));
    assert_eq!(plugin.finished(), 1, "被放弃的插件调用确实跑完了（这就是「无法中断」的实证）");
    clear_plugin_runtime();
}

#[test]
fn timeout_configuration_parsing_is_strict_and_zero_disables_the_watchdog() {
    assert_eq!(parse_plugin_timeout("120").unwrap_or_default(), Duration::from_millis(120));
    assert_eq!(parse_plugin_timeout(" 0 ").unwrap_or_default(), Duration::ZERO);
    assert!(parse_plugin_timeout("abc").is_err());
    assert!(parse_plugin_timeout("-1").is_err());
    assert_eq!(DEFAULT_PLUGIN_TIMEOUT_MS, 500);

    // `0` = 同线程直调（不启用看门狗）：慢插件会阻塞调用线程，但结果**不丢**
    let _guard = lock_globals();
    clear_plugin_runtime();
    let plugin = FakePlugin::new("slow", FakeBehaviour::SleepThenReply { millis: 60, json: PLUGIN_JSON.to_string() });
    install_fake(&plugin, 0);
    let outcome = parse_with(&plugin_template("plugin=slow"), "src=10.0.0.1");
    let status = plugin_runtime_status();
    clear_plugin_runtime();
    assert!(outcome.matched, "{:?}", outcome.error);
    assert_eq!(status.timeouts, 0);
    assert_eq!(status.ok, 1);
}

// ---- 5. 降级：未装载运行时 / 目录不存在 / 显式关闭 ----

#[test]
fn missing_runtime_degrades_with_an_explicit_reason_and_is_counted() {
    let _guard = lock_globals();
    clear_plugin_runtime();
    let before = plugin_runtime_status();
    assert!(!before.configured, "未装载时 configured 必须为 false");
    assert!(before.loaded.is_empty());

    let outcome = parse_with(&plugin_template("plugin=anything"), "src=1");
    let after = plugin_runtime_status();
    assert!(!outcome.matched);
    let error = outcome.error.unwrap_or_default();
    assert!(error.contains("插件引擎不可用") && error.contains(PLUGIN_DIR_ENV), "{error}");
    assert!(after.unavailable > before.unavailable, "未装载运行时的失败也要如实计数");
    assert!(after.describe().contains("未装载"), "{}", after.describe());
}

#[test]
fn missing_plugin_directory_is_reported_as_such() {
    let _guard = lock_globals();
    clear_plugin_runtime();
    let dir = std::env::temp_dir().join("agf-plugin-dir-that-does-not-exist-9f1c");
    let status = load_plugin_runtime(&dir, Duration::from_millis(DEFAULT_PLUGIN_TIMEOUT_MS));
    let loaded = status.loaded.len();
    let failures = status.load_failures.len();
    let describe = status.describe();
    clear_plugin_runtime();

    assert!(status.configured, "显式配置了目录 ⇒ 必须装载运行时并如实报「目录不存在」");
    assert!(!status.dir_exists);
    assert_eq!(loaded, 0);
    assert_eq!(failures, 0, "目录不存在不是「插件装载失败」");
    assert!(describe.contains("不存在"), "{describe}");
    assert!(!status.notes().is_empty());
}

#[test]
fn plugin_dir_resolution_and_explicit_disable_switch() {
    let root = PathBuf::from("D:\\proj");
    assert_eq!(resolve_plugin_dir(None, &root), root.join(DEFAULT_PLUGIN_DIR_NAME));
    assert_eq!(resolve_plugin_dir(Some("  "), &root), root.join(DEFAULT_PLUGIN_DIR_NAME));
    assert_eq!(resolve_plugin_dir(Some(" D:\\x\\plugins "), &root), PathBuf::from("D:\\x\\plugins"));
    for value in ["0", "off", "NONE", "disabled", "False"] {
        assert!(is_disabled_plugin_dir(value), "`{value}` 应被识别为显式关闭");
    }
    assert!(!is_disabled_plugin_dir("plugins"));
}

// ---- 6. 与内置引擎共存 + 能力矩阵口径 ----

#[test]
fn plugin_and_builtin_engines_coexist_without_interference() {
    let _guard = lock_globals();
    clear_plugin_runtime();

    let mut registry = ParserRegistry::new();
    // 插件模板优先级更高；插件失败时**必须**继续落到内置引擎的模板
    assert!(registry.register(plugin_template("plugin=fake"), 1).is_ok());
    let mut regex = plugin_template("(?P<src>\\S+)=(?P<value>\\S+)");
    regex.key = "regex-fallback".to_string();
    regex.engine = ParserEngine::Regex;
    regex.required_fields = vec!["src".to_string()];
    assert!(registry.register(regex, 2).is_ok());

    // ① 插件正常 → 插件模板命中
    let good = FakePlugin::new("fake", FakeBehaviour::Reply(PLUGIN_JSON.to_string()));
    install_fake(&good, 500);
    let hit = registry.match_raw("src=10.9.9.9", IngestProtocol::Webhook, None, None);
    assert!(hit.matched, "{:?}", hit.error);
    assert_eq!(hit.parser_key.as_deref(), Some("plugin-e2e"));
    assert_eq!(hit.get_str("source.ip"), Some("10.1.2.3"), "字段来自插件输出");

    // ② 插件返回非法 JSON → 不命中插件模板，**照常**落到内置 Regex 模板（互不影响）
    clear_plugin_runtime();
    let bad = FakePlugin::new("fake", FakeBehaviour::Reply("broken".to_string()));
    install_fake(&bad, 500);
    let fallback = registry.match_raw("src=10.9.9.9", IngestProtocol::Webhook, None, None);
    let status = plugin_runtime_status();
    clear_plugin_runtime();
    assert!(fallback.matched, "插件失败后内置引擎必须照常工作: {:?}", fallback.error);
    assert_eq!(fallback.parser_key.as_deref(), Some("regex-fallback"));
    assert_eq!(status.bad_output, 1);
}

#[test]
fn capability_matrices_are_truthful_about_the_plugin_engine() {
    // 引擎矩阵（engine/support.rs）：Plugin = 已实现 + 局限写清
    let matrix = engine_support_matrix();
    let row = matrix.iter().find(|(engine, _, _)| *engine == ParserEngine::Plugin);
    assert!(row.is_some_and(|(_, ok, note)| *ok && note.contains("已实现") && note.contains("超时")), "{row:?}");
    assert!(!matrix.iter().any(|(_, _, note)| note.contains("TODO ingest-plugin")), "不得再留下未实现锚点");

    // 注册表矩阵（registry/template_file.rs）：plugin / cel 两行都不许再写"未实现/TODO"
    let registry_matrix = registry_engine_matrix();
    let plugin = registry_matrix.get("plugin").copied().unwrap_or_default();
    assert!(plugin.contains("已实现") && !plugin.contains("TODO"), "{plugin}");
    let cel = registry_matrix.get("cel").copied().unwrap_or_default();
    assert!(cel.contains("已实现") && !cel.contains("TODO"), "{cel}");

    // 运行态矩阵（plugin_runtime_status）：未装载时如实说"未装载"，不许写成"已就绪"
    let _guard = lock_globals();
    clear_plugin_runtime();
    let status = plugin_runtime_status();
    assert!(!status.configured);
    assert!(status.describe().contains("未装载"));
    assert_eq!(status.timeout_ms, DEFAULT_PLUGIN_TIMEOUT_MS, "未装载时超时配置仍如实给出默认值");
    assert!(!status.dir_exists);
}
