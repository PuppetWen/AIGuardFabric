//! 插件运行时：计数与诊断、超时包装、**进程级装载点**与环境变量解析。
//!
//! 拆分的理由：本文件是"什么时候调、调完怎么记账、进程启动时装什么"，
//! 调用接口在 [`super::invoker`]，对外快照在 [`super::status`]。

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;

use serde_json::Value;

use super::invoker::{DynamicPluginInvoker, EmptyInvoker, PluginCallError, PluginInvoker, call_with_timeout};
use super::status::PluginRuntimeStatus;
use super::{
    DEFAULT_PLUGIN_TIMEOUT_MS, PLUGIN_DIR_ENV, PLUGIN_TIMEOUT_ENV, PluginContext, PluginInput, PluginSpec,
    current_plugin_context, default_plugin_dir, parse_plugin_spec, plugin_json_to_fields,
};

/// 诊断环形缓冲容量（`derived_errors` 风格的"如实记账"）。
const MAX_DIAGNOSTICS: usize = 32;

/// 插件运行时计数器（原子量 ⇒ 多个解析任务并发调用也精确）。
#[derive(Debug, Default)]
struct Counters {
    calls: AtomicU64,
    ok: AtomicU64,
    unavailable: AtomicU64,
    unknown_plugin: AtomicU64,
    call_errors: AtomicU64,
    bad_output: AtomicU64,
    timeouts: AtomicU64,
}

impl Counters {
    fn record_failure(&self, kind: &str) {
        let target = match kind {
            "unavailable" => &self.unavailable,
            "unknown_plugin" => &self.unknown_plugin,
            "bad_output" => &self.bad_output,
            "timeout" => &self.timeouts,
            _ => &self.call_errors,
        };
        target.fetch_add(1, Ordering::Relaxed);
    }

    fn failures(&self) -> u64 {
        self.unavailable.load(Ordering::Relaxed)
            + self.unknown_plugin.load(Ordering::Relaxed)
            + self.call_errors.load(Ordering::Relaxed)
            + self.bad_output.load(Ordering::Relaxed)
            + self.timeouts.load(Ordering::Relaxed)
    }
}

/// 插件运行时：装载结果 + 超时策略 + 计数 + 诊断。
#[derive(Debug)]
pub struct PluginRuntime {
    invoker: Arc<dyn PluginInvoker>,
    dir: Option<PathBuf>,
    dir_exists: bool,
    timeout: Duration,
    counters: Counters,
    diagnostics: Mutex<VecDeque<String>>,
}

impl PluginRuntime {
    /// 构造（`dir` / `dir_exists` 只用于对外如实呈现，不参与调用逻辑）。
    #[must_use]
    pub fn new(invoker: Arc<dyn PluginInvoker>, dir: Option<PathBuf>, dir_exists: bool, timeout: Duration) -> Self {
        Self {
            invoker,
            dir,
            dir_exists,
            timeout,
            counters: Counters::default(),
            diagnostics: Mutex::new(VecDeque::new()),
        }
    }

    /// 超时策略。
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    /// 调用插件，返回**映射前**的扁平字段表。
    ///
    /// 名不存在的插件在**调用之前**就被拒（不走到 ABI）：这样"插件名写错"永远是一次便宜的
    /// 失败，也不会把 `calls` 计数弄脏（`calls` 只数真实调用）。
    ///
    /// # Errors
    /// 见 [`PluginCallError`] 的五类（全部计数 + 落诊断，绝不 panic）。
    pub fn invoke(
        &self,
        spec: &PluginSpec,
        raw: &str,
        context: &PluginContext,
    ) -> Result<std::collections::BTreeMap<String, Value>, PluginCallError> {
        let loaded = self.invoker.loaded();
        if !loaded.iter().any(|plugin| plugin.name == spec.name) {
            let error = PluginCallError::UnknownPlugin {
                plugin: spec.name.clone(),
                loaded: loaded.iter().map(|plugin| plugin.name.clone()).collect(),
            };
            self.record(&error);
            return Err(error);
        }
        self.counters.calls.fetch_add(1, Ordering::Relaxed);
        let payload = Self::payload(spec, raw, context);
        let text = match call_with_timeout(&self.invoker, &spec.name, &payload, self.timeout) {
            Ok(text) => text,
            Err(error) => {
                self.record(&error);
                return Err(error);
            }
        };
        match plugin_json_to_fields(&text) {
            Ok(fields) => {
                self.counters.ok.fetch_add(1, Ordering::Relaxed);
                Ok(fields)
            }
            Err(reason) => {
                let error = PluginCallError::BadOutput { plugin: spec.name.clone(), reason };
                self.record(&error);
                Err(error)
            }
        }
    }

    /// 按规格把原始日志行 + 上下文变成传给插件的载荷文本。
    fn payload(spec: &PluginSpec, raw: &str, context: &PluginContext) -> String {
        match spec.input {
            PluginInput::Raw => raw.to_string(),
            PluginInput::Envelope => serde_json::json!({
                "input": raw,
                "context": {
                    "protocol": context.protocol,
                    "source": context.source,
                    "received_at": context.received_at,
                    "plugin": spec.name,
                    "entry": spec.entry,
                },
            })
            .to_string(),
        }
    }

    /// 记一次失败：计数 + 追加诊断（`derived_errors` 风格：如实记账，不中断主流程）。
    fn record(&self, error: &PluginCallError) {
        self.counters.record_failure(error.kind());
        // `PluginCallError` 的 Display 已带插件名与该类的如实说明，直接复用（避免两处口径漂移）
        let line = format!("[{}] {error}", error.kind());
        tracing::debug!(kind = error.kind(), diagnostic = %line, "插件调用失败（已计数并落诊断）");
        if let Ok(mut ring) = self.diagnostics.lock() {
            if ring.len() >= MAX_DIAGNOSTICS {
                let _ = ring.pop_front();
            }
            ring.push_back(line);
        }
    }

    /// 运行态快照。
    #[must_use]
    pub fn status(&self) -> PluginRuntimeStatus {
        let loaded = self.invoker.loaded().to_vec();
        let load_failures = self.invoker.failures().to_vec();
        let recent_diagnostics = self.diagnostics.lock().map(|ring| ring.iter().cloned().collect()).unwrap_or_default();
        PluginRuntimeStatus {
            configured: true,
            dir: self.dir.as_ref().map(|dir| dir.display().to_string()),
            dir_exists: self.dir_exists,
            timeout_ms: u64::try_from(self.timeout.as_millis()).unwrap_or(u64::MAX),
            loaded,
            load_failures,
            calls: self.counters.calls.load(Ordering::Relaxed),
            ok: self.counters.ok.load(Ordering::Relaxed),
            failures: self.counters.failures(),
            unavailable: self.counters.unavailable.load(Ordering::Relaxed),
            unknown_plugin: self.counters.unknown_plugin.load(Ordering::Relaxed),
            call_errors: self.counters.call_errors.load(Ordering::Relaxed),
            bad_output: self.counters.bad_output.load(Ordering::Relaxed),
            timeouts: self.counters.timeouts.load(Ordering::Relaxed),
            recent_diagnostics,
        }
    }
}

// ---------------------------------------------------------------------------
// 全局装载点
// ---------------------------------------------------------------------------

/// 未装载运行时期间的 `unavailable` 计数（"关闭插件"路径也要如实计数）。
static UNAVAILABLE_CALLS: AtomicU64 = AtomicU64::new(0);

static RUNTIME: OnceLock<RwLock<Option<Arc<PluginRuntime>>>> = OnceLock::new();

fn slot() -> &'static RwLock<Option<Arc<PluginRuntime>>> {
    RUNTIME.get_or_init(|| RwLock::new(None))
}

/// 装载插件运行时（替换既有运行时；返回新运行时的 `Arc`）。
pub fn install_plugin_runtime(runtime: PluginRuntime) -> Arc<PluginRuntime> {
    let installed = Arc::new(runtime);
    match slot().write() {
        Ok(mut guard) => *guard = Some(Arc::clone(&installed)),
        Err(poisoned) => *poisoned.into_inner() = Some(Arc::clone(&installed)),
    }
    installed
}

/// 卸载插件运行时（回到"关闭插件"状态；测试与显式关闭共用）。
pub fn clear_plugin_runtime() {
    match slot().write() {
        Ok(mut guard) => *guard = None,
        Err(poisoned) => *poisoned.into_inner() = None,
    }
}

/// 当前插件运行时（`None` = 未装载）。
#[must_use]
pub fn plugin_runtime() -> Option<Arc<PluginRuntime>> {
    slot().read().ok().and_then(|guard| guard.clone())
}

/// 运行态快照（未装载时也给出如实状态：`configured=false`，且累计"未装载失败"计数）。
#[must_use]
pub fn plugin_runtime_status() -> PluginRuntimeStatus {
    plugin_runtime().map_or_else(
        || PluginRuntimeStatus {
            configured: false,
            dir: None,
            dir_exists: false,
            timeout_ms: DEFAULT_PLUGIN_TIMEOUT_MS,
            loaded: Vec::new(),
            load_failures: Vec::new(),
            calls: 0,
            ok: 0,
            failures: UNAVAILABLE_CALLS.load(Ordering::Relaxed),
            unavailable: UNAVAILABLE_CALLS.load(Ordering::Relaxed),
            unknown_plugin: 0,
            call_errors: 0,
            bad_output: 0,
            timeouts: 0,
            recent_diagnostics: Vec::new(),
        },
        |runtime| runtime.status(),
    )
}

/// 显式关闭插件目录的取值（`AGF_INGEST_PLUGIN_DIR` 填这些 = 关闭插件）。
#[must_use]
pub fn is_disabled_plugin_dir(value: &str) -> bool {
    matches!(value.trim().to_ascii_lowercase().as_str(), "0" | "off" | "none" | "disabled" | "false")
}

/// 解析超时环境变量取值（毫秒；`0` = 不启用超时）。
///
/// # Errors
/// 不是合法整数。
pub fn parse_plugin_timeout(raw: &str) -> Result<Duration, String> {
    let text = raw.trim();
    match text.parse::<u64>() {
        Ok(ms) => Ok(Duration::from_millis(ms)),
        Err(error) => Err(format!("{PLUGIN_TIMEOUT_ENV}={text} 不是合法毫秒数：{error}")),
    }
}

/// 插件目录解析：显式配置优先，否则 `<项目根>/plugins`。
#[must_use]
pub fn resolve_plugin_dir(configured: Option<&str>, root: &Path) -> PathBuf {
    match configured.map(str::trim).filter(|value| !value.is_empty()) {
        Some(value) => PathBuf::from(value),
        None => default_plugin_dir(root),
    }
}

/// 装载插件运行时（给定目录与超时），并登记为进程级运行时。
pub fn load_plugin_runtime(dir: &Path, timeout: Duration) -> PluginRuntimeStatus {
    let dir_exists = dir.is_dir();
    let invoker = match DynamicPluginInvoker::load_dir(dir) {
        Ok(invoker) => Arc::new(invoker) as Arc<dyn PluginInvoker>,
        Err(error) => {
            tracing::warn!(dir = %dir.display(), error = %error, "插件目录不可用：按「无插件」装载（宿主继续）");
            Arc::new(EmptyInvoker) as Arc<dyn PluginInvoker>
        }
    };
    let runtime = PluginRuntime::new(invoker, Some(dir.to_path_buf()), dir_exists, timeout);
    install_plugin_runtime(runtime).status()
}

/// 按环境变量装载插件运行时（`apps/ingest` 启动期调用）。
///
/// 策略（三条都"绝不阻止进程启动"）：
/// * `AGF_INGEST_PLUGIN_DIR` 显式关闭取值（`0`/`off`/`none`/`false`/`disabled`）⇒ 卸载运行时；
/// * 未配置 **且** 默认 `<root>/plugins` 不存在 ⇒ 不装载（缺插件不是错误）；
/// * 显式配置了目录（哪怕目录不存在）⇒ 装载并**如实报告**"目录不存在，无插件可用"。
pub fn install_plugin_runtime_from_env(root: &Path) -> PluginRuntimeStatus {
    let raw = std::env::var(PLUGIN_DIR_ENV).ok().map(|value| value.trim().to_string()).filter(|v| !v.is_empty());
    if raw.as_deref().is_some_and(is_disabled_plugin_dir) {
        clear_plugin_runtime();
        tracing::info!(env = PLUGIN_DIR_ENV, "插件按配置关闭：engine: plugin 模板走降级路径（如实报错/未命中）");
        return plugin_runtime_status();
    }
    let explicit = raw.is_some();
    let dir = resolve_plugin_dir(raw.as_deref(), root);
    if !explicit && !dir.is_dir() {
        clear_plugin_runtime();
        tracing::warn!(
            dir = %dir.display(),
            env = PLUGIN_DIR_ENV,
            "未配置插件目录且默认目录不存在：按「无插件」启动（engine: plugin 模板走降级路径）"
        );
        return plugin_runtime_status();
    }
    let timeout = match std::env::var(PLUGIN_TIMEOUT_ENV) {
        Ok(text) if !text.trim().is_empty() => parse_plugin_timeout(&text).unwrap_or_else(|error| {
            tracing::warn!(error = %error, "插件超时配置非法：回退默认值");
            Duration::from_millis(DEFAULT_PLUGIN_TIMEOUT_MS)
        }),
        _ => Duration::from_millis(DEFAULT_PLUGIN_TIMEOUT_MS),
    };
    let status = load_plugin_runtime(&dir, timeout);
    if status.loaded.is_empty() && status.load_failures.is_empty() {
        tracing::warn!(dir = %dir.display(), "插件目录里没有可装载的动态库：engine: plugin 模板将如实报错/未命中");
    } else {
        tracing::info!(
            dir = %dir.display(),
            loaded = status.loaded.len(),
            failed = status.load_failures.len(),
            timeout_ms = status.timeout_ms,
            "Rust 动态库插件已装载（同进程、同权限：仅加载可信插件）"
        );
    }
    for failure in &status.load_failures {
        tracing::warn!(path = %failure.path, reason = %failure.reason, "插件装载失败（已登记，宿主继续）");
    }
    status
}

/// `engine: plugin` 的解析入口：返回**映射前**的扁平字段表（供 `engine::run_engine` 调用）。
///
/// # Errors
/// 规格非法、运行时未装载、或 [`PluginCallError`] 的五类失败；全部是**人类可读的明确原因**。
/// 注意：注册表会把这里的错误收敛成它自己的 miss 原因（"无模板命中"），
/// 插件**分类原因**在 [`plugin_runtime_status`] 的计数/诊断与 `tracing::debug!` 日志里。
pub fn run_plugin_engine(spec_text: &str, raw: &str) -> Result<std::collections::BTreeMap<String, Value>, String> {
    let spec = parse_plugin_spec(spec_text)?;
    let Some(runtime) = plugin_runtime() else {
        UNAVAILABLE_CALLS.fetch_add(1, Ordering::Relaxed);
        let error = PluginCallError::Unavailable { dir: None };
        // `kind` 与其余四类失败的日志口径一致（便于按分类抓日志/告警）
        tracing::debug!(
            kind = error.kind(),
            spec = %spec.describe(),
            error = %error,
            "插件运行时未装载：模板未命中（原始日志照常落库）"
        );
        return Err(error.to_string());
    };
    let context = current_plugin_context();
    runtime.invoke(&spec, raw, &context).map_err(|error| error.to_string())
}
