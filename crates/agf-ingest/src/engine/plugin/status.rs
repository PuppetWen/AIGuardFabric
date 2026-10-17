//! 插件运行态快照与面向 `/readyz` 的 notes 文案。
//!
//! 这里是"插件怎么了"的**唯一真源**：能力矩阵行、启动日志、`/readyz` 的 notes
//! 与测试断言全部读同一个结构，避免出现两套口径。

use super::PLUGIN_DIR_ENV;
use super::invoker::{PluginLoadFailureInfo, PluginLoadedInfo};

/// 插件运行时运行态快照（`/readyz` 能力矩阵行、启动日志与测试共用同一个真源）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PluginRuntimeStatus {
    /// 是否装载了插件运行时（`false` = "关闭插件"或"未配置且默认目录不存在"）。
    pub configured: bool,
    /// 插件目录。
    pub dir: Option<String>,
    /// 目录是否真的存在（如实呈现"配了但不存在的目录"）。
    pub dir_exists: bool,
    /// 单次调用超时（毫秒；`0` = 不启用超时）。
    pub timeout_ms: u64,
    /// 已装载插件。
    pub loaded: Vec<PluginLoadedInfo>,
    /// 装载失败插件。
    pub load_failures: Vec<PluginLoadFailureInfo>,
    /// **真实调用**次数（不含"插件名不存在"这种调用前拒绝）。
    pub calls: u64,
    /// 成功次数。
    pub ok: u64,
    /// 失败总数（下面五类之和）。
    pub failures: u64,
    /// 未装载运行时导致的失败次数。
    pub unavailable: u64,
    /// 插件名找不到的次数（调用前拒绝）。
    pub unknown_plugin: u64,
    /// 插件业务失败的次数。
    pub call_errors: u64,
    /// 插件返回载荷不可用的次数。
    pub bad_output: u64,
    /// 超时次数。
    pub timeouts: u64,
    /// 最近失败诊断（`derived_errors` 风格，最多 32 条）。
    pub recent_diagnostics: Vec<String>,
}

impl PluginRuntimeStatus {
    /// 一行摘要（能力矩阵行的 `note` 与启动日志直接用）。
    #[must_use]
    pub fn describe(&self) -> String {
        let timeout = if self.timeout_ms == 0 {
            "超时保护未启用（0 = 同线程直调，插件卡死会拖住解析线程）".to_string()
        } else {
            format!("超时 {}ms（超时后放弃结果，插件线程仍在跑）", self.timeout_ms)
        };
        if !self.configured {
            return format!(
                "插件运行时未装载（未配置 {PLUGIN_DIR_ENV} 且默认 `plugins/` 目录不存在）：\
                 engine: plugin 模板走降级（如实报错/未命中，原始日志照常落库）"
            );
        }
        let dir = self.dir.clone().unwrap_or_else(|| "<未指定>".to_string());
        if !self.dir_exists {
            return format!("插件目录 {dir} 不存在：无插件可用（进程照常启动）");
        }
        let loaded: Vec<String> =
            self.loaded.iter().map(|p| format!("{}({}, {})", p.name, p.version, p.kind)).collect();
        let base = if loaded.is_empty() {
            format!("插件目录 {dir} 已装载 0 个插件（无插件可用）")
        } else {
            format!("已装载 {} 个插件：{}", loaded.len(), loaded.join("、"))
        };
        let mut text = format!("{base}；装载失败 {} 个；{timeout}", self.load_failures.len());
        if self.failures > 0 {
            text.push_str(&format!(
                "；解析调用 {} 次（成功 {} / 失败 {}：unavailable={}, unknown_plugin={}, call_error={}, \
                 bad_output={}, timeout={}）",
                self.calls,
                self.ok,
                self.failures,
                self.unavailable,
                self.unknown_plugin,
                self.call_errors,
                self.bad_output,
                self.timeouts
            ));
        }
        text
    }

    /// 面向 `/readyz` notes 的条目（**启动期快照**：装载结果 + 当时的诊断）。
    ///
    /// 说明：`/readyz` 的 notes 由装配点在启动时抓一份（`ListenerState::default()`），
    /// 因此运行期新增的调用失败**不会**追加进去；要读实时计数请用
    /// [`plugin_runtime_status`](super::plugin_runtime_status)（库 API）或进程日志。
    #[must_use]
    pub fn notes(&self) -> Vec<String> {
        let mut notes = vec![format!("Rust 动态库插件：{}", self.describe())];
        for failure in &self.load_failures {
            notes.push(format!("Rust 动态库插件装载失败：{}（{}）", failure.path, failure.reason));
        }
        for diagnostic in &self.recent_diagnostics {
            notes.push(format!("Rust 动态库插件诊断：{diagnostic}"));
        }
        notes
    }
}
