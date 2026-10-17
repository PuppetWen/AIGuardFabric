//! 接收器状态与装配登记：`ReceiverStatus` 四态、进程内装配登记表（`declare_wired`/`wired_state`/`wiring_snapshot`）与状态折算。

use super::*;

/// 接收器实现状态。
///
/// **四态**（不再是三态）：`Ready` / `NotWired` / `NotImplemented` / `Mock`。
///
/// 第四态 [`ReceiverStatus::NotWired`] 的存在理由：旧口径只有三态，"**代码已写但进程
/// 没把它挂上**"无处可放，于是 `describe()` 只能说 `Ready`，而 `/v1/traces` 实际返回 404
/// ——这正是"口径不实"的根因。现在"实现了"与"装配了"分开表达：
///
/// * `Ready` = 已实现 **且** 本进程已把入向路由/监听真正挂上；
/// * `NotWired` = 已实现（模块、解析器、路由构造函数都在），但**本进程没有装配**
///   （路由未 `merge` / 监听未启动）——运维看到的必须是这一态，而不是 `Ready`；
/// * `NotImplemented` = 代码层面就没有（仅配置模型 + Mock 回放）；
/// * `Mock` = 仅 Mock 模式可用。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReceiverStatus {
    /// 已实现，且本进程已装配，可承载真实流量。
    Ready,
    /// **已实现但本进程未装配**（路由未挂 / 监听未起）。
    NotWired,
    /// 未实现（仅配置模型 + Mock 回放）。
    NotImplemented,
    /// 仅在 Mock 模式可用。
    Mock,
}

impl ReceiverStatus {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::NotWired => "not-wired",
            Self::NotImplemented => "not-implemented",
            Self::Mock => "mock",
        }
    }
}

// ---------------------------------------------------------------------------
// 装配登记表（"实现了"与"装配了"的唯一真源）
// ---------------------------------------------------------------------------

/// 模块装配登记：模块名 → 本进程是否已把它的**入向路由/监听**真正挂上。
///
/// **为什么必须是真源而不是注释**：能力矩阵与 `/readyz` 的状态必须来自"装配点自己
/// 报到的结果"，否则又一次变成"文档说 Ready、路由没挂"。装配点（`apps/ingest`）在
/// 完成 `merge`/`bind` 之后调用 [`declare_wired`]；**未登记的模块一律按"未装配"处理**
/// （见 [`effective_status`]）——这保证"忘了挂路由"只会让状态掉到
/// [`ReceiverStatus::NotWired`]，而不会反过来谎报 `Ready`。
static WIRING: std::sync::OnceLock<Mutex<BTreeMap<&'static str, bool>>> = std::sync::OnceLock::new();

fn wiring_table() -> &'static Mutex<BTreeMap<&'static str, bool>> {
    WIRING.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// 登记某模块的装配结果（幂等；重复登记覆盖，便于测试复跑不同状态）。
///
/// `wired = true` 表示"已真正挂上入向入口"（路由已 merge / 监听已 bind）。
pub fn declare_wired(module: &'static str, wired: bool) {
    if let Ok(mut table) = wiring_table().lock() {
        table.insert(module, wired);
    }
}

/// 查询装配登记：`None` = 从未登记（**按未装配处理**）。
#[must_use]
pub fn wired_state(module: &str) -> Option<bool> {
    wiring_table().lock().ok().and_then(|table| table.get(module).copied())
}

/// 装配登记快照（`/readyz` 与 `/stats` 如实输出"哪个模块登记了什么"）。
#[must_use]
pub fn wiring_snapshot() -> BTreeMap<String, bool> {
    wiring_table().lock().map(|table| table.iter().map(|(k, v)| ((*k).to_string(), *v)).collect()).unwrap_or_default()
}

/// 状态由**装配事实**决定的接收器模块名（[`effective_status`] 只为它们折算状态）。
///
/// 其余模块（webhook / syslog / file / http-pull / …）的状态是**代码事实**，与"本进程是否
/// 装配"无关——它们的运行态由 `/readyz` 的 `listeners` 如实给出。这里列出的模块则**必须**
/// 同时满足"代码已实现"与"本进程已装配"，否则一律降级为 [`ReceiverStatus::NotWired`]：
///
/// * `otlp` / `otlp-traces` / `otlp-metrics` —— 三信号路由都由 `otlp::signal_router` 挂载，
///   漏挂任何一个就是"用户请求 404"；
/// * `nats-jetstream` —— 入向订阅由装配点起后台任务，没起就是"收不到数"。
pub const WIRING_TRACKED_MODULES: &[&str] =
    &["otlp", "otlp-traces", "otlp-metrics", "nats-jetstream", "otlp-grpc", "otlp-grpc-traces", "otlp-grpc-metrics"];

/// 纯函数：按**给定的装配事实**折算状态（不读全局表，便于无副作用单测）。
///
/// 语义与 [`effective_status`] 完全一致；`wired = None`（未登记）与 `Some(false)`
/// （登记为未装配）同样降级为 [`ReceiverStatus::NotWired`]。
#[must_use]
pub const fn status_for(declared: ReceiverStatus, wired: Option<bool>) -> ReceiverStatus {
    match declared {
        ReceiverStatus::Ready if !matches!(wired, Some(true)) => ReceiverStatus::NotWired,
        other => other,
    }
}

/// 把"声明已实现"按**装配事实**折算为对外状态。
///
/// * `declared != Ready` ⇒ 原样返回（未实现/Mock 与装配无关）；
/// * `declared == Ready` 且已登记 `wired = true` ⇒ `Ready`；
/// * `declared == Ready` 但未登记或登记为 `false` ⇒ [`ReceiverStatus::NotWired`]。
///
/// 未登记（`None`）按"未装配"处理是**故意的默认**：新增一个接收器时若忘了在装配点
/// 登记，能力矩阵会显示 `not-wired` 而不是 `ready`（宁可少报，不可谎报）。
#[must_use]
pub fn effective_status(declared: ReceiverStatus, module: &str) -> ReceiverStatus {
    status_for(declared, wired_state(module))
}
