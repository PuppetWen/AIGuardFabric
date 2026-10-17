//! 插件调用接口与真实调用器：失败分类、[`PluginInvoker`] trait、带超时的调用。
//!
//! 这一层是"**怎么调插件**"，与"什么时候调、调完怎么记账"（[`super::runtime`]）分开：
//! 超时包装在运行时里，因此**假插件与真插件走同一条**超时/记账路径——测试证的是真接线。

use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc::RecvTimeoutError;
use std::time::Duration;

use super::PLUGIN_DIR_ENV;

/// 已装载插件的纯数据视图（可直接进 JSON 响应）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PluginLoadedInfo {
    /// 插件名（描述符里的 `name`）。
    pub name: String,
    /// 插件版本。
    pub version: String,
    /// 插件类型（`normalizer` / `notifier`）。
    pub kind: String,
    /// 动态库文件路径。
    pub path: String,
}

/// 装载失败的插件（**不阻止宿主启动**，只如实登记）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PluginLoadFailureInfo {
    /// 被尝试装载的文件。
    pub path: String,
    /// 失败原因（含 ABI 门禁 / 缺符号 / 非法描述符 / 非法动态库分类）。
    pub reason: String,
}

/// 插件调用失败的分类（每一类都单独计数，绝不合并成"失败了"）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginCallError {
    /// 未装载任何插件运行时（未配置目录且默认目录不存在 ⇔ "关闭插件"）。
    Unavailable {
        /// 期望的插件目录（未配置时为 `None`）。
        dir: Option<String>,
    },
    /// 插件名不在已装载集合里。
    UnknownPlugin {
        /// 请求的插件名。
        plugin: String,
        /// 已装载的插件名（错误文本里如实列出）。
        loaded: Vec<String>,
    },
    /// 调用超时（**宿主放弃结果，插件线程仍在跑**）。
    Timeout {
        /// 插件名。
        plugin: String,
        /// 配置的超时上限（毫秒）。
        limit_ms: u64,
    },
    /// 插件返回业务失败（原因来自插件自己的 `last_error`）。
    Call {
        /// 插件名。
        plugin: String,
        /// 失败原因。
        reason: String,
    },
    /// 插件返回的载荷不可用（非法 JSON / 顶层非对象 / 空对象）。
    BadOutput {
        /// 插件名。
        plugin: String,
        /// 具体原因。
        reason: String,
    },
}

impl PluginCallError {
    /// 失败分类名（计数键与诊断前缀）。
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Unavailable { .. } => "unavailable",
            Self::UnknownPlugin { .. } => "unknown_plugin",
            Self::Timeout { .. } => "timeout",
            Self::Call { .. } => "call_error",
            Self::BadOutput { .. } => "bad_output",
        }
    }

    /// 涉及的插件名（`Unavailable` 没有具体插件）。
    #[must_use]
    pub fn plugin(&self) -> Option<&str> {
        match self {
            Self::Unavailable { .. } => None,
            Self::UnknownPlugin { plugin, .. }
            | Self::Timeout { plugin, .. }
            | Self::Call { plugin, .. }
            | Self::BadOutput { plugin, .. } => Some(plugin),
        }
    }
}

impl std::fmt::Display for PluginCallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable { dir } => write!(
                f,
                "插件引擎不可用：未装载插件运行时（{}={}）⇒ 该模板未命中，原始日志照常落库",
                PLUGIN_DIR_ENV,
                dir.as_deref().unwrap_or("未配置")
            ),
            Self::UnknownPlugin { plugin, loaded } => {
                let names = if loaded.is_empty() { "无".to_string() } else { loaded.join(", ") };
                write!(f, "插件 `{plugin}` 未装载（已装载：{names}）")
            }
            Self::Timeout { plugin, limit_ms } => write!(
                f,
                "插件 `{plugin}` 调用超时（>{limit_ms}ms）：已放弃本次结果并计失败；\
                 同进程调用无法中断，被放弃的插件线程仍在跑（如实局限）"
            ),
            Self::Call { plugin, reason } => write!(f, "插件 `{plugin}` 调用失败：{reason}"),
            Self::BadOutput { plugin, reason } => write!(f, "插件 `{plugin}` 返回的载荷不可用：{reason}"),
        }
    }
}

impl std::error::Error for PluginCallError {}

/// 原始调用接口（**不含超时**）：真实实现是 [`DynamicPluginInvoker`]，测试用假插件。
///
/// 超时、计数、诊断都在 [`PluginRuntime`](super::PluginRuntime)（包装层）里做，因此假插件
/// 与真插件走的是**同一条**超时/记账路径——测试证的是真接线，不是"测了个替身"。
pub trait PluginInvoker: Send + Sync + std::fmt::Debug {
    /// 调用插件的 `normalize`：入参是宿主准备好的载荷文本，出参是 AGF-ECS JSON。
    fn invoke(&self, plugin: &str, payload: &str) -> Result<String, PluginCallError>;
    /// 已装载插件清单。
    fn loaded(&self) -> &[PluginLoadedInfo];
    /// 装载失败清单。
    fn failures(&self) -> &[PluginLoadFailureInfo];
}

/// 真实插件调用器：包住 `agf_plugin::PluginRegistry`（ABI 门禁在它内部完成）。
#[derive(Debug)]
pub struct DynamicPluginInvoker {
    registry: agf_plugin::PluginRegistry,
    loaded: Vec<PluginLoadedInfo>,
    failures: Vec<PluginLoadFailureInfo>,
}

impl DynamicPluginInvoker {
    /// 用给定的插件注册表构造（注册表里装了什么，这里就报什么）。
    #[must_use]
    pub fn new(registry: agf_plugin::PluginRegistry) -> Self {
        let loaded = registry
            .plugins()
            .iter()
            .map(|plugin| PluginLoadedInfo {
                name: plugin.name().to_string(),
                version: plugin.version().to_string(),
                kind: plugin.kind().as_str().to_string(),
                path: plugin.path().display().to_string(),
            })
            .collect();
        let failures = registry
            .failures()
            .iter()
            .map(|failure| PluginLoadFailureInfo {
                path: failure.path.display().to_string(),
                reason: failure.reason.clone(),
            })
            .collect();
        Self { registry, loaded, failures }
    }

    /// 装载目录下的全部插件（缺目录 = 空注册表，不是错误）。
    ///
    /// # Errors
    /// 目录存在但不是目录 / 目录不可读（单个插件装载失败**不**返回 Err，登记在 `failures` 里）。
    pub fn load_dir(dir: &Path) -> Result<Self, String> {
        let mut registry = agf_plugin::PluginRegistry::new();
        registry.load_dir(dir).map_err(|e| e.to_string())?;
        Ok(Self::new(registry))
    }
}

impl PluginInvoker for DynamicPluginInvoker {
    fn invoke(&self, plugin: &str, payload: &str) -> Result<String, PluginCallError> {
        let Some(loaded) = self.registry.get(plugin) else {
            return Err(PluginCallError::UnknownPlugin {
                plugin: plugin.to_string(),
                loaded: self.registry.plugins().iter().map(|p| p.name().to_string()).collect(),
            });
        };
        loaded
            .normalize(payload)
            .map_err(|e| PluginCallError::Call { plugin: plugin.to_string(), reason: e.to_string() })
    }

    fn loaded(&self) -> &[PluginLoadedInfo] {
        &self.loaded
    }

    fn failures(&self) -> &[PluginLoadFailureInfo] {
        &self.failures
    }
}

/// 空调用器（插件目录不可读时的如实降级：一个插件也没有）。
#[derive(Debug)]
pub struct EmptyInvoker;

impl PluginInvoker for EmptyInvoker {
    fn invoke(&self, plugin: &str, _payload: &str) -> Result<String, PluginCallError> {
        Err(PluginCallError::UnknownPlugin { plugin: plugin.to_string(), loaded: Vec::new() })
    }

    fn loaded(&self) -> &[PluginLoadedInfo] {
        &[]
    }

    fn failures(&self) -> &[PluginLoadFailureInfo] {
        &[]
    }
}

/// 带超时地调用一次插件（`timeout == 0` ⇒ 同线程直调，不启用超时）。
///
/// **局限（如实）**：超时只放弃结果，**不能中断**已经在跑的插件线程。要真正可中断，
/// 必须换进程边界（子进程 + IPC/沙箱），那不是本 crate 的形态。
pub(super) fn call_with_timeout(
    invoker: &Arc<dyn PluginInvoker>,
    plugin: &str,
    payload: &str,
    timeout: Duration,
) -> Result<String, PluginCallError> {
    if timeout.is_zero() {
        return invoker.invoke(plugin, payload);
    }
    let (sender, receiver) = std::sync::mpsc::channel();
    let worker = Arc::clone(invoker);
    let name = plugin.to_string();
    let own_payload = payload.to_string();
    let spawned = std::thread::Builder::new().name("agf-plugin-call".to_string()).spawn(move || {
        let _ = sender.send(worker.invoke(&name, &own_payload));
    });
    if let Err(error) = spawned {
        return Err(PluginCallError::Call {
            plugin: plugin.to_string(),
            reason: format!("无法创建插件调用线程：{error}"),
        });
    }
    match receiver.recv_timeout(timeout) {
        Ok(result) => result,
        Err(RecvTimeoutError::Timeout) => Err(PluginCallError::Timeout {
            plugin: plugin.to_string(),
            limit_ms: u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
        }),
        Err(RecvTimeoutError::Disconnected) => Err(PluginCallError::Call {
            plugin: plugin.to_string(),
            reason: "插件调用线程未返回结果（插件内部 panic 或线程被终止）".to_string(),
        }),
    }
}
