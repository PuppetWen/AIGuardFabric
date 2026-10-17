//! 有界进程策略协议；原始路径和参数只用于请求期间求值，不进入审计。
use crate::{
    enums::PolicyAction,
    error::{DomainError, DomainResult},
    ids::Id,
    secret::content_hash,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

/// 观察事件不能授权进程启动。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessMode {
    /// 已发生的事实，始终标注未执行阻断。
    Observe,
    /// 显式受管启动，在创建子进程之前判定。
    Launch,
    /// 探针丢失通知，不虚构进程事实。
    Loss,
}
/// 明确事件来源，不虚构参数或 Windows 完整映像路径。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessSource {
    /// Linux sched_process_exec tracepoint。
    LinuxSchedExec,
    /// Windows 内置 WMI 进程启动事件。
    WindowsWmiStart,
    /// 本产品显式受管启动器。
    ManagedLauncher,
}
/// Agent 身份必须匹配认证 Key 的绑定，不接受请求租户字段。
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessRequest {
    /// 原始随机标识，响应不得替换。
    pub request_id: Id,
    /// 必须是认证 Key 绑定的 Agent。
    pub agent_id: Id,
    /// 区分观察、启动和丢失通知。
    pub mode: ProcessMode,
    /// 真实事件来源。
    pub source: ProcessSource,
    /// 原始文件名字节，以 base64 保留 Linux 非 UTF-8 名称。
    pub executable_b64: String,
    /// 精确参数数组，只用于显式受管启动。
    pub arguments: Vec<String>,
    /// 已打开可执行文件的摘要，只用于受管启动。
    pub executable_sha256: Option<String>,
    /// 内核或提供器给出的 PID，不以该 PID 回查可能已经复用的进程信息。
    pub pid: Option<u32>,
    /// 内核提供的 Linux UID；WMI 无该字段时明确为空。
    pub uid: Option<u32>,
    /// 内核单调时间戳；提供器未给出时明确为空。
    pub monotonic_ns: Option<u64>,
    /// 文件名截断必须显式标注。
    pub truncated: bool,
    /// 明确丢失数量，只用于丢失通知。
    pub lost: u64,
}
impl std::fmt::Debug for ProcessRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProcessRequest")
            .field("request_id", &self.request_id)
            .field("mode", &self.mode)
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}
impl ProcessRequest {
    /// 在求值或记录前拒绝歧义和超出预算的输入。
    pub fn validate(&self) -> DomainResult<Vec<u8>> {
        let bad = || DomainError::Validation("Invalid bounded process event".into());
        if self.request_id.is_nil()
            || self.agent_id.is_nil()
            || self.executable_b64.len() > 5464
            || self.arguments.len() > 64
            || self.arguments.iter().any(|a| a.len() > 4096 || a.contains('\0'))
            || self.arguments.iter().map(String::len).sum::<usize>() > 16384
        {
            return Err(bad());
        }
        let path = STANDARD.decode(&self.executable_b64).map_err(|_| bad())?;
        if path.len() > 4096 || path.contains(&0) {
            return Err(bad());
        }
        match self.mode {
            ProcessMode::Launch => {
                if self.source != ProcessSource::ManagedLauncher
                    || path.is_empty()
                    || std::str::from_utf8(&path).is_err()
                    || self.pid.is_some()
                    || self.uid.is_some()
                    || self.monotonic_ns.is_some()
                    || self.truncated
                    || self.lost != 0
                    || self
                        .executable_sha256
                        .as_ref()
                        .is_none_or(|h| h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()))
                {
                    return Err(bad());
                }
            }
            ProcessMode::Observe => {
                if self.source == ProcessSource::ManagedLauncher
                    || path.is_empty()
                    || self.pid.is_none_or(|p| p == 0)
                    || !self.arguments.is_empty()
                    || self.executable_sha256.is_some()
                    || self.lost != 0
                {
                    return Err(bad());
                }
            }
            ProcessMode::Loss => {
                if self.source == ProcessSource::ManagedLauncher
                    || !path.is_empty()
                    || !self.arguments.is_empty()
                    || self.executable_sha256.is_some()
                    || self.pid.is_some()
                    || self.uid.is_some()
                    || self.monotonic_ns.is_some()
                    || self.truncated
                    || self.lost == 0
                {
                    return Err(bad());
                }
            }
        }
        Ok(path)
    }
    /// 具有独立域前缀的固定协议摘要，绑定随机标识、参数数组、身份和文件字节。
    pub fn digest(&self) -> DomainResult<String> {
        self.validate()?;
        Ok(content_hash(&format!("AIGuardFabric/process-admission/v1\n{}", serde_json::to_string(self)?)))
    }
}
/// TLS 认证的响应，不返回原始命令或可能包含敏感数据的策略原因。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessReceipt {
    /// 回显原始随机标识。
    pub request_id: Id,
    /// 回显认证 Agent 身份。
    pub agent_id: Id,
    /// 原始完整请求的摘要。
    pub request_sha256: String,
    /// 区分观察和受管启动。
    pub mode: ProcessMode,
    /// 只允许具有已实现动作的受管启动。
    pub launch_allowed: bool,
    /// 求值动作；尚未实现的动作默认拒绝。
    pub action: PolicyAction,
    /// 策略明确配置为模拟模式。
    pub dry_run: bool,
    /// 判定与脱敏审计在返回该响应之前已提交。
    pub audit_committed: bool,
    /// 已保存的判定与审计关联标识。
    pub audit_id: Id,
    /// 短时准入期限，Unix 毫秒。
    pub expires_at_ms: i64,
    /// 服务端不宣称已经执行或阻断系统进程。
    pub enforced: bool,
}
/// 只有受管启动器已实现的动作才能授权创建子进程。
#[must_use]
pub const fn launch_action_supported(action: PolicyAction, dry_run: bool, redact: bool) -> bool {
    dry_run || (!redact && matches!(action, PolicyAction::Allow | PolicyAction::Audit))
}
