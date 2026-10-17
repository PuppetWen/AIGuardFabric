//! 采集器身份：agent id / 租户 / 版本 / 主机画像 / 幂等键。
//!
//! ## 身份来源（优先级）
//!
//! ```text
//! ① 显式注入（`AgentIdentity::with_agent_id` / `with_tenant`，供服务端下发或测试）
//!         ↓ 未提供
//! ② 环境变量 `AGF_AGENT_ID` / `AGF_AGENT_TENANT_ID`（容器/静默安装场景）
//!         ↓ 未提供
//! ③ 本地生成 UUID v7 并落盘 `<data_dir>/agent-id`（首次启动生成，之后复用）
//! ```
//!
//! ## 降级行为
//!
//! | 情况 | 行为 |
//! |---|---|
//! | 主机名/用户不可得 | 用 `unknown-host` / `None` 占位，**不失败**（采集照常进行） |
//! | `AGF_AGENT_TENANT_ID` 非法 | 返回 `DomainError::Validation`（租户是强隔离锚点，不能猜） |
//! | agent id 文件不可写 | 内存内 id 仍可用（返回 `DomainError::Internal` 由调用方决定是否降级） |
//! | 幂等键 | 由 `(agent_id, 载荷种类, 规范化载荷)` 的 SHA-256 派生，**不含时间戳**，同一载荷恒等 |

use std::path::{Path, PathBuf};

use agf_core::error::{DomainError, DomainResult};
use agf_core::ids::TenantId;
use serde::Serialize;

use crate::payload::PayloadKind;

/// 采集器版本（编译期）。
pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// agent id 环境变量名。
pub const ENV_AGENT_ID: &str = "AGF_AGENT_ID";

/// 租户环境变量名。
pub const ENV_AGENT_TENANT_ID: &str = "AGF_AGENT_TENANT_ID";

/// 采集器身份。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AgentIdentity {
    /// 采集器唯一 id（持久化，同一终端重装前保持不变）。
    pub agent_id: String,
    /// 租户（多租户隔离锚点）。
    pub tenant_id: TenantId,
    /// 采集器版本。
    pub agent_version: String,
    /// 主机名。
    pub hostname: String,
    /// 操作系统。
    pub os: String,
    /// 当前用户。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_user: Option<String>,
}

impl AgentIdentity {
    /// 生成新身份（主机名/用户不可得时用占位值，不失败）。
    #[must_use]
    pub fn generate() -> Self {
        Self {
            agent_id: new_agent_id(),
            tenant_id: TenantId::default_tenant(),
            agent_version: AGENT_VERSION.to_string(),
            hostname: collect_hostname(),
            os: collect_os(),
            os_user: collect_os_user(),
        }
    }

    /// 覆盖 agent id（链式）。
    #[must_use]
    pub fn with_agent_id(mut self, agent_id: impl Into<String>) -> Self {
        self.agent_id = agent_id.into();
        self
    }

    /// 覆盖租户（链式）。
    #[must_use]
    pub fn with_tenant(mut self, tenant: TenantId) -> Self {
        self.tenant_id = tenant;
        self
    }

    /// 覆盖主机名（链式，测试用）。
    #[must_use]
    pub fn with_hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = hostname.into();
        self
    }

    /// 从环境读取覆盖项（`AGF_AGENT_ID` / `AGF_AGENT_TENANT_ID`）。
    ///
    /// # Errors
    /// `AGF_AGENT_TENANT_ID` 非法 UUID 时返回 `DomainError::Validation`。
    pub fn apply_env(mut self) -> DomainResult<Self> {
        if let Ok(id) = std::env::var(ENV_AGENT_ID) {
            if !id.trim().is_empty() {
                self.agent_id = id.trim().to_string();
            }
        }
        if let Ok(raw) = std::env::var(ENV_AGENT_TENANT_ID) {
            let trimmed = raw.trim();
            if !trimmed.is_empty() {
                self.tenant_id = TenantId::parse(trimmed)
                    .map_err(|e| DomainError::Validation(format!("{ENV_AGENT_TENANT_ID} 非法: {e}")))?;
            }
        }
        Ok(self)
    }

    /// 从环境变量与本地状态文件装配身份。
    ///
    /// # Errors
    /// 环境变量非法或本地状态文件损坏时返回错误（文件不存在则自动创建）。
    pub fn from_env(data_dir: &Path) -> DomainResult<Self> {
        let mut identity = Self::generate().apply_env()?;
        if std::env::var(ENV_AGENT_ID).is_err() {
            identity.agent_id = load_or_create_agent_id(data_dir)?;
        }
        Ok(identity)
    }

    /// 由载荷派生幂等键（不含时间戳，可安全重放）。
    ///
    /// # Errors
    /// 载荷无法序列化时返回 `DomainError::Parse`。
    pub fn idempotency_key<T: Serialize>(&self, kind: PayloadKind, payload: &T) -> DomainResult<String> {
        let canonical = serde_json::to_string(payload)?;
        Ok(crate::payload::payload_key(&self.agent_id, kind, &canonical))
    }
}

/// 采集主机名（失败时退化占位值）。
#[must_use]
pub fn collect_hostname() -> String {
    hostname::get()
        .ok()
        .map(|h| h.to_string_lossy().trim().to_string())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "unknown-host".to_string())
}

/// 采集操作系统描述（`os/arch/version` 组合，便于排障与规则匹配）。
#[must_use]
pub fn collect_os() -> String {
    format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH)
}

/// 采集当前用户（`USERNAME`（Windows）/`USER`（类 Unix））。
#[must_use]
pub fn collect_os_user() -> Option<String> {
    for key in ["USERNAME", "USER", "LOGNAME"] {
        if let Ok(value) = std::env::var(key) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

/// 生成新的 agent id（UUID v7，时间有序，便于服务端按注册顺序建索引）。
#[must_use]
pub fn new_agent_id() -> String {
    format!("agf-agent-{}", uuid::Uuid::now_v7())
}

/// agent id 状态文件路径。
#[must_use]
pub fn agent_id_path(data_dir: &Path) -> PathBuf {
    data_dir.join("agent-id")
}

/// 读取或创建本地 agent id（写入失败时抛出错误，由调用方决定是否退化到内存 id）。
///
/// # Errors
/// 目录不可创建、文件不可写、既有文件内容非法（空/含换行）时返回错误。
pub fn load_or_create_agent_id(data_dir: &Path) -> DomainResult<String> {
    let path = agent_id_path(data_dir);
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let trimmed = existing.trim();
        if !trimmed.is_empty() && !trimmed.contains(['\n', '\r']) {
            return Ok(trimmed.to_string());
        }
        return Err(DomainError::Parse(format!("agent id 文件内容非法: {}", path.display())));
    }
    let id = new_agent_id();
    std::fs::create_dir_all(data_dir)
        .map_err(|e| DomainError::Internal(format!("创建状态目录失败 {}: {e}", data_dir.display())))?;
    std::fs::write(&path, &id).map_err(|e| DomainError::Internal(format!("写入 agent id 失败: {e}")))?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::PayloadKind;

    #[test]
    fn generated_identity_has_usable_fields() {
        let identity = AgentIdentity::generate();
        assert!(identity.agent_id.starts_with("agf-agent-"));
        assert_eq!(identity.agent_version, AGENT_VERSION);
        assert!(!identity.hostname.is_empty(), "主机名不可得时必须占位而不是空串");
        assert!(identity.os.contains('/'), "os 描述应含 arch: {}", identity.os);
        assert_eq!(identity.tenant_id, TenantId::default_tenant());
    }

    #[test]
    fn chained_overrides_apply() {
        let tenant = TenantId::new();
        let identity = AgentIdentity::generate().with_agent_id("fixed-id").with_tenant(tenant).with_hostname("host-x");
        assert_eq!(identity.agent_id, "fixed-id");
        assert_eq!(identity.tenant_id, tenant);
        assert_eq!(identity.hostname, "host-x");
    }

    #[test]
    fn idempotency_key_is_stable_and_payload_sensitive() {
        let identity = AgentIdentity::generate().with_agent_id("fixed-id");
        let a = identity.idempotency_key(PayloadKind::Snapshot, &serde_json::json!({"x": 1}));
        let b = identity.idempotency_key(PayloadKind::Snapshot, &serde_json::json!({"x": 1}));
        let c = identity.idempotency_key(PayloadKind::Snapshot, &serde_json::json!({"x": 2}));
        let d = identity.idempotency_key(PayloadKind::Heartbeat, &serde_json::json!({"x": 1}));
        assert!(a.is_ok());
        assert_eq!(a.as_ref().ok(), b.as_ref().ok());
        assert_ne!(a.as_ref().ok(), c.as_ref().ok(), "载荷变化必须改变幂等键");
        assert_ne!(a.as_ref().ok(), d.as_ref().ok(), "载荷种类变化必须改变幂等键");
        assert_eq!(a.unwrap_or_default().len(), 32, "SHA-256 前 16 字节 = 32 hex 字符");
    }

    #[test]
    fn os_user_and_hostname_never_panic() {
        let _ = collect_hostname();
        let _ = collect_os_user();
        assert!(collect_os().contains(std::env::consts::OS));
    }

    #[test]
    fn agent_id_roundtrip_on_disk() {
        let dir = tempfile::tempdir().expect("临时目录");
        let nested = dir.path().join("state");
        let first = load_or_create_agent_id(&nested).expect("首次应创建");
        let second = load_or_create_agent_id(&nested).expect("再次应复用");
        assert_eq!(first, second);
        assert!(first.starts_with("agf-agent-"));
        assert!(agent_id_path(&nested).exists());
    }

    #[test]
    fn corrupted_agent_id_file_is_reported() {
        let dir = tempfile::tempdir().expect("临时目录");
        let path = agent_id_path(dir.path());
        std::fs::write(&path, "bad\nid\n").expect("写入");
        let result = load_or_create_agent_id(dir.path());
        assert!(matches!(result, Err(DomainError::Parse(_))), "损坏文件必须报错而不是静默覆盖");
    }

    #[test]
    fn identity_serde_roundtrip() {
        let identity = AgentIdentity::generate().with_agent_id("id-1").with_hostname("h1");
        let json = serde_json::to_string(&identity).unwrap_or_default();
        let back: Option<AgentIdentity> = serde_json::from_str(&json).ok();
        assert_eq!(back.as_ref(), Some(&identity));
    }
}
