//! 凭据资产模型（§4.2 凭证泄露 + §4.4 密钥管理）。
//!
//! **安全约定**：明文凭据永不进入领域模型。落库形态是
//! `ciphertext + nonce + key_id`（AES-256-GCM 或 KMS 封装），
//! 模型层只持有 [`SecretMaterial`] 引用；API 出参一律为 [`crate::redact::mask_secret`] 结果。

use serde::{Deserialize, Serialize};

use crate::ids::{Id, TenantId, TenantScoped};
use crate::time::Timestamp;

/// 凭据类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialKind {
    /// 大模型厂商 API Key。
    LlmApiKey,
    /// 阿里云 AK/SK 对。
    CloudAkSk,
    /// AWS AK/SK 对。
    AwsAkSk,
    /// STS 临时凭据。
    StsToken,
    /// JWT / OAuth Access Token。
    BearerToken,
    /// 刷新令牌。
    RefreshToken,
    /// 数据库口令。
    DbPassword,
    /// SSH 私钥。
    SshPrivateKey,
    /// TLS 证书私钥。
    TlsPrivateKey,
    /// MCP 明文凭据（环境变量中的 token）。
    McpPlaintext,
    /// Webhook 密钥。
    WebhookSecret,
    /// 平台自身主密钥（KMS 封装）。
    MasterKey,
    /// 通用口令。
    GenericPassword,
}

impl CredentialKind {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::LlmApiKey => "llm-api-key",
            Self::CloudAkSk => "cloud-aksk",
            Self::AwsAkSk => "aws-aksk",
            Self::StsToken => "sts-token",
            Self::BearerToken => "bearer-token",
            Self::RefreshToken => "refresh-token",
            Self::DbPassword => "db-password",
            Self::SshPrivateKey => "ssh-private-key",
            Self::TlsPrivateKey => "tls-private-key",
            Self::McpPlaintext => "mcp-plaintext",
            Self::WebhookSecret => "webhook-secret",
            Self::MasterKey => "master-key",
            Self::GenericPassword => "generic-password",
        }
    }

    /// 全部类型。
    #[must_use]
    pub const fn all() -> [Self; 13] {
        [
            Self::LlmApiKey,
            Self::CloudAkSk,
            Self::AwsAkSk,
            Self::StsToken,
            Self::BearerToken,
            Self::RefreshToken,
            Self::DbPassword,
            Self::SshPrivateKey,
            Self::TlsPrivateKey,
            Self::McpPlaintext,
            Self::WebhookSecret,
            Self::MasterKey,
            Self::GenericPassword,
        ]
    }

    /// 泄露后的影响等级（用于风险定级）。
    #[must_use]
    pub const fn impact(&self) -> crate::enums::Severity {
        use crate::enums::Severity;
        match self {
            Self::CloudAkSk | Self::AwsAkSk | Self::SshPrivateKey | Self::MasterKey => Severity::Critical,
            Self::LlmApiKey | Self::StsToken | Self::TlsPrivateKey | Self::DbPassword => Severity::High,
            Self::BearerToken | Self::RefreshToken | Self::McpPlaintext => Severity::Medium,
            Self::WebhookSecret | Self::GenericPassword => Severity::Medium,
        }
    }
}

/// 密钥封装后端。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyBackend {
    /// 本地文件主密钥 + AES-256-GCM（默认，离线可用）。
    LocalFile,
    /// 阿里云 KMS。
    AliyunKms,
    /// AWS KMS。
    AwsKms,
    /// HashiCorp Vault。
    Vault,
    /// 仅 Mock（单元测试用，不做真实加密）。
    Mock,
}

impl KeyBackend {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::LocalFile => "local-file",
            Self::AliyunKms => "aliyun-kms",
            Self::AwsKms => "aws-kms",
            Self::Vault => "vault",
            Self::Mock => "mock",
        }
    }
}

/// 加密后的凭据材料（落库形态）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMaterial {
    /// 密钥后端。
    pub backend: KeyBackend,
    /// 密钥标识（KMS key id / 本地主密钥版本）。
    pub key_id: String,
    /// 密文（base64）。
    pub ciphertext_b64: String,
    /// 随机数/IV（base64，AES-GCM 12 字节）。
    pub nonce_b64: String,
    /// 认证标签（base64；与密文拼接存储的后端可为空）。
    pub tag_b64: Option<String>,
    /// 明文长度（用于脱敏展示与完整性提示，不泄露内容）。
    pub plaintext_len: usize,
    /// 加密时间。
    pub encrypted_at: Timestamp,
    /// 关联的附加认证数据（如 `tenant:credential_id`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aad: Option<String>,
}

/// 凭据记录。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRecord {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 名称。
    pub name: String,
    /// 类型。
    pub kind: CredentialKind,
    /// 用途说明。
    #[serde(default)]
    pub purpose: String,
    /// 归属人。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// 归属部门。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub department: Option<String>,
    /// 密文材料。
    pub material: SecretMaterial,
    /// 掩码展示值（如 `sk-abc***xyz`），可安全出现在 UI/日志。
    pub masked: String,
    /// 指纹（SHA-256 hex，用于"同一密钥出现在多处"的关联检测，不可逆）。
    pub fingerprint: String,
    /// 关联的资产（哪个 Agent/MCP/端点使用它）。
    #[serde(default)]
    pub used_by_assets: Vec<Id>,
    /// 轮换周期（天，0 = 不轮换）。
    pub rotation_days: u32,
    /// 上次轮换时间。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_rotated_at: Option<Timestamp>,
    /// 下次轮换时间。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_rotation_at: Option<Timestamp>,
    /// 过期时间（STS/临时凭据）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Timestamp>,
    /// 是否已吊销。
    pub revoked: bool,
    /// 吊销时间。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<Timestamp>,
    /// 是否由平台生成（非导入）。
    pub platform_generated: bool,
    /// 创建时间。
    pub created_at: Timestamp,
    /// 更新时间。
    pub updated_at: Timestamp,
}

impl TenantScoped for CredentialRecord {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

impl CredentialRecord {
    /// 是否到了轮换时间。
    #[must_use]
    pub fn needs_rotation(&self, now: Timestamp) -> bool {
        if self.revoked || self.rotation_days == 0 {
            return false;
        }
        self.next_rotation_at.is_some_and(|t| t.as_datetime() <= now.as_datetime())
    }

    /// 是否已过期。
    #[must_use]
    pub fn is_expired(&self, now: Timestamp) -> bool {
        self.expires_at.is_some_and(|t| t.as_datetime() <= now.as_datetime())
    }

    /// 按轮换周期计算下次轮换时间。
    #[must_use]
    pub fn compute_next_rotation(from: Timestamp, rotation_days: u32) -> Option<Timestamp> {
        if rotation_days == 0 {
            return None;
        }
        Some(from.offset_secs(i64::from(rotation_days) * 86_400))
    }
}

/// 凭据泄露发现的上下文（在哪儿发现的）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialLeakContext {
    /// Prompt 文本中。
    Prompt,
    /// 日志中。
    Log,
    /// 工具调用参数中。
    ToolArguments,
    /// 知识库文档中。
    KnowledgeBase,
    /// Git 仓库中。
    GitRepo,
    /// MCP 配置中。
    McpConfig,
    /// 环境变量中。
    Environment,
    /// 模型输出中（敏感信息回显）。
    ModelOutput,
    /// 代码中。
    SourceCode,
}

impl CredentialLeakContext {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Prompt => "prompt",
            Self::Log => "log",
            Self::ToolArguments => "tool-arguments",
            Self::KnowledgeBase => "knowledge-base",
            Self::GitRepo => "git-repo",
            Self::McpConfig => "mcp-config",
            Self::Environment => "environment",
            Self::ModelOutput => "model-output",
            Self::SourceCode => "source-code",
        }
    }
}

/// 凭据泄露发现记录。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialLeak {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 凭据类型。
    pub kind: CredentialKind,
    /// 发现位置上下文。
    pub context: CredentialLeakContext,
    /// 来源引用（文件路径/日志事件 id/资产 id）。
    pub source_ref: String,
    /// 掩码片段。
    pub masked: String,
    /// 指纹（与 [`CredentialRecord::fingerprint`] 同算法，用于关联"是否为平台已知凭据"）。
    pub fingerprint: String,
    /// 置信度（0.0-1.0）。
    pub confidence: f32,
    /// 影响等级。
    pub severity: crate::enums::Severity,
    /// 是否属平台已纳管凭据（是 → 需轮换；否 → 可能是影子凭据）。
    pub known_credential: bool,
    /// 发现时间。
    pub detected_at: Timestamp,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(rotation_days: u32, next: Option<Timestamp>) -> CredentialRecord {
        let now = Timestamp::now();
        CredentialRecord {
            id: Id::new(),
            tenant_id: TenantId::default_tenant(),
            name: "openai-prod".into(),
            kind: CredentialKind::LlmApiKey,
            purpose: "生产分析".into(),
            owner: None,
            department: None,
            material: SecretMaterial {
                backend: KeyBackend::LocalFile,
                key_id: "v1".into(),
                ciphertext_b64: "AAAA".into(),
                nonce_b64: "BBBB".into(),
                tag_b64: None,
                plaintext_len: 51,
                encrypted_at: now,
                aad: None,
            },
            masked: "sk-abc***xyz".into(),
            fingerprint: "deadbeef".into(),
            used_by_assets: vec![],
            rotation_days,
            last_rotated_at: None,
            next_rotation_at: next,
            expires_at: None,
            revoked: false,
            revoked_at: None,
            platform_generated: false,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn rotation_due_detection() {
        let now = Timestamp::now();
        let due = record(90, Some(now.offset_secs(-1)));
        assert!(due.needs_rotation(now));
        let future = record(90, Some(now.offset_secs(86_400)));
        assert!(!future.needs_rotation(now));
        let disabled = record(0, None);
        assert!(!disabled.needs_rotation(now));
    }

    #[test]
    fn revoked_credential_never_needs_rotation() {
        let now = Timestamp::now();
        let mut r = record(30, Some(now.offset_secs(-10)));
        r.revoked = true;
        assert!(!r.needs_rotation(now));
    }

    #[test]
    fn expiry_detection() {
        let now = Timestamp::now();
        let mut r = record(0, None);
        assert!(!r.is_expired(now));
        r.expires_at = Some(now.offset_secs(-5));
        assert!(r.is_expired(now));
    }

    #[test]
    fn next_rotation_computation() {
        let from = Timestamp::now();
        let next = CredentialRecord::compute_next_rotation(from, 30);
        assert_eq!(next.map(|t| t.unix_secs() - from.unix_secs()), Some(30 * 86_400));
        assert!(CredentialRecord::compute_next_rotation(from, 0).is_none());
    }

    #[test]
    fn impact_levels_are_sane() {
        assert_eq!(CredentialKind::CloudAkSk.impact(), crate::enums::Severity::Critical);
        assert_eq!(CredentialKind::LlmApiKey.impact(), crate::enums::Severity::High);
        assert_eq!(CredentialKind::McpPlaintext.impact(), crate::enums::Severity::Medium);
        assert_eq!(CredentialKind::all().len(), 13);
    }

    #[test]
    fn leak_context_str() {
        assert_eq!(CredentialLeakContext::ToolArguments.as_str(), "tool-arguments");
        assert_eq!(CredentialLeakContext::ModelOutput.as_str(), "model-output");
    }
}
