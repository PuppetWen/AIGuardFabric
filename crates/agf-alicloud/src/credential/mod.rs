//! 凭据解析（§5.3：优先 RAM Role / STS，禁止长期 AK 明文落盘，支持跨账号 AssumeRole）。
//!
//! ## 设计要点
//!
//! - [`CloudCredential`] 持有**明文**签名材料，其 `Debug` 实现只输出掩码（见 [`Debug`] impl），
//!   避免 `tracing` 的 `?cred` 把密钥打进日志；
//! - [`CredentialResolver`] 以 trait 形式暴露，**测试用 [`StaticResolver`] 永不触网**；
//! - 需要联网的解析器（[`StsResolver`] / [`AssumeRoleResolver`]）在 Mock 模式下直接返回
//!   [`DomainError::DependencyUnavailable`]，绝不发起真实 STS 调用；
//! - 长期 AK 会被登记为一等风险（[`CredentialWarning::for_kind`]），
//!   与控制台"云环境自检"页的红色项对应。
//!
//! ## 与 `agf-storage` 的分工
//!
//! 落库形态是密文（`agf_storage::crypto::FieldCipher`，AES-256-GCM，AAD 绑定租户 + 凭据 id）。
//! 本模块通过 [`SecretLookup`] trait 取明文，因此**不直接依赖数据库**，可完整单元测试。

pub(crate) use std::collections::BTreeMap;

pub(crate) use std::sync::Arc;

pub(crate) use agf_core::cloud::CloudCredentialKind;
pub(crate) use agf_core::cloud::CloudIntegration;

pub(crate) use agf_core::error::DomainError;
pub(crate) use agf_core::error::DomainResult;

pub(crate) use agf_core::ids::Id;

pub(crate) use agf_core::secret::mask_default;

pub(crate) use agf_core::time::Timestamp;

#[cfg(test)]
pub(crate) use crate::test_support::fixture_integration;

#[allow(unused_imports)]
pub use impl_sts_resolver::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 凭据临近过期的告警阈值（15 分钟，与 [`CloudIntegration::sts_expiring_soon`] 一致）。
pub const REFRESH_THRESHOLD_SECS: i64 = 900;

/// 环境变量前缀（[`EnvResolver`] 使用）。
pub const ENV_PREFIX: &str = "AGF_ALIYUN_";

/// 明文签名材料。
///
/// **安全约定**：本结构只在适配器内部短暂存活，不落库、不序列化、
/// `Debug`/日志输出一律掩码。
#[derive(Clone, PartialEq, Eq)]
pub struct CloudCredential {
    /// AccessKeyId（可脱敏展示，本身不敏感）。
    pub access_key_id: String,
    /// AccessKeySecret（敏感）。
    pub access_key_secret: String,
    /// STS 安全令牌（临时凭据才有）。
    pub security_token: Option<String>,
    /// 过期时间（长期 AK 为 `None`）。
    pub expires_at: Option<Timestamp>,
    /// 凭据类型。
    pub kind: CloudCredentialKind,
}

/// 凭据风险告警（与"云环境自检"页的 `PermissionCheck` 同构）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialWarning {
    /// 检查项名（稳定标识，前端 i18n 依赖）。
    pub name: String,
    /// 说明。
    pub note: String,
    /// 是否需要该能力（长期 AK 风险项为 `false`：不阻断，但要登记）。
    pub required: bool,
}

/// 解析结果：凭据 + 风险告警 + 解析耗时信息。
#[derive(Debug, Clone)]
pub struct CredentialOutcome {
    /// 签名材料。
    pub credential: CloudCredential,
    /// 风险告警（可能多条）。
    pub warnings: Vec<CredentialWarning>,
    /// 是否命中长期密钥风险（等价于 `cloud.has_long_lived_risk()`）。
    pub long_lived_risk: bool,
    /// 解析时间。
    pub resolved_at: Timestamp,
}

/// 密文取明文的口子（生产由 `agf-storage` 实现，测试用内存实现）。
pub trait SecretLookup: Send + Sync {
    /// 按凭据 id 取出明文。
    ///
    /// # Errors
    /// 凭据不存在或解密失败时返回错误。
    fn resolve_secret(&self, credential_ref: Id) -> DomainResult<String>;
}

/// 解析上下文：密文读取入口 + 是否 Mock + 时间基准。
#[derive(Clone)]
pub struct CredentialContext {
    /// 密文读取入口。
    pub secrets: Arc<dyn SecretLookup>,
    /// 是否 Mock 模式（Mock 下禁止任何联网解析）。
    pub mock: bool,
    /// 时间基准（测试可注入）。
    pub now: Timestamp,
}

/// 凭据解析器契约。
pub trait CredentialResolver: Send + Sync {
    /// 解析器名（日志与自检页展示）。
    fn name(&self) -> &str;

    /// 解析凭据。
    ///
    /// # Errors
    /// 配置缺失返回 [`DomainError::Config`]；需要联网但当前不可用时返回
    /// [`DomainError::DependencyUnavailable`]。
    fn resolve(&self, integration: &CloudIntegration, ctx: &CredentialContext) -> DomainResult<CredentialOutcome>;
}

/// 内存密文表（测试与本地开发用）。
#[derive(Debug, Default)]
pub struct MapSecretStore {
    values: BTreeMap<Id, String>,
}

/// 静态解析器：凭据直接来自内存（**测试专用**，也是 Mock 模式的凭据来源）。
#[derive(Clone)]
pub struct StaticResolver {
    credential: CloudCredential,
}

/// 环境变量读取口（可注入，测试不触碰进程环境 —— 进程环境变量在并行测试下不可靠）。
pub type EnvGetter = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// 环境变量解析器：`AGF_ALIYUN_ACCESS_KEY_ID` / `AGF_ALIYUN_ACCESS_KEY_SECRET` / `AGF_ALIYUN_SECURITY_TOKEN`。
///
/// 用途：本地开发与容器注入（配合 K8s Secret / ECS 环境变量）。
/// 生产建议改用 [`AssumeRoleResolver`]（跨账号）或实例 RAM Role（免密钥）。
#[derive(Clone)]
pub struct EnvResolver {
    /// 前缀覆盖（默认 [`ENV_PREFIX`]）。
    pub prefix: Option<String>,
    /// 读取口（默认 `std::env::var`）。
    pub getter: EnvGetter,
}

/// STS / AssumeRole 解析器的公共行为：**没有网络就明确说不可用，绝不假装成功**。
#[derive(Debug, Clone)]
pub struct StsResolver {
    /// STS endpoint（缺省用 `sts.aliyuncs.com`）。
    pub endpoint: String,
    /// 是否允许联网（false 时直接返回不可用）。
    pub allow_network: bool,
}

/// 跨账号 AssumeRole 解析器：先用源凭据换取目标账号临时凭据。
pub struct AssumeRoleResolver {
    /// 源凭据解析器（实例 RAM Role / 平台主账号 AK）。
    pub source: Arc<dyn CredentialResolver>,
    /// STS endpoint。
    pub endpoint: String,
    /// 是否允许联网。
    pub allow_network: bool,
}

/// 可刷新凭据：缓存当前凭据并在临近过期时重新解析。
pub struct RefreshableCredential {
    resolver: Arc<dyn CredentialResolver>,
    cached: std::sync::Mutex<Option<CredentialOutcome>>,
}

mod impl_cloud_credential;
mod impl_sts_resolver;
pub mod sts_async;
#[cfg(test)]
mod tests;
pub mod workload;
