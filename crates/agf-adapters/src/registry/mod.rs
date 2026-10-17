//! 适配器注册表：按厂商注册/查找、能力路由、启停与配置热替换。
//!
//! ## 语义（对齐 `docs/adapter-spec.md` §4.2）
//!
//! | 操作 | 语义 |
//! |---|---|
//! | [`AdapterRegistry::register`] | 按注册名登记；重复登记返回 `Conflict`（**不静默覆盖**） |
//! | [`AdapterRegistry::apply_config`] | 配置热替换：先 `prepare`（纯校验）再 `commit`（不可失败）——**失败保持旧配置** |
//! | [`AdapterRegistry::route`] | 事件类型前缀 + 最低等级 + 适配器自身订阅规则（如 EDR 只订隔离指令）三重过滤 |
//! | [`AdapterRegistry::broadcast`] | 逐适配器下发，**单个失败不影响其它**（降级不阻塞主流程） |
//! | [`AdapterRegistry::close_all`] | 幂等关闭全部适配器（可重复调用） |
//! | [`AdapterRegistry::init_all`] | 批量应用配置；未登记的适配器配置计入 `skipped`（不报错） |
//!
//! ## 降级行为
//!
//! | 情况 | 行为 |
//! |---|---|
//! | 未提供配置 | 适配器保持 `Unconfigured`（不发送、不报错，`init_all` 计入 `skipped`） |
//! | `mock_mode = true`（`AGF_MOCK_MODE=1` / [`AdapterRegistry::mock_only`]） | 全部适配器返回确定性 Mock 回执，**零网络** |
//! | 单个适配器下发失败 | 该适配器错误随 `BroadcastOutcome` 返回，其余适配器照常下发 |
//! | 关闭后下发 | 返回 `PreconditionFailed`（不 panic） |

pub(crate) use std::collections::BTreeMap;

pub(crate) use std::sync::Arc;

pub(crate) use agf_core::adapter::AdapterConfig;
pub(crate) use agf_core::adapter::AdapterDescriptor;

pub(crate) use agf_core::enums::Severity;

pub(crate) use agf_core::error::DomainError;
pub(crate) use agf_core::error::DomainResult;

pub(crate) use agf_core::ids::TenantId;

pub(crate) use tokio::sync::Mutex;

pub(crate) use crate::contract::AdapterMessage;
pub(crate) use crate::contract::AdapterMetadata;
pub(crate) use crate::contract::AdapterReceipt;
pub(crate) use crate::contract::VendorAdapter;

pub(crate) use crate::health::AdapterHealthRecord;

pub(crate) use crate::settings::EnvSecrets;
pub(crate) use crate::settings::SecretLookup;

pub(crate) use crate::vendor::VendorSpec;

#[cfg(test)]
pub(crate) use crate::health::HealthStatus;

#[cfg(test)]
pub(crate) use crate::settings::AdapterMode;

#[cfg(test)]
pub(crate) use crate::test_support::config_for;
#[cfg(test)]
pub(crate) use crate::test_support::secrets;

#[cfg(test)]
pub(crate) use serde_json::json;

#[cfg(test)]
pub(crate) use wiremock::matchers::any;
#[cfg(test)]
pub(crate) use wiremock::matchers::path;

#[cfg(test)]
pub(crate) use wiremock::Mock;
#[cfg(test)]
pub(crate) use wiremock::MockServer;
#[cfg(test)]
pub(crate) use wiremock::ResponseTemplate;

#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 适配器句柄（注册表内部并发安全包装）。
pub type AdapterHandle = Arc<Mutex<Box<dyn VendorAdapter>>>;

/// 订阅规则（控制台可配置的事件路由）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SubscriptionRule {
    /// 适配器注册名。
    pub adapter: String,
    /// 事件类型前缀（`*` 表示全订阅）。
    pub event_prefixes: Vec<String>,
    /// 最低等级（`None` 表示不限）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_severity: Option<Severity>,
}

/// 单次直播下发的产出（逐适配器，失败不掩盖成功）。
#[derive(Debug)]
pub struct BroadcastOutcome {
    /// 适配器名。
    pub adapter: String,
    /// 下发结果。
    pub result: DomainResult<AdapterReceipt>,
}

/// 批量初始化报告。
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InitReport {
    /// 成功应用的配置数。
    pub applied: usize,
    /// 因适配器未登记而跳过的配置数。
    pub skipped: usize,
    /// 登记但配置非法的适配器（**旧配置保持有效**）。
    pub failed: Vec<FailureNote>,
}

/// 配置失败记录。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FailureNote {
    /// 适配器名。
    pub adapter: String,
    /// 错误文本。
    pub error: String,
}

struct Entry {
    handle: AdapterHandle,
    enabled: bool,
    rule: SubscriptionRule,
    metadata: AdapterMetadata,
}

/// 适配器注册表。
pub struct AdapterRegistry {
    tenant_id: TenantId,
    mock_mode: bool,
    secrets: Arc<dyn SecretLookup>,
    entries: BTreeMap<String, Entry>,
}

/// 配置中的路由覆盖项（`event_prefixes` / `min_severity`）。
#[derive(Debug, Default)]
pub(crate) struct RuleUpdate {
    prefixes: Option<Vec<String>>,
    min_severity: Option<Severity>,
}

mod impl_subscription_rule;
#[cfg(test)]
mod tests;
