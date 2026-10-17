//! 不执行任意 DSL，也不把条件、dry-run、Agent 范围或费用配额隐式放大成 API 全局限流。
use crate::quota_definitions::VersionedQuota;
use agf_alicloud::apig::policy_driver::ManagedLimit;
use agf_core::{
    enums::{InterceptPoint, PolicyAction, QuotaDimension, QuotaScope},
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    policy::{Policy, PolicyLanguage, StructuredCondition},
    quota::QuotaWindow,
};
use agf_runtime::signature::PolicySigner;
use serde::Serialize;

/// 已校验签名的无条件来源，仅提供显式选定云 API 的阈值蓝本。
/// 没有 Deserialize 入口，不能通过用户请求构造可信投射。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceLimit {
    /// 来源平台策略 ID。
    pub policy_id: Id,
    /// 来源平台策略的确切签名版本。
    pub policy_version: u32,
    /// 来源配额 ID。
    pub quota_id: Id,
    /// 配额定义版本，必须在发布事务中再次核对。
    pub quota_version: u64,
    /// 完整配额定义与版本的 SHA256，供当前依赖围栏使用。
    pub quota_fingerprint: String,
    /// 单个已有 API-global minute 规则的类型。
    pub managed_limit: ManagedLimit,
    /// 可写 provider int32 正阈值。
    pub limit: u32,
}

/// 从当前可信注册表选中的策略和当前已锁定配额提取数值蓝本。
///
/// 该函数不读取存储、发送网络或领取执行权。调用方必须先用完整注册表读取器验证
/// 当前来源，再以同一依赖版本做预览/发送/提交围栏；历史回滚不调用本函数冒充当前阈值。
/// 平台 Tenant 与云 API-global 范围、UTC minute 与 provider TTL 均需用户明确确认。
///
/// # Errors
/// 租户/签名/依赖不匹配，条件或计量语义无法表达，或阈值超出可写范围时拒绝。
pub fn derive_source_limit(
    tenant: TenantId,
    policy: &Policy,
    row: &VersionedQuota,
    signer: &PolicySigner,
) -> DomainResult<SourceLimit> {
    if tenant.as_uuid().is_nil()
        || policy.tenant_id != tenant
        || row.quota.tenant_id != tenant
        || policy.id.is_nil()
        || row.quota.id.is_nil()
        || policy.version == 0
        || row.version == 0
        || policy.deleted_at.is_some()
        || !policy.enabled
        || !row.quota.enabled
        || policy.quota_id != Some(row.quota.id)
        || policy.content_hash != policy.compute_hash()
    {
        return Err(unsupported("来源身份、版本、启用状态或依赖不匹配"));
    }
    signer.verify(policy)?;
    if policy.language != PolicyLanguage::Structured
        || policy.action != PolicyAction::Quota
        || !policy.source.is_empty()
        || policy.dry_run
        || policy.degrade_endpoint_id.is_some()
        || !policy.scope_agent_ids.is_empty()
        || !policy.scope_departments.is_empty()
        || policy.intercept_points.as_slice() != [InterceptPoint::AiGateway]
        || serde_json::to_value(&policy.structured)? != serde_json::to_value(StructuredCondition::default())?
    {
        return Err(unsupported("仅支持明确 AI 网关的无条件、非 dry-run、全租户结构化 quota 蓝本"));
    }
    let quota = &row.quota;
    if quota.scope != QuotaScope::Tenant
        || quota.target_id.is_some()
        || quota.window != QuotaWindow::Minute
        || quota.on_exceed != PolicyAction::Deny
        || quota.soft_threshold != 0
    {
        return Err(unsupported("所选 API-global minute 规则无法表达此作用域、周期、软阈值或超限动作"));
    }
    let managed_limit = match quota.dimension {
        QuotaDimension::Requests => ManagedLimit::RequestPerMinute,
        QuotaDimension::Tokens => ManagedLimit::TokenPerMinute,
        QuotaDimension::Concurrency | QuotaDimension::Cost => {
            return Err(unsupported("此投射不支持并发或费用维度"));
        }
    };
    let limit = u32::try_from(quota.limit)
        .ok()
        .filter(|limit| *limit > 0 && *limit <= i32::MAX.unsigned_abs())
        .ok_or_else(|| unsupported("阈值须为 1 至 2147483647，不截断或夹取"))?;
    Ok(SourceLimit {
        policy_id: policy.id,
        policy_version: policy.version,
        quota_id: quota.id,
        quota_version: row.version,
        quota_fingerprint: crate::policy_store::quota_publication_evidence(row)?.fingerprint,
        managed_limit,
        limit,
    })
}

fn unsupported(reason: &str) -> DomainError {
    DomainError::PreconditionFailed(format!("APIG 配额来源不能投射：{reason}"))
}
