//! Publication choices use the complete trusted signed registry and current quota definitions.
use super::{records::POLICY, util};
use crate::{policy_store, state::AppState};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::TenantId,
};
use serde_json::{Value, json};

#[derive(Debug, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct Query {
    #[serde(rename = "source_page")]
    pub page: u32,
    #[serde(rename = "source_page_size")]
    pub page_size: u32,
    #[serde(rename = "source_eligible_only")]
    pub eligible_only: bool,
}

impl Default for Query {
    fn default() -> Self {
        Self { page: 1, page_size: 100, eligible_only: false }
    }
}

impl Query {
    pub(super) fn validate(&self) -> DomainResult<()> {
        if self.page == 0 || !(1..=100).contains(&self.page_size) {
            return Err(DomainError::Validation("来源页码必须为正整数，每页1至100条".into()));
        }
        Ok(())
    }
}

pub(super) async fn list(state: &AppState, tenant: TenantId, query: &Query) -> DomainResult<Value> {
    query.validate()?;
    let registry_id = crate::model_routes::tenant_record_id(tenant);
    let payload = state.configurations.get(tenant, POLICY, registry_id).await?;
    let mut policies = policy_store::publication_candidates(state, tenant, payload)?;
    policies.sort_by_key(|row| (row.name.clone(), row.id));
    let count = policies.len();
    let quotas = state.configurations.get::<Value>(tenant, crate::quota_definitions::KIND, registry_id).await?;
    let signer = policy_store::signer(state)?;
    let mut rows = Vec::new();
    let mut eligible_count = 0;
    for policy in policies {
        let result = (|| {
            let id = policy.quota_id.ok_or_else(|| DomainError::PreconditionFailed("来源必须引用配额定义".into()))?;
            let quota =
                crate::quota_definitions::parse_versioned_registry(quotas.clone().ok_or_else(util::stale)?, id)?
                    .ok_or_else(|| DomainError::PreconditionFailed("当前配额依赖不存在".into()))?;
            super::derive_source_limit(tenant, &policy, &quota, &signer)
        })();
        let (source, reason) = match result {
            Ok(source) => (Some(source), None),
            Err(error) => (None, Some(error.to_string())),
        };
        if source.is_some() {
            eligible_count += 1;
        }
        if !query.eligible_only || source.is_some() {
            rows.push(json!({"policyId":policy.id,"version":policy.version,"name":policy.name,
                "eligible":source.is_some(),"source":source,"reason":reason}));
        }
    }
    let total = rows.len();
    let size = query.page_size as usize;
    let offset = (query.page as usize - 1)
        .checked_mul(size)
        .ok_or_else(|| DomainError::Validation("来源页码超出范围".into()))?;
    let items = rows.into_iter().skip(offset).take(size).collect::<Vec<_>>();
    Ok(json!({"items":items,"total":total,"policyCount":count,"eligibleCount":eligible_count,
        "page":query.page,"pageSize":size,"totalPages":total.div_ceil(size),
        "truncated":offset.saturating_add(items.len())<total,
        "reason":if count==0{Some("请先在策略中心保存签名的无条件AI网关配额策略，未从示例初始化")}
            else if total==0{Some("当前没有符合筛选条件的可投射来源，请核对配额与AI网关拦截点")}
            else{None}}))
}
