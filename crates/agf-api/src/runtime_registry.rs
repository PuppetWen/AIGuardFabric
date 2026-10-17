//! 按租户装配运行时；策略或黑名单变更后自动重建，审计共用平台哈希链。
use crate::state::AppState;
use agf_core::{error::DomainResult, ids::TenantId};
use agf_runtime::{
    blocklist::Blocklist,
    engine::{EngineConfig, RuntimeEngine},
};
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::Mutex;

#[derive(Debug, Default)]
pub struct Registry {
    entries: Mutex<BTreeMap<TenantId, (String, Arc<RuntimeEngine>)>>,
}
impl Registry {
    pub async fn get(&self, state: &AppState, tenant: TenantId) -> DomainResult<Arc<RuntimeEngine>> {
        let policies: Vec<_> =
            crate::policy_store::list(state, tenant).await?.into_iter().filter(|p| p.enabled).collect();
        let rows = crate::runtime_rules::load(state, tenant).await?;
        let rules: Vec<_> = rows.rules.into_iter().filter(|row| row.enabled).map(|row| row.rule).collect();
        let quotas = crate::quota_definitions::list(state, tenant).await?;
        let fingerprint = agf_core::secret::content_hash(&serde_json::to_string(&(&policies, &rules, &quotas))?);
        let mut entries = self.entries.lock().await;
        if let Some((old, engine)) = entries.get(&tenant) {
            if *old == fingerprint {
                return Ok(engine.clone());
            }
        }
        let policy_engine = agf_runtime::policy::PolicyEngine::new()
            .with_signer(crate::policy_store::signer(state)?)
            .with_signature_mode(agf_runtime::policy::SignatureMode::Enforce)
            .with_eval_error_mode(agf_runtime::policy::EvalErrorMode::FailClosed)
            .from_policies(policies)?;
        let engine = Arc::new(
            RuntimeEngine::assemble(
                policy_engine,
                Blocklist::from_rules(rules)?,
                agf_runtime::quota::QuotaService::in_memory(Vec::new()),
                state.runtime.approvals().clone(),
                EngineConfig::default().with_tenant(tenant).with_self_proxy_enrollment(false),
            )
            .with_audit_log(state.runtime.audit().clone()),
        );
        entries.insert(tenant, (fingerprint, engine.clone()));
        Ok(engine)
    }
}
