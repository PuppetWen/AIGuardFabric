//! Probe results publish only against the configuration actually observed.
use crate::{
    integration_store::{Stored, id},
    state::AppState,
};
use agf_core::{
    audit::{AuditAction, AuditActor, AuditOutcome, AuditTarget},
    error::{DomainError, DomainResult},
    ids::TenantId,
    time::Timestamp,
};
use agf_storage::configuration::{ConditionalMutation, ConfigurationGuard, MutationDecision};
use serde_json::{Value, json};

pub(crate) struct Publication<'a> {
    pub configuration_kind: &'static str,
    pub report_kind: &'static str,
    pub name: &'a str,
    pub version: u64,
    pub mocked: bool,
    pub started_at: Timestamp,
    pub report: Value,
    pub outcome: AuditOutcome,
}

pub(crate) async fn publish(
    state: &AppState,
    tenant: TenantId,
    publication: Publication<'_>,
    actor: AuditActor,
) -> DomainResult<Value> {
    let Publication { configuration_kind, report_kind, name, version, mocked, started_at, mut report, outcome } =
        publication;
    let cfg_id = id(tenant, name);
    report["started_at"] = json!(started_at);
    let mut audit = AppState::audit_entry(
        tenant,
        AuditAction::Execute,
        outcome,
        actor,
        AuditTarget::new(report_kind, Some(cfg_id.to_string()), Some(name.into())),
        "自检报告与审计同时发布；模拟检查不证明真实连通性或权限",
    );
    audit.after = Some(json!({"version":version,"mocked":mocked,
        "run_id":report.get("run_id"),"status":report.get("status")}));
    let (published, sealed) = state
        .configurations
        .mutate_conditional_audited::<Option<Value>, _, _>(
            tenant,
            ConditionalMutation {
                kind: report_kind,
                id: cfg_id,
                guard: Some(ConfigurationGuard { kind: configuration_kind, id: cfg_id }),
            },
            |guard, current| {
                let cfg: Stored = guard
                    .map(serde_json::from_value)
                    .transpose()?
                    .ok_or_else(|| DomainError::Conflict("自检配置已删除，请重新加载".into()))?;
                let same_configuration = cfg.id == cfg_id && cfg.name == name && cfg.version == version;
                let same_mode = mocked == (state.config.mock_mode || cfg.mock);
                if !cfg.enabled || !same_configuration || !same_mode {
                    return Err(DomainError::Conflict(
                        "自检期间配置、模式或启用状态已改变；保留历史回执，未覆盖当前报告".into(),
                    ));
                }
                if let Some(previous) = current {
                    if *previous == report {
                        return Ok(MutationDecision::Unchanged);
                    }
                    let prior_started = previous
                        .get("started_at")
                        .or_else(|| previous.get("checked_at"))
                        .cloned()
                        .map(serde_json::from_value::<Timestamp>)
                        .transpose()?;
                    if previous["version"].as_u64() == Some(version)
                        && prior_started.is_some_and(|prior| prior > started_at)
                    {
                        return Err(DomainError::Conflict("较新的自检已发布；当前旧检查未覆盖报告".into()));
                    }
                }
                *current = Some(report);
                Ok(MutationDecision::Write(Some(Box::new(audit))))
            },
            |audit| state.store.audit_append(audit).map(Some),
        )
        .await?;
    if state.store.database().is_some() {
        if let Some(sealed) = sealed {
            if let Err(error) = state.store.hydrate_audit(&sealed) {
                tracing::warn!(%error, "已提交的自检审计投影刷新失败");
            }
        }
    }
    published.ok_or_else(|| DomainError::Internal("已提交自检报告不存在".into()))
}
