//! Main ledger -> sorted immutable archives -> audit, atomically in SQL or offline.
use super::{
    KIND, MAX_BYTES, archive, archive_sql,
    contract::{Archived, Record, Scope},
    scope, store,
};
use crate::{Principal, cloud_store, integration_store::Stored, state::AppState};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    time::Timestamp,
};
use agf_storage::configuration::{BatchDecision, BatchMutation, ConfigurationGuard};
use serde_json::Value;
use std::collections::BTreeMap;

pub(super) type Related = BTreeMap<Id, Option<Archived>>;

pub(super) async fn mutate<F>(
    state: &AppState,
    principal: &Principal,
    expected: Option<&Scope>,
    ids: &[Id],
    submitted_at: Timestamp,
    apply: F,
) -> DomainResult<Record>
where
    F: FnOnce(&mut Record, &Related) -> DomainResult<BatchDecision> + Send,
{
    let tenant = principal.tenant;
    if state.store.database().is_some() {
        return archive_sql::mutate(state, principal, expected, ids, submitted_at, apply).await;
    }
    if !crate::tenant_directory::get(state, tenant).await?.enabled {
        return Err(DomainError::Forbidden("租户已停用".into()));
    }
    let (row, _) = state
        .configurations
        .mutate_batch_audited(
            tenant,
            BatchMutation {
                kind: KIND,
                id: crate::integration_store::id(tenant, super::NAME),
                guard: expected.map(|scope| ConfigurationGuard { kind: cloud_store::KIND, id: scope.cloud_id }),
                related_kind: archive::KIND,
                related_ids: ids,
                max_main_bytes: MAX_BYTES,
                max_related_bytes: 8192,
            },
            |guard, row: &mut Record, values| {
                if let Some(expected) = expected {
                    let cloud: Stored = guard
                        .map(serde_json::from_value)
                        .transpose()?
                        .filter(|cloud: &Stored| cloud.enabled)
                        .ok_or_else(scope::stale)?;
                    if scope::from_row(state, tenant, &cloud)? != *expected {
                        return Err(scope::stale());
                    }
                }
                let related = values
                    .iter()
                    .map(|(id, value)| Ok((*id, value.clone().map(serde_json::from_value).transpose()?)))
                    .collect::<DomainResult<Related>>()?;
                let decision = apply(row, &related)?;
                if matches!(decision, BatchDecision::Write { .. }) {
                    store::bounded(row)?;
                }
                Ok(decision)
            },
            |audit| state.store.audit_append(audit),
        )
        .await?;
    Ok(row)
}

pub(super) fn validate_candidates(
    tenant: TenantId,
    ids: &[Id],
    related: &BTreeMap<Id, Value>,
    audit: Option<&agf_core::audit::AuditLog>,
) -> DomainResult<()> {
    if audit.is_some_and(|audit| audit.tenant_id != tenant) {
        return Err(DomainError::TenantViolation { tenant: tenant.to_string(), resource: KIND.into() });
    }
    for (id, payload) in related {
        if !ids.contains(id) || serde_json::to_vec(payload)?.len() > 8192 {
            return Err(DomainError::Validation("PrivateLink 归档候选超出声明范围或容量".into()));
        }
    }
    Ok(())
}
