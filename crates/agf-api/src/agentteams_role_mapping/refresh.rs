use super::*;
use crate::{cloud_inventory::Snapshot, integration_store::Stored};
use agf_asset::service::AssetBackend;
use agf_core::audit::{AuditAction, AuditActor, AuditLog, AuditOutcome, AuditTarget};

pub(super) fn decision(
    row: &model::Record,
    snapshot: &Snapshot,
) -> DomainResult<Option<(model::Eligibility, &'static str)>> {
    if row.eligibility != model::Eligibility::Eligible {
        return Ok(None);
    }
    if row.proof.configuration_version != snapshot.version
        || row.proof.mocked != snapshot.mocked
        || row.proof.region != snapshot.region
        || row.proof.instance_id != snapshot.instance_id
    {
        return Ok(Some((model::Eligibility::Revoked, "source_changed")));
    }
    let relations = agf_alicloud::agentteams::relations::parse_inventory(
        &snapshot.instance_id,
        &snapshot.teams,
        &snapshot.workers,
    )?;
    relations.require_complete()?;
    if snapshot.assets.get(&row.proof.worker_name) != Some(&row.asset_id) {
        return Ok(Some((model::Eligibility::Revoked, "worker_missing_or_remapped")));
    }
    let member = relations
        .teams
        .get(&row.proof.team_name)
        .and_then(|team| team.workers.as_ref())
        .and_then(|workers| workers.get(&row.proof.worker_name));
    Ok(match member {
        None => Some((model::Eligibility::Revoked, "membership_removed")),
        Some(None) => Some((model::Eligibility::Unverified, "cloud_role_unknown")),
        Some(Some(role)) if role != &row.proof.cloud_role => Some((model::Eligibility::Revoked, "cloud_role_changed")),
        Some(Some(_)) => None,
    })
}

/// Complete inventory and negative qualification facts commit with the same asset/audit transaction.
/// Partial observations are never interpreted as removal. Positive observations never reactivate.
pub(crate) async fn in_transaction(
    state: &AppState,
    tx: &AssetTransaction<'_>,
    tenant: TenantId,
    cfg: &Stored,
    snapshot: &Snapshot,
    actor: &AuditActor,
) -> DomainResult<()> {
    let rows = tx.configurations::<model::Sealed>(KIND).await?;
    if rows.len() > MAX_WORKERS {
        return Err(DomainError::Crypto("角色治理台账超过上限".into()));
    }
    for (id, sealed) in rows {
        let mut record = codec::record(state, tenant, id, &sealed)?;
        if record.eligibility != model::Eligibility::Eligible {
            continue;
        }
        let mut negative = decision(&record, snapshot)?;
        if negative.is_none() && proof::source(cfg, snapshot.mocked)? != record.proof.source_digest {
            negative = Some((model::Eligibility::Revoked, "source_changed"));
        }
        if negative.is_none() {
            let asset = tx.find(tenant, id).await?;
            if asset.as_ref().and_then(|asset| model::AgentIdentity::capture(tenant, asset).ok())
                != Some(record.proof.agent.clone())
            {
                negative = Some((model::Eligibility::Revoked, "agent_governance_changed"));
            }
        }
        let Some((eligibility, reason)) = negative else {
            continue;
        };
        if !record.retire(eligibility, reason)? {
            continue;
        }
        let saved = codec::seal(state, tenant, KIND, id, &record)?;
        tx.configure(KIND, id, Some(serde_json::to_value(saved)?)).await?;
        tx.audit(AuditLog {
            id: Id::new(),
            tenant_id: tenant,
            sequence: 0,
            action: AuditAction::Grant,
            outcome: AuditOutcome::Success,
            actor: actor.clone(),
            target: AuditTarget::new(KIND, Some(id.to_string()), None),
            before: None,
            after: Some(json!({"version":record.version,"eligibility":eligibility,"reason":reason})),
            changed_fields: vec!["qualification".into()],
            request_id: crate::error::current_request_id(),
            error: None,
            note: "完整盘点撤销或标记未知；正面观测不能自动恢复本地角色权限".into(),
            prev_hash: String::new(),
            entry_hash: String::new(),
            at: Timestamp::now(),
        })
        .await?;
    }
    Ok(())
}
