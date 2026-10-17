use super::*;
use crate::{
    integration_store::{Stored, decrypt, id},
    policy_store::{AccessLease, AuthorizedSubmission, Grant, PublicationAuthorization, authorize_publication},
};
use agf_asset::service::AssetBackend;
use agf_core::{
    audit::{AuditAction, AuditLog, AuditOutcome, AuditTarget},
    rbac::SubjectKind,
};

static AUTHORIZATION: PublicationAuthorization = PublicationAuthorization {
    resource: "platform",
    action: "admin",
    additional: &[Grant { resource: "alicloud", action: "read" }, Grant { resource: "assets", action: "write" }],
};
fn audit(principal: &Principal, record: &model::Record, request_id: Id) -> AuditLog {
    AuditLog {
        id: Id::new(),
        tenant_id: principal.tenant,
        sequence: 0,
        action: AuditAction::Grant,
        outcome: AuditOutcome::Success,
        actor: AppState::audit_actor(principal, "agentteams-role-governance"),
        target: AuditTarget::new(KIND, Some(record.asset_id.to_string()), None),
        before: None,
        after: Some(json!({"version":record.version,"eligibility":record.eligibility,"roleId":record.proof.role_id})),
        changed_fields: vec!["local_role_constraint".into()],
        request_id: Some(request_id.to_string()),
        error: None,
        note: "明确本地角色约束；Key 原 scopes 取交集，不写入云端或扩权".into(),
        prev_hash: String::new(),
        entry_hash: String::new(),
        at: Timestamp::now(),
    }
}
pub(super) async fn save(
    state: &AppState,
    principal: &Principal,
    lease: Option<&AccessLease>,
    asset_id: Id,
    input: model::Input,
) -> DomainResult<model::Intent> {
    if principal.subject_kind != SubjectKind::User {
        return Err(DomainError::Forbidden("角色治理需要管理员用户会话确认".into()));
    }
    if asset_id.is_nil() || input.request_id.is_nil() || !input.confirm_local_constraint {
        return Err(DomainError::Validation("需要明确 Worker、独立请求编号及本地权限约束确认".into()));
    }
    let submission =
        AuthorizedSubmission { principal, submitted_at: Timestamp::now(), lease, authorization: &AUTHORIZATION };
    authorize_publication(state, &submission).await?;
    let actor_id = principal.subject_id.ok_or_else(denied)?;
    let db = state.store.database().ok_or_else(|| {
        DomainError::PreconditionFailed("新增角色映射需要真实 SQL 角色目录；离线模式未实现该管理功能".into())
    })?;
    let tx = AssetTransaction::begin(db, principal.tenant).await?;
    tx.tenant_enabled().await?;
    let cloud_id = id(principal.tenant, crate::cloud_inventory::NAME);
    // Same order as full inventory: connection, inventory, governance. Never acquire audit first.
    let cfg = tx.configuration::<Stored>(crate::cloud_store::KIND, cloud_id).await?;
    let saved = tx.configuration::<Stored>("cloud-inventory", cloud_id).await?;
    tx.configuration_lock(KIND, asset_id).await?;
    tx.configuration_lock(INTENTS, input.request_id).await?;
    if let Some(sealed) = tx.configuration::<model::Sealed>(INTENTS, input.request_id).await? {
        let fact = codec::replay(state, principal.tenant, actor_id, asset_id, &input, &sealed)?;
        authorize_publication(state, &submission).await?;
        return Ok(fact);
    }
    let previous = tx
        .configuration::<model::Sealed>(KIND, asset_id)
        .await?
        .map(|row| codec::record(state, principal.tenant, asset_id, &row))
        .transpose()?;
    if previous.as_ref().map_or(0, |row| row.version) != input.expected_version {
        return Err(DomainError::Conflict("角色约束版本已改变；保留草稿，读取后明确采用或停用".into()));
    }
    let mut asset = tx.find(principal.tenant, asset_id).await?;
    if previous.is_none() && asset.as_ref().is_some_and(|asset| asset.attributes.contains_key(MARKER)) {
        return Err(denied());
    }
    tx.agentteams_role_capacity(INTENTS, MAX_INTENTS).await?;
    if previous.is_none() {
        tx.agentteams_role_capacity(KIND, MAX_WORKERS).await?;
    }
    let version =
        input.expected_version.checked_add(1).ok_or_else(|| DomainError::Validation("映射版本已耗尽".into()))?;
    let result = match &input.change {
        model::Change::Adopt { role_id, .. } => {
            let asset = asset.as_ref().ok_or_else(denied)?;
            model::AgentIdentity::capture(principal.tenant, asset)?;
            let cfg = cfg.ok_or_else(denied)?;
            let saved = saved.ok_or_else(denied)?;
            if saved.version != cfg.version || saved.id != cloud_id || saved.name != crate::cloud_inventory::NAME {
                return Err(denied());
            }
            let snapshot = serde_json::from_value(
                decrypt(state, principal.tenant, &saved)?.settings.get("snapshot").cloned().ok_or_else(denied)?,
            )?;
            let role = tx.agentteams_platform_role(*role_id).await?.ok_or_else(denied)?;
            let proof = proof::adopt(
                principal.tenant,
                &cfg,
                &snapshot,
                asset,
                &role,
                &input.change,
                state.config.mock_mode || cfg.mock,
            )?;
            model::Record {
                tenant: principal.tenant,
                asset_id,
                version,
                governed: true,
                eligibility: model::Eligibility::Eligible,
                reason: None,
                proof,
                updated_at: Timestamp::now(),
            }
        }
        model::Change::Disable => {
            let mut row =
                previous.ok_or_else(|| DomainError::NotFound { entity: "role mapping", id: asset_id.to_string() })?;
            row.version = version;
            row.eligibility = model::Eligibility::Disabled;
            row.reason = Some("administrator_disabled".into());
            row.updated_at = Timestamp::now();
            row
        }
    };
    let fact = model::Intent {
        tenant: principal.tenant,
        actor_id,
        request_id: input.request_id,
        asset_id,
        body_hash: hash(&(asset_id, &input))?,
        result,
    };
    let row = codec::seal(state, principal.tenant, KIND, asset_id, &fact.result)?;
    let receipt = codec::seal(state, principal.tenant, INTENTS, input.request_id, &fact)?;
    authorize_publication(state, &submission).await?;
    // Disable must also work after retirement/deletion; it never revives an asset.
    if matches!(&input.change, model::Change::Adopt { .. }) {
        let asset = asset.as_mut().ok_or_else(denied)?;
        asset.attributes.insert(MARKER.into(), Value::Bool(true));
        tx.upsert(principal.tenant, asset).await?;
    }
    tx.configure(KIND, asset_id, Some(serde_json::to_value(row)?)).await?;
    tx.configure(INTENTS, input.request_id, Some(serde_json::to_value(receipt)?)).await?;
    tx.audit(audit(principal, &fact.result, input.request_id)).await?;
    // Role/asset/source locks are still held; account/session authority is rechecked after audit wait.
    authorize_publication(state, &submission).await?;
    if matches!(&input.change, model::Change::Adopt { .. })
        && Timestamp::now().since_secs(&fact.result.proof.observed_at) > 300
    {
        return Err(DomainError::PreconditionFailed("审计等待期间采用观察过期；未提交，请重新盘点并明确采用".into()));
    }
    tx.commit(&state.store).await?;
    Ok(fact)
}
