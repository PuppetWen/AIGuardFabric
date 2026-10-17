use super::*;
use crate::{cloud_inventory::Snapshot, integration_store::Stored};

pub(super) fn source(cfg: &Stored, mocked: bool) -> DomainResult<String> {
    hash(&(cfg.id, &cfg.name, cfg.version, cfg.enabled, mocked, &cfg.private))
}
pub(super) fn member(snapshot: &Snapshot, worker: &str, team: &str, role: &str, asset: Id) -> DomainResult<()> {
    let relations = agf_alicloud::agentteams::relations::parse_inventory(
        &snapshot.instance_id,
        &snapshot.teams,
        &snapshot.workers,
    )?;
    relations.require_complete()?;
    if snapshot.assets.get(worker) != Some(&asset) || snapshot.assets.values().filter(|id| **id == asset).count() != 1 {
        return Err(denied());
    }
    let actual = relations
        .teams
        .get(team)
        .and_then(|team| team.workers.as_ref())
        .and_then(|workers| workers.get(worker))
        .and_then(Option::as_ref);
    if actual.map(String::as_str) != Some(role) {
        return Err(denied());
    }
    Ok(())
}
pub(super) fn current(
    proof: &model::Proof,
    tenant: TenantId,
    cfg: &Stored,
    snapshot: &Snapshot,
    asset: &Asset,
    role: &RoleEntry,
    mocked: bool,
) -> DomainResult<()> {
    catalog::supported(role, tenant)?;
    let configuration_changed = cfg.version != proof.configuration_version;
    if cfg.id != crate::integration_store::id(tenant, crate::cloud_inventory::NAME)
        || cfg.name != crate::cloud_inventory::NAME
        || model::AgentIdentity::capture(tenant, asset)? != proof.agent
        || !cfg.enabled
        || configuration_changed
        || snapshot.version != cfg.version
        || snapshot.mocked != mocked
        || mocked != proof.mocked
        || snapshot.region != proof.region
        || snapshot.instance_id != proof.instance_id
        || source(cfg, mocked)? != proof.source_digest
        || role.id != proof.role_id
        || catalog::digest(role)? != proof.role_digest
    {
        return Err(denied());
    }
    member(snapshot, &proof.worker_name, &proof.team_name, &proof.cloud_role, asset.id)
}
pub(super) fn adopt(
    tenant: TenantId,
    cfg: &Stored,
    snapshot: &Snapshot,
    asset: &Asset,
    role: &RoleEntry,
    change: &model::Change,
    mocked: bool,
) -> DomainResult<model::Proof> {
    let model::Change::Adopt { configuration_version, observed_at, worker_name, team_name, cloud_role, role_id } =
        change
    else {
        return Err(DomainError::Validation("采用请求缺少角色选择".into()));
    };
    for text in [worker_name, team_name, cloud_role] {
        if text.is_empty() || text.len() > 256 || text.trim() != text || text.chars().any(char::is_control) {
            return Err(DomainError::Validation("Worker/Team/Role 必须是明确的安全名称".into()));
        }
    }
    if cfg.version != *configuration_version || snapshot.checked_at != *observed_at {
        return Err(DomainError::Conflict("连接或盘点版本已改变，草稿未保存；请读取最新结果再明确采用".into()));
    }
    let age = Timestamp::now().since_secs(&snapshot.checked_at);
    if !cfg.enabled
        || !(-60..=300).contains(&age)
        || snapshot.version != cfg.version
        || snapshot.mocked != mocked
        || role.id != *role_id
    {
        return Err(DomainError::PreconditionFailed("采用需要 300 秒内的完整盘点、启用连接及真实平台角色".into()));
    }
    catalog::supported(role, tenant)?;
    let proof = model::Proof {
        agent: model::AgentIdentity::capture(tenant, asset)?,
        configuration_version: cfg.version,
        source_digest: source(cfg, mocked)?,
        mocked,
        region: snapshot.region.clone(),
        instance_id: snapshot.instance_id.clone(),
        worker_name: worker_name.clone(),
        team_name: team_name.clone(),
        cloud_role: cloud_role.clone(),
        observed_at: snapshot.checked_at,
        role_id: role.id,
        role_digest: catalog::digest(role)?,
    };
    current(&proof, tenant, cfg, snapshot, asset, role, mocked)?;
    Ok(proof)
}
