//! 显式盘点 AgentTeams：完整分页成功后保存加密快照，资产按租户/账号/实例归并。
use crate::{
    cloud_runtime::{self, Request},
    cloud_store,
    integration_store::{Private, Stored, decrypt, id},
    model_gateway::encrypt,
    state::AppState,
    store::{asset_transaction::AssetTransaction, cloud_assets},
};
use agf_alicloud::agentteams::relations::{self, ResourceKind};
use agf_core::{
    asset::Asset,
    audit::{AuditAction, AuditActor, AuditLog, AuditOutcome, AuditTarget},
    enums::{AssetKind, DiscoverySource},
    error::{DomainError, DomainResult},
    ids::{Id, TenantId, deterministic_id},
    time::Timestamp,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const NAME: &str = "alicloud-agentteams";
const KIND: &str = "cloud-inventory";
#[derive(Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub version: u64,
    pub mocked: bool,
    pub checked_at: Timestamp,
    pub region: String,
    pub instance_id: String,
    pub teams: Vec<Value>,
    pub workers: Vec<Value>,
    pub tasks: BTreeMap<String, Vec<Value>>,
    pub assets: BTreeMap<String, Id>,
}
#[derive(Debug, Deserialize, Serialize)]
pub struct SyncRequest {
    pub request_id: Id,
    pub configuration_version: u64,
    #[serde(default)]
    pub confirm_live: bool,
}
impl std::fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudSnapshot")
            .field("version", &self.version)
            .field("mocked", &self.mocked)
            .field("teams", &self.teams.len())
            .field("workers", &self.workers.len())
            .finish_non_exhaustive()
    }
}
pub async fn load(state: &AppState, tenant: TenantId) -> DomainResult<Option<Snapshot>> {
    let current = cloud_store::load(state, tenant, NAME).await?;
    let saved = state.configurations.get::<Stored>(tenant, KIND, id(tenant, NAME)).await?;
    let Some(saved) = saved.filter(|row| current.as_ref().is_some_and(|cfg| cfg.version == row.version)) else {
        return Ok(None);
    };
    let private = decrypt(state, tenant, &saved)?;
    private.settings.get("snapshot").cloned().map(serde_json::from_value).transpose().map_err(Into::into)
}
pub async fn sync(
    state: &AppState,
    tenant: TenantId,
    actor: String,
    audit_actor: AuditActor,
    request: SyncRequest,
) -> DomainResult<Value> {
    sync_inner(state, tenant, actor, audit_actor, request, None).await
}

pub(crate) async fn sync_for_team(
    state: &AppState,
    tenant: TenantId,
    actor: String,
    audit_actor: AuditActor,
    request: SyncRequest,
    publication: &dyn crate::team_management::publication::InventoryPublication,
) -> DomainResult<Value> {
    sync_inner(state, tenant, actor, audit_actor, request, Some(publication)).await
}

async fn sync_inner(
    state: &AppState,
    tenant: TenantId,
    actor: String,
    audit_actor: AuditActor,
    request: SyncRequest,
    publication: Option<&dyn crate::team_management::publication::InventoryPublication>,
) -> DomainResult<Value> {
    let cfg = cloud_store::load(state, tenant, NAME)
        .await?
        .filter(|row| row.enabled)
        .ok_or_else(|| DomainError::PreconditionFailed("请先启用 AgentTeams 连接".into()))?;
    if cfg.version != request.configuration_version {
        return Err(DomainError::Conflict("云配置已改变，请重新加载".into()));
    }
    let mocked = cfg.mock || state.config.mock_mode;
    if !mocked && !request.confirm_live {
        return Err(DomainError::PreconditionFailed("请确认只读云调用及本地资产台账更新".into()));
    }
    let settings = decrypt(state, tenant, &cfg)?;
    let context = Context { state, tenant, actor, request: &request };
    let mut listed_teams = context.pages("ListTeams", json!({})).await?;
    let mut listed_workers = context.pages("ListWorkers", json!({})).await?;
    let instance = cloud_store::setting(&settings, "instance_id", "");
    let mut teams = Vec::new();
    for team in &mut listed_teams {
        teams.push(context.detail(team, "GetTeam", ResourceKind::Team, instance, mocked).await?);
    }
    let mut workers = Vec::new();
    for worker in &mut listed_workers {
        workers.push(context.detail(worker, "GetWorker", ResourceKind::Worker, instance, mocked).await?);
    }
    let relationships = relations::parse_inventory(instance, &teams, &workers)?;
    relations::verify_list_references(&listed_teams, &listed_workers, &relationships)?;
    relationships.require_complete()?;
    let mut tasks = BTreeMap::new();
    for team in &teams {
        let name = required_name(team)?;
        tasks.insert(name.to_owned(), context.pages("ListTeamTasks", json!({"Team":name})).await?);
    }
    // 完整失败保留上次快照，不把不完整分页当成删除资源。
    if cloud_store::load(state, tenant, NAME).await?.is_none_or(|row| row.version != cfg.version) {
        return Err(DomainError::Conflict("盘点期间配置改变，结果未发布，请重新盘点".into()));
    }
    let mut snapshot = Snapshot {
        version: cfg.version,
        mocked,
        checked_at: Timestamp::now(),
        region: cloud_store::setting(&settings, "region_id", "cn-hangzhou").into(),
        instance_id: cloud_store::setting(&settings, "instance_id", "").into(),
        teams,
        workers,
        tasks,
        assets: BTreeMap::new(),
    };
    use sha2::{Digest, Sha256};
    let source_identity = format!(
        "{}:{}:{}",
        cloud_store::setting(&settings, "endpoint", ""),
        cloud_store::setting(&settings, "role_arn", ""),
        settings.secrets.get("access_key_id").map_or("", String::as_str)
    );
    let identity_hash = format!("{:x}", Sha256::digest(source_identity.as_bytes()));
    let account = cloud_store::setting(&settings, "account_id", &identity_hash);
    if serde_json::to_vec(&snapshot)?.len() > 1_900_000 {
        return Err(DomainError::Validation("盘点快照过大，请分实例接入".into()));
    }
    let discovered = assets(tenant, &snapshot, account)?;
    if let Some(publication) = publication {
        publication.validate_snapshot(&snapshot)?;
    }
    let audit = AuditLog {
        id: Id::new(),
        tenant_id: tenant,
        sequence: 0,
        action: AuditAction::Execute,
        outcome: AuditOutcome::Success,
        actor: audit_actor,
        target: AuditTarget::new("cloud-integration", None, Some(NAME.into())),
        before: None,
        after: None,
        changed_fields: Vec::new(),
        request_id: crate::error::current_request_id().or_else(|| Some(request.request_id.to_string())),
        error: None,
        note: "完整盘点团队、Worker 和任务；同步本地资产台账".into(),
        prev_hash: String::new(),
        entry_hash: String::new(),
        at: Timestamp::now(),
    };
    let bindings_refreshed;
    if let Some(db) = state.store.database() {
        let tx = AssetTransaction::begin(db, tenant).await?;
        tx.tenant_enabled().await?;
        // Lock the connection row as well: an administrator must not switch its
        // account or credentials while this snapshot is being published.
        let current = tx.configuration::<Stored>(cloud_store::KIND, cfg.id).await?;
        if !current.is_some_and(|row| row.version == cfg.version && row.enabled) {
            return Err(DomainError::Conflict("盘点期间云配置改变，资产与快照均未发布".into()));
        }
        let previous = tx.configuration::<Stored>(KIND, cfg.id).await?.map(|row| row.updated_at);
        snapshot.assets = cloud_assets::merge_in_transaction(&tx, &discovered).await?;
        let stored = seal_snapshot(state, tenant, &cfg, &snapshot)?;
        tx.configure(KIND, stored.id, Some(serde_json::to_value(&stored)?)).await?;
        bindings_refreshed =
            crate::agentteams_audit::inventory_refresh::in_transaction(&tx, tenant, &snapshot, previous).await?;
        if let Some(publication) = publication {
            publication.in_transaction(&tx, &snapshot).await?;
        }
        crate::agentteams_role_mapping::refresh_in_transaction(state, &tx, tenant, &cfg, &snapshot, &audit.actor)
            .await?;
        tx.audit(audit).await?;
        tx.commit(&state.store).await?;
    } else {
        let previous = state.configurations.get::<Stored>(tenant, KIND, cfg.id).await?.map(|row| row.updated_at);
        snapshot.assets = cloud_assets::merge_offline(state, &discovered)?;
        let stored = seal_snapshot(state, tenant, &cfg, &snapshot)?;
        state.configurations.put(tenant, KIND, stored.id, &stored).await?;
        bindings_refreshed =
            crate::agentteams_audit::inventory_refresh::offline(state, tenant, &snapshot, previous).await?;
        if let Some(publication) = publication {
            publication.offline(state, &snapshot).await?;
        }
        state.store.audit_append_durable(audit).await?;
    }
    let count = snapshot.assets.len();
    Ok(json!({"mocked":mocked,"checked_at":snapshot.checked_at,"teams":snapshot.teams.len(),
        "workers":snapshot.workers.len(),"assets":count,"tasks":snapshot.tasks.values().map(Vec::len).sum::<usize>(),"bindingsRefreshed":bindings_refreshed,
        "note":"完整分页已入库；未返回的旧资产保留，人工归属、分级和生命周期保持不变"}))
}

fn seal_snapshot(state: &AppState, tenant: TenantId, cfg: &Stored, snapshot: &Snapshot) -> DomainResult<Stored> {
    let mut private = Private::default();
    private.settings.insert("snapshot".into(), serde_json::to_value(snapshot)?);
    let raw = serde_json::to_string(&private)?;
    if raw.len() > 2 * 1024 * 1024 {
        return Err(DomainError::Validation("盘点快照超过 2 MiB，请分实例接入".into()));
    }
    Ok(Stored {
        private: encrypt(state, tenant, id(tenant, NAME), raw)?,
        updated_at: snapshot.checked_at,
        ..cfg.clone()
    })
}
struct Context<'a> {
    state: &'a AppState,
    tenant: TenantId,
    actor: String,
    request: &'a SyncRequest,
}
impl Context<'_> {
    async fn detail(
        &self,
        listed: &mut Value,
        action: &str,
        kind: ResourceKind,
        instance: &str,
        mocked: bool,
    ) -> DomainResult<Value> {
        let name = required_name(listed)?;
        let mut data = self.call(action, json!({"Name":name})).await?["Data"].clone();
        if mocked {
            // Only the public mock fixture instance is substituted; identities and types remain checked.
            for value in [&mut *listed, &mut data] {
                if value["InstanceId"] == "inst-demo" {
                    value["InstanceId"] = json!(instance);
                }
            }
        }
        relations::verify_detail(listed, &data, instance, kind)?;
        Ok(data)
    }

    async fn call(&self, action: &str, parameters: Value) -> DomainResult<Value> {
        let key = format!("{}:{action}:{parameters}", self.request.request_id);
        let value = Box::pin(cloud_runtime::execute(
            self.state,
            self.tenant,
            NAME,
            self.actor.clone(),
            Request {
                request_id: deterministic_id("agf.cloud.inventory.operation", &key),
                configuration_version: self.request.configuration_version,
                action: action.into(),
                parameters,
                confirm_live: self.request.confirm_live,
            },
        ))
        .await?;
        if value["status"] != "succeeded" {
            return Err(DomainError::DependencyUnavailable {
                dependency: action.into(),
                cause: format!("盘点未完成，请查看操作回执 {}", value["id"]),
            });
        }
        Ok(value["receipt"]["response"].clone())
    }
    async fn pages(&self, action: &str, mut parameters: Value) -> DomainResult<Vec<Value>> {
        parameters["MaxResults"] = json!(100);
        let identity = if action == "ListTeamTasks" { "TaskId" } else { "Name" };
        let mut out = Vec::new();
        let mut tokens = BTreeSet::new();
        let mut identities = BTreeSet::new();
        let mut total = None;
        for _ in 0..20 {
            let body = self.call(action, parameters.clone()).await?;
            let items =
                body["Items"].as_array().ok_or_else(|| DomainError::Parse(format!("{action} 缺少 Items 数组")))?;
            if let Some(value) = body.get("TotalCount").filter(|value| !value.is_null()) {
                let count = value.as_u64().ok_or_else(|| DomainError::Parse(format!("{action} 的 TotalCount 无效")))?;
                if total.is_some_and(|previous| previous != count) {
                    return Err(DomainError::Parse(format!("{action} 分页 TotalCount 不一致")));
                }
                total = Some(count);
            }
            for item in items {
                let key = item[identity]
                    .as_str()
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| DomainError::Parse(format!("{action} 资源缺少 {identity}")))?;
                if !identities.insert(key.to_owned()) {
                    return Err(DomainError::Parse(format!("{action} 返回重复 {identity}")));
                }
                out.push(item.clone());
            }
            if identity == "Name" && out.len() > 200 {
                return Err(DomainError::Validation(format!("{action} 单次最多 200 个资源，请分实例接入")));
            }
            if total.is_some_and(|count| count < out.len() as u64) {
                return Err(DomainError::Parse(format!("{action} 资源数超过 TotalCount")));
            }
            let next = match body.get("NextToken").filter(|value| !value.is_null()) {
                None => "",
                Some(value) => {
                    value.as_str().ok_or_else(|| DomainError::Parse(format!("{action} 的 NextToken 无效")))?
                }
            };
            if next.is_empty() {
                if total.is_some_and(|count| count != out.len() as u64) {
                    return Err(DomainError::Parse(format!("{action} 资源列表提前结束")));
                }
                return Ok(out);
            }
            if !tokens.insert(next.to_owned()) {
                return Err(DomainError::Parse(format!("{action} 返回重复分页令牌")));
            }
            parameters["NextToken"] = json!(next);
        }
        Err(DomainError::Validation(format!("{action} 超过单次 20 页；未发布不完整快照")))
    }
}
fn required_name(value: &Value) -> DomainResult<&str> {
    value["Name"].as_str().filter(|name| !name.is_empty()).ok_or_else(|| DomainError::Parse("云资源缺少 Name".into()))
}
fn assets(tenant: TenantId, snapshot: &Snapshot, account: &str) -> DomainResult<Vec<Asset>> {
    let mut out = Vec::new();
    for worker in &snapshot.workers {
        let name = required_name(worker)?;
        let scope = format!(
            "{}:{account}:{}:{}",
            if snapshot.mocked { "mock" } else { "live" },
            snapshot.region,
            snapshot.instance_id
        );
        let fp = format!("agentteams:{scope}:worker:{name}");
        let mut asset = Asset::new(tenant, AssetKind::Agent, name, &fp);
        asset.id = deterministic_id("agf.cloud.asset", &format!("{tenant}:{fp}"));
        asset.vendor = Some("Alibaba Cloud AgentTeams".into());
        asset.version = worker["VersionCode"].as_str().map(str::to_owned);
        asset.discovery_source = DiscoverySource::CloudApi;
        asset.runtime = Some("saas".into());
        asset.cloud_resource_id = Some(format!("{}/{}", snapshot.instance_id, name));
        asset.attributes.insert("cloud_worker_name".into(), json!(name));
        asset.attributes.insert("cloud_instance_id".into(), json!(snapshot.instance_id));
        asset.attributes.insert("cloud_configuration_version".into(), json!(snapshot.version));
        asset.attributes.insert("mock_mode".into(), json!(snapshot.mocked));
        for key in ["Status", "AgentType", "DeployType", "Groups", "Model", "Skills"] {
            // Returned Workers own these observations. Absence must clear a previous observation,
            // rather than retain an old role/model as though the cloud returned it this time.
            asset.attributes.insert(format!("cloud_{key}"), worker.get(key).cloned().unwrap_or(Value::Null));
        }
        asset.attributes.insert(
            "cloud_McpServers".into(),
            json!(worker["McpServers"].as_array().map(|items| {
                items
                    .iter()
                    .map(|item| json!({"Name":item["Name"].as_str(),"Transport":item["Transport"].as_str()}))
                    .collect::<Vec<_>>()
            })),
        );
        out.push(asset);
    }
    Ok(out)
}
