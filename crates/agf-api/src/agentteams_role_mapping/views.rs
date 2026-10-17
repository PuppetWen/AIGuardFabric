use super::*;
pub(super) fn record(row: &model::Record) -> Value {
    json!({"assetId":row.asset_id,"version":row.version,"governed":row.governed,
        "eligibility":row.eligibility,"reason":row.reason,"updatedAt":row.updated_at,
        "proof":{"configurationVersion":row.proof.configuration_version,"mocked":row.proof.mocked,
            "region":row.proof.region,"instanceId":row.proof.instance_id,"workerName":row.proof.worker_name,
            "teamName":row.proof.team_name,"cloudRole":row.proof.cloud_role,"observedAt":row.proof.observed_at,
            "platformRoleId":row.proof.role_id,"department":row.proof.agent.department,
            "dataClass":row.proof.agent.data_class},
        "currentQualified":null,"constraint":"key_scopes_intersection","cloudPermissionGranted":false})
}
pub(super) fn intent(fact: &model::Intent) -> Value {
    json!({"requestId":fact.request_id,"assetId":fact.asset_id,"original":record(&fact.result),
        "immutable":true,"providerCalled":false})
}
pub(super) async fn list(state: &AppState, principal: &Principal) -> DomainResult<Value> {
    let tenant = principal.tenant;
    if state.store.database().is_none() {
        return Ok(
            json!({"catalogAvailable":false,"canManage":false,"roles":[],"items":[],"workers":[],"mappedCount":0,
            "note":"离线角色只有名称；未纳管 Key 保持原权限，新增映射需要数据库真实角色目录"}),
        );
    }
    let catalog = catalog::list(state, tenant).await?;
    let roles: Vec<Value> = catalog
        .iter()
        .map(|role| {
            let result = catalog::supported(role, tenant);
            json!({"id":role.id,"name":role.name,"displayName":role.display_name,"permissions":role.permissions,
            "selectable":result.is_ok(),"reason":result.err().map(|error| error.to_string())})
        })
        .collect();
    let cfg = crate::cloud_store::load(state, tenant, crate::cloud_inventory::NAME).await?;
    let snapshot = crate::cloud_inventory::load(state, tenant).await?;
    let mut items = BTreeMap::new();
    let mut mapped_count = 0;
    for row in catalog::mappings(state, tenant).await? {
        let asset = state.store.asset_get_durable(tenant, row.asset_id).await?;
        let role = catalog.iter().find(|role| role.id == row.proof.role_id);
        let current =
            qualified(&row, tenant, cfg.as_ref(), snapshot.as_ref(), asset.as_ref(), role, state.config.mock_mode);
        let mut item = record(&row);
        item["currentQualified"] = json!(current);
        item["currentReason"] = if current { Value::Null } else { json!("current_role_constraint_unavailable") };
        mapped_count += usize::from(current);
        if items.insert(row.asset_id, item).is_some() {
            return Err(denied());
        }
    }
    let workers = if let Some(snapshot) = &snapshot {
        let relations = agf_alicloud::agentteams::relations::parse_inventory(
            &snapshot.instance_id,
            &snapshot.teams,
            &snapshot.workers,
        )?;
        relations.require_complete()?;
        relations.teams.iter().flat_map(|(team, members)| members.workers.iter().flat_map(move |workers| {
            workers.iter().map(move |(worker, role)| json!({"assetId":snapshot.assets.get(worker),"workerName":worker,
                "teamName":team,"cloudRole":role,"configurationVersion":snapshot.version,"observedAt":snapshot.checked_at}))
        })).collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    Ok(json!({"catalogAvailable":true,"canManage":principal.subject_kind==agf_core::rbac::SubjectKind::User
        && principal.require(state,"platform","admin").is_ok() && principal.require(state,"assets","write").is_ok(),
        "roles":roles,"items":items.into_values().collect::<Vec<_>>(),"workers":workers,"mappedCount":mapped_count,
        "adoptionWindowSeconds":300,"permissionTTL":null,"providerCalled":false,
        "limits":{"workers":MAX_WORKERS,"immutableIntents":MAX_INTENTS},
        "note":"本地角色约束，云 Role 不作身份认证；离线新增映射尚未实现"}))
}

pub(super) fn qualified(
    row: &model::Record,
    tenant: TenantId,
    cfg: Option<&crate::integration_store::Stored>,
    snapshot: Option<&crate::cloud_inventory::Snapshot>,
    asset: Option<&Asset>,
    role: Option<&RoleEntry>,
    mock_mode: bool,
) -> bool {
    let (Some(cfg), Some(snapshot), Some(asset), Some(role)) = (cfg, snapshot, asset, role) else {
        return false;
    };
    row.governed
        && row.tenant == tenant
        && row.asset_id == asset.id
        && row.eligibility == model::Eligibility::Eligible
        && asset.attributes.get(MARKER) == Some(&Value::Bool(true))
        && proof::current(&row.proof, tenant, cfg, snapshot, asset, role, mock_mode || cfg.mock).is_ok()
}
