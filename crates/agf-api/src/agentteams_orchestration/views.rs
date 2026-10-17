use super::*;

pub(super) fn source(row: &model::Source) -> Value {
    json!({"configurationVersion":row.configuration_version,"region":row.region,"instanceId":row.instance_id,
        "inventoryFingerprint":row.inventory_fingerprint,"mocked":true,"source":"application_owned"})
}
pub(super) fn record(row: &model::Record) -> Value {
    json!({"teamName":row.team_name,"version":row.version,"source":source(&row.source),"local":row.local,
        "receiver":row.receiver,"receiverAvailable":row.receiver.is_some(),"updatedAt":row.updated_at,
        "vendorDagAvailable":false,"consumerApplied":null,"providerCalled":false})
}
pub(super) fn intent(row: &model::Intent, durable: bool) -> Value {
    json!({"requestId":row.request_id,"teamName":row.team_name,"bodyHash":row.body_hash,"version":row.version,
        "source":source(&row.source),"action":row.action,"direction":row.direction,"status":"committed",
        "localHash":row.local_hash,"receiverHash":row.receiver_hash,"localNodeCount":row.local_node_count,
        "receiverNodeCount":row.receiver_node_count,"difference":row.difference,"committedAt":row.committed_at,
        "durable":durable,"immutable":true,"providerCalled":false,"consumerApplied":null})
}
pub(super) async fn state(state: &AppState, principal: &Principal) -> DomainResult<Value> {
    let rows = codec::load(state, principal.tenant).await?;
    let mut teams = Vec::new();
    let cfg = crate::cloud_store::load(state, principal.tenant, crate::cloud_inventory::NAME).await?;
    let snapshot = crate::cloud_inventory::load(state, principal.tenant).await?;
    let supported = cfg.as_ref().is_some_and(|cfg| cfg.enabled && (cfg.mock || state.config.mock_mode))
        && snapshot.as_ref().is_some_and(|row| row.mocked);
    if supported {
        if let Some(snapshot) = snapshot {
            let relationships = agf_alicloud::agentteams::relations::parse_inventory(
                &snapshot.instance_id,
                &snapshot.teams,
                &snapshot.workers,
            )?;
            relationships.require_complete()?;
            for name in relationships.teams.keys() {
                let current = source::current(state, principal.tenant, name).await?;
                teams.push(json!({"teamName":name,"source":source(&current.source),
                    "workers":current.team.agents.iter().map(|agent| json!({"name":agent.cloud_agent_id,"assetId":agent.asset_id})).collect::<Vec<_>>(),
                    "template":agf_alicloud::agentteams::orchestration::DefinitionDocument::from_application(&current.team, vec![]),
                    "current":rows.records.get(name).map(record),
                    "sourceCurrent":rows.records.get(name).map(|row| row.source == current.source)}));
            }
        }
    }
    Ok(
        json!({"modeSupported":supported,"canManage":supported && principal.subject_kind==agf_core::rbac::SubjectKind::User
        && principal.require(state,"platform","admin").is_ok() && principal.require(state,"alicloud","write").is_ok(),
        "durable":state.store.database().is_some(),"generation":rows.generation,"intentCount":rows.intents.len(),
        "teams":teams,"records":rows.records.values().map(record).collect::<Vec<_>>(),"consumerApplied":null,
        "limits":{"maxTeams":MAX_RECORDS,"maxIntents":MAX_INTENTS,"maxBytes":MAX_BYTES,"maxNodes":128,"maxDocumentBytes":256*1024}}),
    )
}
