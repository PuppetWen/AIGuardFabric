//! Archival helpers retain the original completed request and its immutable hash.
#![allow(dead_code)]
use crate::{common::*, mse_inventory_support::*};
use agf_core::ids::Id;
use sha2::{Digest, Sha256};

pub(crate) const ARCHIVE: &str = "/api/v1/alicloud/mse/operations/archive";
pub(crate) const ARCHIVES: &str = "mse-inventory-archive";

pub(crate) async fn archive(h: &Harness, ids: Vec<Value>) -> Resp {
    let view = h.get(VIEW).await.json();
    h.post(ARCHIVE, json!({"expected_generation":view["generation"],"request_ids":ids})).await
}

pub(crate) async fn archive_audits(h: &Harness) -> usize {
    h.state
        .store
        .audit_chain_durable(h.tenant, 0, i64::MAX)
        .await
        .unwrap()
        .into_iter()
        .filter(|row| row.target.kind == "mse-inventory" && row.action == agf_core::audit::AuditAction::Update)
        .count()
}

/// Existing successful evidence is copied only to exercise the bounded ledger;
/// the complete lifecycle and every replay assertion still use real HTTP routes.
pub(crate) async fn fill_capacity(h: &Harness) -> Vec<Value> {
    let mut record = ledger(h).await.unwrap();
    let template = record["runs"].as_object().unwrap().values().next().unwrap().clone();
    let mut requests = Vec::new();
    while record["runs"].as_object().unwrap().len() < 512 {
        let request = body(1);
        let id = request["request_id"].as_str().unwrap();
        let mut run = template.clone();
        let input: agf_api::mse_inventory::contract::SyncInput = serde_json::from_value(request.clone()).unwrap();
        let scope: agf_api::mse_inventory::contract::Scope = serde_json::from_value(run["scope"].clone()).unwrap();
        run["request_id"] = request["request_id"].clone();
        run["claim_id"] = json!(Id::new());
        run["request_hash"] =
            json!(format!("{:x}", Sha256::digest(serde_json::to_vec(&json!({"input":input,"scope":scope})).unwrap())));
        record["runs"][id] = run;
        requests.push(request);
    }
    record["generation"] = json!(512);
    h.state
        .configurations
        .put(h.tenant, KIND, agf_api::integration_store::id(h.tenant, "alicloud-mse"), &record)
        .await
        .unwrap();
    requests
}

pub(crate) async fn asset_view(h: &Harness) -> Value {
    serde_json::to_value(h.state.store.asset_list_all_durable(h.tenant).await.unwrap()).unwrap()
}
