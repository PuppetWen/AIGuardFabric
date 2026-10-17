//! Owned offline fixtures have explicit target settings and synthetic signing keys.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use crate::{integration_store, state::AppState};
use agf_core::{
    ids::{Id, TenantId},
    policy::Policy,
    time::Timestamp,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub(super) fn state(mocked: bool) -> AppState {
    let mut env: BTreeMap<String, String> = [
        ("AGF_ENV", "test"),
        ("AGF_MOCK_MODE", if mocked { "1" } else { "0" }),
        ("AGF_JWT_SECRET", "nacos-foundation-owned-secret-at-least-32-bytes"),
        ("AGF_MASTER_KEY_BASE64", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="),
        ("AGF_PROJECT_ROOT", "."),
    ]
    .into_iter()
    .map(|(key, value)| (key.into(), value.into()))
    .collect();
    let data = std::env::var_os("AGF_TEST_DATA_DIR").map_or_else(
        || std::path::PathBuf::from("./target/test-data/nacos-foundation"),
        |root| std::path::PathBuf::from(root).join("nacos-foundation"),
    );
    env.insert("AGF_DATA_DIR".into(), data.to_string_lossy().into_owned());
    AppState::offline(agf_core::config::from_env_map(&env).unwrap()).unwrap()
}
pub(super) fn settings() -> Value {
    json!({"engine_origin":"https://mse-agf-demo.invalid","region_id":"cn-hangzhou",
        "instance_id":"inst-demo","namespace_id":"","config_group":"AGF",
        "config_data_id":"agf-policies.json","config_dialect":"nacos-http-v2-cas",
        "managed_upsert_confirmed":true})
}
pub(super) fn row(state: &AppState, tenant: TenantId, settings: Value, mocked: bool) -> integration_store::Stored {
    let private =
        integration_store::Private { settings: serde_json::from_value(settings).unwrap(), secrets: BTreeMap::new() };
    let name = agf_core::enums::AliCloudService::Mse.as_str();
    let id = integration_store::id(tenant, name);
    integration_store::Stored {
        id,
        name: name.into(),
        enabled: true,
        mock: mocked,
        version: 1,
        updated_at: Timestamp::now(),
        private: crate::model_gateway::encrypt(state, tenant, id, serde_json::to_string(&private).unwrap()).unwrap(),
    }
}
pub(super) fn scope(state: &AppState) -> contract::Scope {
    let tenant = TenantId::default_tenant();
    scope::from_row(state, tenant, &row(state, tenant, settings(), true), &Registry::default()).unwrap()
}
pub(super) fn policy(state: &AppState, name: &str) -> Policy {
    let now = Timestamp::now();
    let mut row: Policy = serde_json::from_value(json!({
        "id":Id::new(),"tenant_id":TenantId::default_tenant(),"name":name,
        "language":"cel","source":"{}","action":"deny","priority":1,
        "enabled":true,"content_hash":"","signature":"","version":1,
        "created_at":now,"updated_at":now,"intercept_points":["mcp-proxy"]
    }))
    .unwrap();
    row.content_hash = row.compute_hash();
    row.signature = crate::policy_store::signer(state).unwrap().sign(&row);
    row
}
