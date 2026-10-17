//! Runtime quota edits must preserve usage and reject stale or unversioned writes.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_api::{model_routes::tenant_record_id, quota_definitions, runtime_quota};
use agf_core::{
    asset::Asset,
    audit::AuditOutcome,
    enums::{AssetKind, QuotaDimension},
    ids::Id,
    quota::{Quota, QuotaConsumption},
};
use common::*;

const PATH: &str = "/api/v1/quotas";

fn update(name: &str, limit: i64, version: Option<u64>) -> Value {
    let mut body = json!({"name":name,"dimension":"requests","scope":"tenant","window":"total","limit":limit});
    if let Some(version) = version {
        body["expected_version"] = json!(version);
    }
    body
}

async fn entry(h: &Harness, name: &str) -> Value {
    let response = h.get(PATH).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    response.json()["items"].as_array().unwrap().iter().find(|row| row["quota"]["name"] == name).unwrap().clone()
}

async fn consume(h: &Harness) -> agf_core::error::DomainResult<runtime_quota::Lease> {
    runtime_quota::Lease::acquire(
        &h.state,
        h.tenant,
        None,
        "version-test",
        "quota-test",
        &QuotaConsumption::one_request(),
    )
    .await
}

#[tokio::test]
async fn editing_requires_current_version_preserves_usage_and_audits_only_success() {
    let h = setup().await;
    let created = h.post(PATH, update("protected", 3, None)).await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text);
    assert_eq!(created.json()["quota"]["version"], 1);
    let original = created.json()["quota"].clone();
    consume(&h).await.unwrap().finish(None).await.unwrap();

    let edited = h.post(PATH, update("protected", 1, Some(1))).await;
    assert_eq!(edited.status, StatusCode::OK, "{}", edited.text);
    assert_eq!(edited.json()["quota"]["version"], 2);
    assert_eq!(edited.json()["quota"]["id"], original["id"]);
    assert_eq!(edited.json()["quota"]["created_at"], original["created_at"]);
    let current = entry(&h, "protected").await;
    assert_eq!(current["used"], 1);
    assert_eq!(current["remaining"], 0);
    assert!(consume(&h).await.is_err(), "lowered limit must use the already consumed request");

    let missing = h.post(PATH, update("protected", 100, None)).await;
    assert_eq!(missing.status, StatusCode::BAD_REQUEST, "{}", missing.text);
    let stale = h.post(PATH, update("protected", 100, Some(1))).await;
    assert_eq!(stale.status, StatusCode::CONFLICT, "{}", stale.text);
    assert_eq!(entry(&h, "protected").await, current);
    assert!(consume(&h).await.is_err(), "a rejected stale edit must not raise the limit");

    let read_key = h.state.api_keys.issue(ApiKeyIssueRequest {
        scopes: vec![Permission::from_raw("quotas:read")],
        ..ApiKeyIssueRequest::named(h.tenant, "read-quota-config", Timestamp::now())
    });
    h.state.store.api_key_insert(read_key.record).unwrap();
    let reader = h.request("GET", PATH, Some(&read_key.plaintext), None).await;
    assert_eq!(reader.status, StatusCode::OK);
    assert!(reader.json()["items"].as_array().unwrap().iter().all(|row| row["quota"]["version"].is_u64()));
    let denied = h.request("POST", PATH, Some(&read_key.plaintext), Some(update("protected", 100, Some(2)))).await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);
    let audits = h.state.store.audit_chain(h.tenant, 0, 1000).unwrap();
    let quota_audits: Vec<_> = audits
        .iter()
        .filter(|row| row.target.kind == "quota" && row.target.name.as_deref() == Some("protected"))
        .collect();
    assert_eq!(quota_audits.len(), 2);
    assert!(quota_audits.iter().all(|row| row.outcome == AuditOutcome::Success && row.actor.id.is_some()));
    assert_eq!(quota_audits[1].after.as_ref().unwrap()["limit"], 1);
}

#[tokio::test]
async fn simultaneous_edits_have_one_winner_and_versions_are_tenant_scoped() {
    let h = setup().await;
    assert_eq!(h.post(PATH, update("shared-name", 5, Some(0))).await.status, StatusCode::OK);
    let (left, right) =
        tokio::join!(h.post(PATH, update("shared-name", 7, Some(1))), h.post(PATH, update("shared-name", 9, Some(1))));
    let statuses = [left.status, right.status];
    assert_eq!(statuses.iter().filter(|status| **status == StatusCode::OK).count(), 1);
    assert_eq!(statuses.iter().filter(|status| **status == StatusCode::CONFLICT).count(), 1);
    let current = entry(&h, "shared-name").await;
    let winner = if left.status == StatusCode::OK { left.json() } else { right.json() };
    assert_eq!(current["quota"], winner["quota"]);
    assert_eq!(current["quota"]["version"], 2);
    let audits = h.state.store.audit_chain(h.tenant, 0, 1000).unwrap();
    assert_eq!(
        audits
            .iter()
            .filter(|row| row.target.kind == "quota" && row.target.name.as_deref() == Some("shared-name"))
            .count(),
        2
    );

    let bearer = format!("Bearer {}", h.admin);
    let other = h.other_tenant.to_string();
    let headers = [("authorization", bearer.as_str()), ("x-agf-tenant", other.as_str())];
    let wrong_version = h.request_with("POST", PATH, &headers, Some(update("shared-name", 100, Some(2)))).await;
    assert_eq!(wrong_version.status, StatusCode::CONFLICT);
    let isolated = h.request_with("POST", PATH, &headers, Some(update("shared-name", 2, Some(0)))).await;
    assert_eq!(isolated.status, StatusCode::OK, "{}", isolated.text);
    assert_eq!(isolated.json()["quota"]["version"], 1);
    assert_ne!(isolated.json()["quota"]["id"], current["quota"]["id"]);
    assert_eq!(entry(&h, "shared-name").await, current);
}

#[tokio::test]
async fn legacy_definitions_start_at_zero_and_internal_writes_advance_the_api_version() {
    let h = setup().await;
    let mut legacy = Quota::tenant_default(h.tenant, QuotaDimension::Requests, 10);
    legacy.name = "legacy".into();
    legacy.id = Id::new();
    let record = json!({"initialized":true,"entries":{"legacy":legacy}});
    let key = tenant_record_id(h.tenant);
    h.state.configurations.put(h.tenant, "quota-definitions", key, &record).await.unwrap();
    assert_eq!(entry(&h, "legacy").await["quota"]["version"], 0);
    assert_eq!(h.post(PATH, update("legacy", 8, None)).await.status, StatusCode::BAD_REQUEST);
    let saved = h.post(PATH, update("legacy", 8, Some(0))).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    assert_eq!(saved.json()["quota"]["id"], json!(legacy.id));
    assert_eq!(saved.json()["quota"]["version"], 1);

    legacy.limit = 6;
    let internal = quota_definitions::save(&h.state, h.tenant, legacy.clone()).await.unwrap();
    assert_eq!(internal.id, legacy.id);
    assert_eq!(entry(&h, "legacy").await["quota"]["version"], 2);
    assert_eq!(h.post(PATH, update("legacy", 99, Some(1))).await.status, StatusCode::CONFLICT);
    assert_eq!(quota_definitions::list(&h.state, h.tenant).await.unwrap()[0].limit, 6);

    h.state
        .configurations
        .mutate::<Value, _>(h.tenant, "quota-definitions", key, |registry| {
            registry["versions"]["legacy"] = json!(u64::MAX);
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(h.post(PATH, update("legacy", 99, Some(u64::MAX))).await.status, StatusCode::CONFLICT);
    assert_eq!(entry(&h, "legacy").await["quota"]["limit"], 6);
}

#[tokio::test]
async fn targeted_quota_rejects_foreign_or_non_agent_assets_and_limits_only_its_agent() {
    let h = setup().await;
    let agent = Asset::new(h.tenant, AssetKind::Agent, "worker-one", "quota-worker-one");
    let other_agent = Asset::new(h.tenant, AssetKind::Agent, "worker-two", "quota-worker-two");
    let skill = Asset::new(h.tenant, AssetKind::Skill, "skill", "quota-skill");
    let foreign = Asset::new(h.other_tenant, AssetKind::Agent, "foreign", "quota-foreign");
    for asset in [&agent, &other_agent, &skill, &foreign] {
        h.state.store.asset_upsert(asset).unwrap();
    }
    let targeted = |target: Id, scope: &str| json!({"name":"worker-one-only","scope":scope,"target_id":target,"dimension":"requests","window":"total","limit":1,"expected_version":0});
    for body in [
        targeted(skill.id, "agent"),
        targeted(foreign.id, "agent"),
        targeted(Id::new(), "agent"),
        targeted(agent.id, "tenant"),
        targeted(agent.id, "session"),
    ] {
        assert_eq!(h.post(PATH, body).await.status, StatusCode::BAD_REQUEST);
    }
    let saved = h.post(PATH, targeted(agent.id, "agent")).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    assert_eq!(saved.json()["quota"]["target_id"], json!(agent.id));
    for (asset, allowed) in [(agent.id, true), (agent.id, false), (other_agent.id, true), (other_agent.id, true)] {
        let lease = runtime_quota::Lease::acquire(
            &h.state,
            h.tenant,
            Some(asset),
            "worker-test",
            "quota-test",
            &QuotaConsumption::one_request(),
        )
        .await;
        assert_eq!(lease.is_ok(), allowed, "unexpected quota result for {asset}: {lease:?}");
        if let Ok(lease) = lease {
            lease.finish(None).await.unwrap();
        }
    }
}

#[tokio::test]
async fn default_soft_threshold_rounds_eighty_percent_down_without_overflow() {
    let h = setup().await;
    for (limit, expected) in [(9, 7), (19, 15), (i64::MAX, 7_378_697_629_483_820_645_i64)] {
        let saved = h.post(PATH, update(&format!("threshold-{limit}"), limit, Some(0))).await;
        assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
        assert_eq!(saved.json()["quota"]["soft_threshold"], expected);
    }
}

#[tokio::test]
async fn openapi_describes_conditional_quota_edits_and_targeted_agent_rules() {
    let h = setup().await;
    let response = h.get("/api/v1/openapi.json").await;
    assert_eq!(response.status, StatusCode::OK);
    let document = response.json();
    let post = &document["paths"][PATH]["post"];
    assert_eq!(post["requestBody"]["content"]["application/json"]["schema"]["$ref"], "#/components/schemas/QuotaBody");
    assert!(post["responses"]["409"]["description"].is_string());
    assert_eq!(post["x-required-permissions"], json!(["quotas:write"]));
    let properties = &document["components"]["schemas"]["QuotaBody"]["properties"];
    assert_eq!(properties["expected_version"]["minimum"], 0);
    assert!(properties["target_id"]["description"].as_str().unwrap().contains("Agent"));
    assert_eq!(document["components"]["schemas"]["VersionedRuntimeQuota"]["properties"]["version"]["minimum"], 0);
}
