//! Source pages use trusted current records and leave provider, workflow and audit state unchanged.
mod common;
use agf_core::error::{DomainError, DomainResult};
use common::*;

const BASE: &str = "/api/v1/alicloud/apig/policy-publication";

async fn state(h: &Harness, query: &str) -> DomainResult<Value> {
    let response = h.get(&format!("{BASE}{query}")).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    Ok(serde_json::from_slice(&response.bytes)?)
}

async fn snapshot(h: &Harness) -> DomainResult<Value> {
    let mut rows = BTreeMap::new();
    for kind in [
        "apig-policy-publication-state",
        "apig-policy-publication-fact",
        "apig-policy-publication-detail",
        "apig-policy-publication-preview",
        "apig-policy-publication-pending",
        "apig-policy-driver-mock",
        "cloud-integration",
        "signed-policy-registry",
        "quota-definitions",
    ] {
        rows.insert(kind, h.state.configurations.list::<Value>(h.tenant, kind).await?);
    }
    Ok(json!({"rows":rows,"audit":h.state.store.audit_chain_durable(h.tenant,0,i64::MAX).await?}))
}

fn items(value: &Value) -> DomainResult<&Vec<Value>> {
    value["sources"]["items"].as_array().ok_or_else(|| DomainError::Internal("source rows absent".into()))
}

#[tokio::test]
async fn more_than_one_hundred_sources_are_accessible_and_filtered_before_pagination() -> DomainResult<()> {
    let h = setup().await;
    let quota = h
        .post(
            "/api/v1/quotas",
            json!({"name":"owned-pagination-quota","expected_version":0,
        "scope":"tenant","dimension":"tokens","window":"minute","limit":1200,
        "soft_threshold":0,"action":"deny","enabled":true}),
        )
        .await;
    assert_eq!(quota.status, StatusCode::OK, "{}", quota.text);
    let quota = quota.json()["quota"]["id"].clone();
    for index in 0..107 {
        let response = h
            .post(
                "/api/v1/policies",
                json!({"expected_version":0,
            "name":format!("owned-pagination-{index:03}"),"language":"structured","structured":{},
            "action":"quota","enabled":index>=3,"dry_run":false,"intercept_points":["ai-gateway"],
            "quota_id":quota}),
            )
            .await;
        assert_eq!(response.status, StatusCode::CREATED, "{}", response.text);
    }
    let before = snapshot(&h).await?;
    let first = state(&h, "?source_page=1&source_page_size=100&source_eligible_only=true").await?;
    let second = state(&h, "?source_page=2&source_page_size=100&source_eligible_only=true").await?;
    assert_eq!(first["sources"]["total"], 104);
    assert_eq!(first["sources"]["eligibleCount"], 104);
    assert_eq!(first["sources"]["totalPages"], 2);
    assert_eq!(first["sources"]["truncated"], true);
    assert_eq!(second["sources"]["page"], 2);
    assert_eq!(second["sources"]["truncated"], false);
    assert_eq!(items(&first)?.len(), 100);
    assert_eq!(items(&second)?.len(), 4);
    let rows = items(&first)?.iter().chain(items(&second)?.iter()).collect::<Vec<_>>();
    for (index, row) in rows.iter().enumerate() {
        assert_eq!(row["name"], format!("owned-pagination-{:03}", index + 3));
        assert_eq!(row["eligible"], true);
        assert_eq!(row["version"], row["source"]["policyVersion"]);
        assert_eq!(row["policyId"], row["source"]["policyId"]);
    }
    let all = state(&h, "?source_page_size=2").await?;
    assert!(all["sources"]["policyCount"].as_u64().is_some_and(|count| count >= 107));
    assert_eq!(all["sources"]["total"], all["sources"]["policyCount"]);
    let distant = state(&h, "?source_page=4294967295&source_eligible_only=true").await?;
    assert!(items(&distant)?.is_empty());
    assert_eq!(distant["sources"]["total"], 104);
    assert_eq!(snapshot(&h).await?, before);
    assert!(h.state.store.audit_verify_durable(h.tenant).await?.passed);
    Ok(())
}

#[tokio::test]
async fn invalid_source_queries_are_rejected_without_seeding_or_mutating_local_records() -> DomainResult<()> {
    let h = setup().await;
    let before = snapshot(&h).await?;
    for query in [
        "source_page=0",
        "source_page=-1",
        "source_page=4294967296",
        "source_page_size=0",
        "source_page_size=101",
        "source_eligible_only=1",
        "source_eligible_only=null",
        "source_unknown=1",
    ] {
        let response = h.get(&format!("{BASE}?{query}")).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{query}: {}", response.text);
        assert!(response.content_type().starts_with("application/problem+json"));
        assert_eq!(response.json()["status"], 400);
        assert_eq!(snapshot(&h).await?, before);
    }
    let empty = state(&h, "?source_eligible_only=true").await?;
    assert!(items(&empty)?.is_empty());
    assert_eq!(empty["sources"]["policyCount"], 0);
    assert_eq!(snapshot(&h).await?, before);
    Ok(())
}
