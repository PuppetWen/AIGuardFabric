//! Offline console filtering follows the same multi-select, search and sort contract as SQL.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::{
    enums::{RiskDomain, Severity},
    risk::Finding,
};
use common::*;

#[tokio::test]
async fn selections_search_sort_and_exact_severity_are_consistent() {
    let h = setup().await;
    for (title, domain, severity) in [
        ("first", RiskDomain::PromptAttack, Severity::High),
        ("second", RiskDomain::ToolAbuse, Severity::Low),
        ("third", RiskDomain::CredentialLeak, Severity::Critical),
    ] {
        let finding = Finding::new(h.tenant, domain, severity, "fixture", title, "summary", "fix");
        h.state.store.finding_insert(&finding).unwrap();
    }
    let result = h
        .get("/api/v1/findings?domain=prompt-attack,tool-abuse&severity=high,low&state=pending,verified&sort=severity")
        .await;
    assert_eq!(result.status, StatusCode::OK, "{}", result.text);
    assert_eq!(result.json()["total"], 2);
    assert_eq!(result.json()["items"][0]["title"], "second");
    assert_eq!(h.get("/api/v1/findings?severity=high").await.json()["total"], 1);
    assert_eq!(h.get("/api/v1/findings?min_severity=high").await.json()["total"], 2);
    assert_eq!(h.get("/api/v1/findings?q=second").await.json()["total"], 1);
    assert_eq!(h.get("/api/v1/findings?state=verified").await.json()["total"], 0);
    assert_eq!(h.get("/api/v1/findings?severity=invalid").await.status, StatusCode::BAD_REQUEST);
}
