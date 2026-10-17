//! Owned SQL proves rollback and cross-instance CAS through the real rule/Skill handlers.
mod common;
mod rule_skill_publication_support;
use agf_core::ids::Id;
use common::*;
use rule_skill_publication_support::SqlCase;
type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

fn yaml() -> &'static str {
    "key: OWNED-SQL\nname: Owned SQL\ndomain: prompt-attack\nseverity: high\nkind: keyword\ntarget: prompt\naction: deny\ndetection:\n  type: keyword\n  any: [ownedSqlMarker]\nsamples:\n  positive: [ownedSqlMarker]\n  negative: [clean]\n"
}
async fn skill(h: &Harness) -> Result<Id, Box<dyn std::error::Error + Send + Sync>> {
    let response = h
        .post(
            "/api/v1/assets/register",
            json!({"request_id":Id::new(),"kind":"skill",
        "fingerprint":"owned-sql-skill","name":"Owned SQL Skill","owner":"Reviewer",
        "data_class":"internal","note":"Owned SQL fixture"}),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    Ok(serde_json::from_value(response.json()["asset"]["id"].clone())?)
}
async fn snapshot(h: &Harness, id: Id) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
    let rules: Vec<Value> = h.state.configurations.list(h.tenant, "detection-rules").await?;
    Ok(json!({"rules":rules,"asset":h.state.store.asset_get_durable(h.tenant,id).await?,
        "history":h.state.store.asset_changes_durable(h.tenant,id,1000).await?,
        "audit":h.state.store.audit_chain_durable(h.tenant,0,i64::MAX).await?}))
}
#[derive(Clone, Copy)]
enum Mutation {
    Publish,
    Patch,
    Restore,
    Review,
    Allowlist,
}
async fn failure(mutation: Mutation) -> TestResult {
    let case = SqlCase::open("rule-skill-audit").await?;
    let response = case.h.post("/api/v1/rules", json!({"yaml":yaml(),"expectedVersion":0})).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    let id = skill(&case.h).await?;
    let current = case.h.state.store.asset_get_durable(case.h.tenant, id).await?.ok_or("Skill missing")?;
    let before = snapshot(&case.h, id).await?;
    let second = case.second().await?;
    let (method, uri, body) = match mutation {
        Mutation::Publish => (
            "POST",
            "/api/v1/rules".into(),
            json!({"yaml":yaml().replace("OWNED-SQL","OWNED-NEW"),"expectedVersion":0}),
        ),
        Mutation::Patch => ("PATCH", "/api/v1/rules/OWNED-SQL".into(), json!({"enabled":false,"expectedVersion":1})),
        Mutation::Restore => ("POST", "/api/v1/rules/OWNED-SQL/versions/1/restore?expectedVersion=1".into(), json!({})),
        Mutation::Review => (
            "POST",
            format!("/api/v1/skills/{id}/status"),
            json!({"to":"under-review","note":"Reviewed","expectedUpdatedAt":current.updated_at}),
        ),
        Mutation::Allowlist => (
            "PUT",
            format!("/api/v1/skills/{id}/whitelist"),
            json!({"domains":["owned.test"],"paths":[],"expectedUpdatedAt":current.updated_at}),
        ),
    };
    let gate = case.reject_audit().await?;
    let response = case.h.request(method, &uri, Some(&case.h.admin), Some(body)).await;
    // Remove the owned fault before assertions, so a failed assertion does not strand its DDL.
    case.release_audit(&gate).await?;
    assert!(response.status.is_server_error(), "Valid candidate must reach audit rejection: {}", response.text);
    assert_eq!(snapshot(&case.h, id).await?, before);
    assert_eq!(
        snapshot(&second, id).await?,
        before,
        "Fresh instance must see no failed business/history/audit changes"
    );
    case.pool.close().await;
    Ok(())
}
#[tokio::test]
#[ignore = "requires exact full-UUID loopback DB, COMMENT owner and OID env"]
async fn rule_publish_audit_failure_rolls_back_registry_and_history() -> TestResult {
    failure(Mutation::Publish).await
}
#[tokio::test]
#[ignore = "requires exact full-UUID loopback DB, COMMENT owner and OID env"]
async fn rule_patch_audit_failure_rolls_back_registry_and_history() -> TestResult {
    failure(Mutation::Patch).await
}
#[tokio::test]
#[ignore = "requires exact full-UUID loopback DB, COMMENT owner and OID env"]
async fn rule_restore_audit_failure_rolls_back_registry_and_history() -> TestResult {
    failure(Mutation::Restore).await
}
#[tokio::test]
#[ignore = "requires exact full-UUID loopback DB, COMMENT owner and OID env"]
async fn skill_review_audit_failure_rolls_back_asset_and_history() -> TestResult {
    failure(Mutation::Review).await
}
#[tokio::test]
#[ignore = "requires exact full-UUID loopback DB, COMMENT owner and OID env"]
async fn skill_allowlist_audit_failure_rolls_back_asset_and_history() -> TestResult {
    failure(Mutation::Allowlist).await
}

#[tokio::test]
#[ignore = "requires exact full-UUID loopback DB, COMMENT owner and OID env"]
async fn independent_instances_have_one_rule_and_skill_cas_winner() -> TestResult {
    let case = SqlCase::open("rule-skill-cas").await?;
    let first = case.h.post("/api/v1/rules", json!({"yaml":yaml(),"expectedVersion":0})).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.text);
    let id = skill(&case.h).await?;
    let current = case.h.state.store.asset_get_durable(case.h.tenant, id).await?.ok_or("Skill missing")?;
    let second = case.second().await?;
    let before = case.h.state.store.audit_chain_durable(case.h.tenant, 0, i64::MAX).await?.len();
    let rule_body = json!({"enabled":false,"expectedVersion":1});
    let (left, right) = tokio::join!(
        case.h.request("PATCH", "/api/v1/rules/OWNED-SQL", Some(&case.h.admin), Some(rule_body.clone())),
        second.request("PATCH", "/api/v1/rules/OWNED-SQL", Some(&second.admin), Some(rule_body))
    );
    one_winner(&left, &right);
    let uri = format!("/api/v1/skills/{id}/whitelist");
    let skill_body = json!({"domains":["owned.test"],"paths":[],"expectedUpdatedAt":current.updated_at});
    let (left, right) = tokio::join!(
        case.h.request("PUT", &uri, Some(&case.h.admin), Some(skill_body.clone())),
        second.request("PUT", &uri, Some(&second.admin), Some(skill_body))
    );
    one_winner(&left, &right);
    let chain = case.h.state.store.audit_chain_durable(case.h.tenant, 0, i64::MAX).await?;
    assert_eq!(chain.len(), before + 2);
    assert!(chain.iter().all(agf_core::audit::AuditLog::verify));
    assert_eq!(snapshot(&case.h, id).await?, snapshot(&second, id).await?);
    case.pool.close().await;
    Ok(())
}
fn one_winner(left: &Resp, right: &Resp) {
    assert_eq!(
        [left.status, right.status].iter().filter(|status| **status == StatusCode::OK).count(),
        1,
        "{} / {}",
        left.text,
        right.text
    );
    assert_eq!(
        [left.status, right.status].iter().filter(|status| **status == StatusCode::CONFLICT).count(),
        1,
        "{} / {}",
        left.text,
        right.text
    );
}
