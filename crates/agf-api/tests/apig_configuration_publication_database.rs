//! Owned PostgreSQL and independent AppStates; no provider or production database.
mod apig_configuration_publication_database_support;
mod apig_configuration_publication_support;
mod common;
use agf_core::{credential::SecretMaterial, error::DomainResult, ids::Id};
use apig_configuration_publication_database_support::{
    SqlCase,
    gate::{Mode, Target, with_gate},
};
use apig_configuration_publication_support::*;
use common::*;
use secrecy::ExposeSecret;

struct Pending(tokio::task::JoinHandle<common::Resp>);
impl Drop for Pending {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL + AGF_APIG_CONFIGURATION_DATABASE_OWNER"]
async fn two_instances_share_one_consumed_preview_one_write_and_permanent_uuid() -> DomainResult<()> {
    let case = SqlCase::open("apig-cfg-two").await?;
    let h = &case.h;
    configure(h, 0, true, settings("models")).await?;
    let p = ready(h, "models").await?;
    let second = case.second_instance().await?;
    let path = format!("{BASE}/operations");
    let a = Id::new();
    let b = Id::new();
    let (ra, rb) = tokio::join!(h.post(&path, apply_body(&p, a)?), second.post(&path, apply_body(&p, b)?));
    assert!(matches!(
        (ra.status, rb.status),
        (StatusCode::OK, StatusCode::CONFLICT) | (StatusCode::CONFLICT, StatusCode::OK)
    ));
    let winner = if ra.status == StatusCode::OK { a } else { b };
    let result = get(&second, &receipt(winner)).await?;
    verified(&result);
    assert_eq!(result["cloudWrite"]["providerRequestId"], "mock-configuration-update-1");
    let before = snapshot(&second).await?;
    assert_eq!(apply(&second, &p, winner).await?, result);
    assert_eq!(snapshot(&second).await?, before);
    assert_eq!(terminal_count(&second, winner).await?, 1);
    assert!(second.state.store.audit_verify_durable(second.tenant).await?.passed);
    case.pool.close().await;
    Ok(())
}
#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL + AGF_APIG_CONFIGURATION_DATABASE_OWNER"]
async fn terminal_audit_failure_keeps_encrypted_evidence_then_disabled_source_recovers_without_a_second_write()
-> DomainResult<()> {
    let case = SqlCase::open("apig-cfg-pending").await?;
    let h = &case.h;
    configure(h, 0, true, settings("content")).await?;
    let p = ready(h, "content").await?;
    let request = Id::new();
    let owned = h.clone();
    let prepared = p.clone();
    let pending = with_gate(
        &case,
        h.tenant,
        Target { kind: "apig-configuration-publication", id: request, action: "execute" },
        Mode::Reject,
        move |_| Box::pin(async move { apply(&owned, &prepared, request).await }),
    )
    .await?;
    assert_eq!(pending["completionState"], "pending_audit");
    assert_eq!(pending["cloudWrite"]["status"], "accepted");
    assert_eq!(pending["status"], "uncertain");
    assert_eq!(terminal_count(h, request).await?, 0);
    let rows = h.state.configurations.list::<Value>(h.tenant, PENDING).await?;
    assert_eq!(rows.len(), 1);
    let secret: SecretMaterial = serde_json::from_value(rows[0]["completion"].clone())?;
    let known = agf_api::model_gateway::cipher(&h.state)?.decrypt(&secret)?;
    let known: Value = serde_json::from_str(known.expose_secret())?;
    assert_eq!(known["receipt"]["status"], "verified");
    configure(h, 1, false, settings("content")).await?;
    let second = case.second_instance().await?;
    let before = snapshot(&second).await?;
    let read = get(&second, &receipt(request)).await?;
    assert_eq!(read["sourceCurrent"], false);
    assert_eq!(snapshot(&second).await?, before);
    let recovered = post(&second, &format!("{}/recover", receipt(request)), json!({})).await?;
    verified(&recovered);
    assert_eq!(recovered["cloudWrite"], pending["cloudWrite"]);
    assert_eq!(terminal_count(&second, request).await?, 1);
    assert!(second.state.configurations.list::<Value>(second.tenant, PENDING).await?.is_empty());
    let before = snapshot(&second).await?;
    assert_eq!(post(&second, &format!("{}/recover", receipt(request)), json!({})).await?, recovered);
    assert_eq!(snapshot(&second).await?, before);
    case.pool.close().await;
    Ok(())
}
#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL + AGF_APIG_CONFIGURATION_DATABASE_OWNER"]
async fn audit_claim_rejection_rolls_back_uuid_and_preview_consumption_without_provider_changes() -> DomainResult<()> {
    let case = SqlCase::open("apig-cfg-claim").await?;
    let h = &case.h;
    configure(h, 0, true, settings("content")).await?;
    let p = ready(h, "content").await?;
    let request = Id::new();
    let before = snapshot(h).await?;
    let owned = h.clone();
    let prepared = p.clone();
    with_gate(
        &case,
        h.tenant,
        Target { kind: "apig-configuration-publication-claim", id: request, action: "configure" },
        Mode::Reject,
        move |_| {
            Box::pin(async move {
                let r = owned.post(&format!("{BASE}/operations"), apply_body(&prepared, request)?).await;
                assert!(r.status.is_server_error());
                Ok(())
            })
        },
    )
    .await?;
    assert_eq!(snapshot(h).await?, before);
    assert_eq!(h.get(&receipt(request)).await.status, StatusCode::NOT_FOUND);
    verified(&apply(h, &p, request).await?);
    assert_eq!(terminal_count(h, request).await?, 1);
    case.pool.close().await;
    Ok(())
}
#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL + AGF_APIG_CONFIGURATION_DATABASE_OWNER"]
async fn fresh_state_hides_foreign_receipts_and_crypto_failure_is_pure_fail_closed() -> DomainResult<()> {
    let case = SqlCase::open("apig-cfg-crypto").await?;
    let h = &case.h;
    configure(h, 0, true, settings("models")).await?;
    let p = ready(h, "models").await?;
    let request = Id::new();
    verified(&apply(h, &p, request).await?);
    let foreign = case.foreign_instance().await?;
    assert_eq!(foreign.get(&receipt(request)).await.status, StatusCode::NOT_FOUND);
    let rows = h.state.configurations.list::<Value>(h.tenant, MOCK).await?;
    assert_eq!(rows.len(), 1);
    let original = &rows[0];
    let record: Id = serde_json::from_value(original["id"].clone())?;
    case.check().await?;
    let mut bad = original.clone();
    bad["secret"]["aad"] = json!("foreign-authenticated-owner");
    h.state.configurations.put(h.tenant, MOCK, record, &bad).await?;
    let outcome = async {
        let before = snapshot(h).await?;
        let r = h.post(&format!("{BASE}/observe"), json!({"request_id":Id::new(),"configuration_version":1})).await;
        assert!(r.status.is_server_error());
        let snapshot_after = snapshot(h).await?;
        assert_eq!(snapshot_after["rows"][MOCK], before["rows"][MOCK]);
        assert_eq!(terminal_count(h, request).await?, 1);
        Ok::<_, agf_core::error::DomainError>(())
    }
    .await;
    case.check().await?;
    h.state.configurations.put(h.tenant, MOCK, record, original).await?;
    outcome?;
    let second = case.second_instance().await?;
    verified(&get(&second, &receipt(request)).await?);
    let before = snapshot(&second).await?;
    get(&second, BASE).await?;
    get(&second, &receipt(request)).await?;
    assert_eq!(snapshot(&second).await?, before);
    case.pool.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL + AGF_APIG_CONFIGURATION_DATABASE_OWNER"]
async fn task_write_scope_revoked_during_claim_audit_wait_rolls_back_every_business_row() -> DomainResult<()> {
    let case = SqlCase::open("apig-cfg-revoke").await?;
    let h = &case.h;
    configure(h, 0, true, settings("content")).await?;
    let p = ready(h, "content").await?;
    let key = h
        .post(
            "/api/v1/settings/api-keys",
            json!({"name":format!("owned-config-key-{}",Id::new()),"scopes":["alicloud:read","alicloud:write"]}),
        )
        .await;
    assert_eq!(key.status, StatusCode::CREATED);
    let key = key.json();
    let key_id = id(&key["api_key"], "id")?;
    let token = key["plaintext"]
        .as_str()
        .ok_or_else(|| agf_core::error::DomainError::Internal("owned key missing".into()))?
        .to_owned();
    let request = Id::new();
    let before = snapshot(h).await?;
    let owned = h.clone();
    let pool = case.pool.clone();
    let tenant = h.tenant;
    let input = apply_body(&p, request)?;
    with_gate(&case,tenant,Target{kind:"apig-configuration-publication-claim",id:request,action:"configure"},Mode::Wait,
        move |gate| Box::pin(async move {
            let mut pending=Pending(tokio::spawn(async move {owned.request("POST",&format!("{BASE}/operations"),Some(&token),Some(input)).await}));
            gate.waiting().await?;
            let affected=sqlx::query("UPDATE api_keys SET scopes=scopes-'alicloud:write',updated_at=now() WHERE tenant_id=$1 AND id=$2 AND NOT revoked AND deleted_at IS NULL")
                .bind(tenant.as_uuid()).bind(key_id.as_uuid()).execute(&pool).await.map_err(apig_configuration_publication_database_support::sql)?.rows_affected();
            assert_eq!(affected,1);gate.release().await?;
            let r=(&mut pending.0).await.map_err(|_|agf_core::error::DomainError::Internal("owned pending request failed".into()))?;
            assert_eq!(r.status,StatusCode::FORBIDDEN);Ok(())
        })).await?;
    assert_eq!(snapshot(h).await?, before);
    assert_eq!(h.get(&receipt(request)).await.status, StatusCode::NOT_FOUND);
    case.pool.close().await;
    Ok(())
}
