//! Known encrypted completion survives audit failure and parent cancellation; recovery is purely local.
use super::{
    gate::{Mode, Target, with_gate, with_pending_cleanup_fault},
    wire::Pending,
    *,
};
use agf_core::{
    credential::SecretMaterial,
    error::{DomainError, DomainResult},
    ids::Id,
};
use agf_storage::crypto::FieldCipher;
use secrecy::ExposeSecret;
use sha2::{Digest, Sha256};
use std::time::Duration;

pub(super) async fn pending_completion(
    f: &Fixture,
    preview: &Value,
    request: Id,
    pool: &sqlx::PgPool,
) -> DomainResult<Value> {
    let h = f.h.clone();
    let preview = preview.clone();
    with_gate(
        pool,
        h.tenant,
        Target { kind: "apig-policy-publication", id: request, action: "execute" },
        Mode::Reject,
        move |_| {
            Box::pin(async move {
                let result = post(&h, &format!("{BASE}/operations"), apply_input(&preview, request)?).await?;
                assert_eq!(result["cloudWrite"]["status"], "accepted");
                assert_eq!(result["readback"]["status"], "matched");
                assert_eq!(result["completionState"], "pending_audit");
                assert_eq!(result["status"], "uncertain");
                assert!(audits(&h, request, "apig-policy-publication").await?.is_empty());
                let pending = row(&h, PENDING, content_id(h.tenant, request, "pending")).await?;
                let material: SecretMaterial = serde_json::from_value(pending["completion"].clone())?;
                let aad = format!(
                    "{}|kind:apig-policy-publication:v1",
                    FieldCipher::make_aad(&h.tenant, &content_id(h.tenant, request, "pending"))
                );
                assert_eq!(material.aad.as_deref(), Some(aad.as_str()));
                let text = agf_api::model_gateway::cipher(&h.state)?.decrypt(&material)?;
                assert_eq!(pending["completion_hash"], hex::encode(Sha256::digest(text.expose_secret().as_bytes())));
                let value: Value = serde_json::from_str(text.expose_secret())?;
                assert_eq!(value["receipt"]["status"], "verified");
                assert_eq!(value["receipt"]["cloud_write"], "accepted");
                assert_eq!(value["receipt"]["readback"], "matched");
                assert_eq!(value["receipt"]["local_publication"], "pending_audit");
                Ok(result)
            })
        },
    )
    .await
}

#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_APIG_POLICY_PUBLICATION_DATABASE_OWNER"]
async fn failed_terminal_audit_retains_accepted_evidence_then_disabled_source_recovers_on_a_fresh_instance()
-> DomainResult<()> {
    let case = SqlCase::open("apig-pending-recover").await?;
    let f = Fixture::with_harness(case.h.clone()).await?;
    let preview = f.ready().await?;
    let request = Id::new();
    let pending = pending_completion(&f, &preview, request, &case.pool).await?;
    let cloud = provider(&f.h).await?.row;
    let original = row(&f.h, FACT, fact_id(f.h.tenant, request)).await?;
    configure(&f.h, 1, false, settings()).await?;
    let second = case.second_instance().await?;
    let before = snapshot(&second).await?;
    let view = read(&second, &receipt_path(request)).await?;
    assert_eq!(view["cloudWrite"], pending["cloudWrite"]);
    assert_eq!(view["sourceCurrent"], false);
    assert_eq!(snapshot(&second).await?, before);
    let recovered = post(&second, &format!("{}/recover", receipt_path(request)), json!({})).await?;
    assert_eq!(recovered["status"], "verified");
    assert_eq!(recovered["completionState"], "complete");
    assert_eq!(recovered["cloudWrite"], pending["cloudWrite"]);
    assert_eq!(recovered["readback"], pending["readback"]);
    assert_eq!(recovered["target"], pending["target"]);
    assert_eq!(recovered["sourcePolicyVersions"], pending["sourcePolicyVersions"]);
    assert_eq!(provider(&second).await?.row, cloud);
    let committed = row(&second, FACT, fact_id(second.tenant, request)).await?;
    for field in ["tenant", "request_id", "purpose", "request_hash", "scope", "created_at", "actor"] {
        assert_eq!(committed[field], original[field]);
    }
    assert!(second.state.configurations.list::<Value>(second.tenant, PENDING).await?.is_empty());
    let terminal = audits(&second, request, "apig-policy-publication").await?;
    assert_eq!(terminal.len(), 1);
    assert_eq!(serde_json::to_value(&terminal[0].actor)?, original["actor"]);
    let before = snapshot(&second).await?;
    assert_eq!(post(&second, &format!("{}/recover", receipt_path(request)), json!({})).await?, recovered);
    assert_eq!(post(&second, &format!("{BASE}/operations"), apply_input(&preview, request)?).await?, recovered);
    assert_eq!(snapshot(&second).await?, before);
    chain(&second).await?;
    case.pool.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_APIG_POLICY_PUBLICATION_DATABASE_OWNER"]
async fn foreign_aad_and_corrupt_ciphertext_are_rejected_before_recovery_or_audit_and_can_be_repaired_locally()
-> DomainResult<()> {
    let case = SqlCase::open("apig-pending-aad").await?;
    let f = Fixture::with_harness(case.h.clone()).await?;
    let preview = f.ready().await?;
    let request = Id::new();
    pending_completion(&f, &preview, request, &case.pool).await?;
    let id = content_id(f.h.tenant, request, "pending");
    let trusted = row(&f.h, PENDING, id).await?;
    let second = case.second_instance().await?;
    for field in ["aad", "ciphertext_b64"] {
        let mut corrupted = trusted.clone();
        corrupted["completion"][field] =
            json!(if field == "aad" { "foreign authenticated owner" } else { "invalid-base64!" });
        replace_owned_row(&second, &case.pool, PENDING, id, &corrupted).await?;
        let before = snapshot(&second).await?;
        assert!(second.get(&receipt_path(request)).await.status.is_server_error());
        assert!(second.post(&format!("{}/recover", receipt_path(request)), json!({})).await.status.is_server_error());
        assert_eq!(snapshot(&second).await?, before);
        assert_eq!(provider(&second).await?.calls("UpdatePolicy"), 1);
        assert!(audits(&second, request, "apig-policy-publication").await?.is_empty());
    }
    replace_owned_row(&second, &case.pool, PENDING, id, &trusted).await?;
    assert_verified(&post(&second, &format!("{}/recover", receipt_path(request)), json!({})).await?);
    assert_eq!(provider(&second).await?.calls("UpdatePolicy"), 1);
    chain(&second).await?;
    case.pool.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_APIG_POLICY_PUBLICATION_DATABASE_OWNER"]
async fn cancelling_a_delivered_put_stages_unknown_once_and_pending_cleanup_failure_cannot_unpublish_a_commit()
-> DomainResult<()> {
    let case = SqlCase::open("apig-parent-cancel").await?;
    let engine = Engine::start().await?;
    let f = loopback(case.h.clone(), &engine).await?;
    let preview = f.ready().await?;
    let request = Id::new();
    let (gate, _release) = engine.hold("PUT", 1)?;
    let pending =
        Pending::start(f.h.clone(), format!("{BASE}/operations"), f.h.admin.clone(), apply_input(&preview, request)?);
    gate.wait_entered().await?;
    assert_eq!(engine.counts()?, (6, 1));
    assert_eq!(engine.config()?["globalRules"][0]["limitValue"], 1250);
    drop(pending);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if f.h
                .state
                .configurations
                .get::<Value>(f.h.tenant, PENDING, content_id(f.h.tenant, request, "pending"))
                .await?
                .is_some()
            {
                break Ok::<_, DomainError>(());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| DomainError::Timeout("cancelled APIG result was not locally staged".into()))??;
    gate.release();
    let second = route(case.second_instance().await?, engine.address)?;
    let pending_id = content_id(second.tenant, request, "pending");
    let h = second.clone();
    with_pending_cleanup_fault(&case.pool, second.tenant, pending_id, move || {
        Box::pin(async move {
            let recovered = post(&h, &format!("{}/recover", receipt_path(request)), json!({})).await?;
            assert_eq!(recovered["status"], "uncertain");
            assert_eq!(recovered["cloudWrite"]["status"], "unknown");
            assert_eq!(recovered["completionState"], "complete");
            assert!(h.state.configurations.get::<Value>(h.tenant, PENDING, pending_id).await?.is_some());
            let before = snapshot(&h).await?;
            assert_eq!(post(&h, &format!("{}/recover", receipt_path(request)), json!({})).await?, recovered);
            assert_eq!(post(&h, &format!("{BASE}/operations"), apply_input(&preview, request)?).await?, recovered);
            assert_eq!(snapshot(&h).await?, before);
            Ok(())
        })
    })
    .await?;
    assert_eq!(engine.counts()?, (6, 1));
    assert_eq!(audits(&second, request, "apig-policy-publication").await?.len(), 1);
    assert_eq!(read(&second, BASE).await?["unresolvedOperationId"], json!(request));
    chain(&second).await?;
    case.pool.close().await;
    Ok(())
}
