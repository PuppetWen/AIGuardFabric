use super::*;
use agf_storage::crypto::FieldCipher;
use futures::FutureExt;
use std::{future::Future, panic::AssertUnwindSafe};

pub(crate) async fn with_record<F, Fut>(
    f: &Fixture,
    kind: &str,
    id: Id,
    original: &Value,
    changed: &Value,
    action: F,
) -> DomainResult<()>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = DomainResult<()>> + Send,
{
    f.case.owner.check().await?;
    f.h.state.configurations.put(f.h.tenant, kind, id, changed).await?;
    let result = AssertUnwindSafe(action()).catch_unwind().await;
    // This is an exact task-owned reversible corruption, restored even when the assertion panics.
    f.case.owner.check().await?;
    let restored = f.h.state.configurations.put(f.h.tenant, kind, id, original).await;
    match result {
        Ok(value) => {
            restored?;
            value
        }
        Err(panic) => {
            if restored.is_err() {
                tracing::error!("Owned callback corruption restoration failed; details withheld");
            }
            std::panic::resume_unwind(panic)
        }
    }
}

pub(crate) async fn authenticated() -> DomainResult<()> {
    let f = Fixture::new("cb-auth-envelope").await?;
    let running = f.admit(f.input("asset-inventory", "owned-aead", 0, 1)).await?;
    f.start(&running).await?;
    let complete = f.complete(&running, good()).await?;
    let fact_id = native::identifier(&complete, "factId")?;
    let original = native::row(&f.h, EXECUTION, fact_id)
        .await?
        .ok_or_else(|| native::wire::fixture_error("sealed fact absent"))?;
    for foreign_aad in [false, true] {
        let mut changed = original.clone();
        if foreign_aad {
            changed["seal"]["secret"]["aad"] = json!(FieldCipher::make_aad(&TenantId::new(), &fact_id));
        } else {
            // Shape-valid cleartext tweak retains the original authenticated seal.
            changed["claim_id"] = json!(Id::new());
        }
        with_record(&f, EXECUTION, fact_id, &original, &changed, || {
            Box::pin(async {
                let prior = snapshot(&f.h).await?;
                assert_eq!(
                    f.h.request("GET", &fact_path(&complete)?, Some(&f.token), None).await.status,
                    StatusCode::INTERNAL_SERVER_ERROR
                );
                assert_eq!(snapshot(&f.h).await?, prior);
                Ok(())
            })
        })
        .await?;
    }
    let progress_id =
        deterministic_id("agf.scheduler.callback.progress.v1", &format!("{}:asset-inventory", f.h.tenant));
    let progress = native::row(&f.h, PROGRESS, progress_id)
        .await?
        .ok_or_else(|| native::wire::fixture_error("sealed progress absent"))?;
    for foreign_aad in [false, true] {
        let mut changed = progress.clone();
        if foreign_aad {
            changed["seal"]["secret"]["aad"] = json!(FieldCipher::make_aad(&TenantId::new(), &progress_id));
        } else {
            changed["batch"]["partitions"]["0"]["terminal"]["degraded"] = json!(true);
        }
        with_record(&f, PROGRESS, progress_id, &progress, &changed, || {
            Box::pin(async {
                let prior = snapshot(&f.h).await?;
                assert_eq!(
                    f.h.request(
                        "POST",
                        ROOT,
                        Some(&f.token),
                        Some(f.input("log-pull", "owned-no-forged-progress", 0, 1))
                    )
                    .await
                    .status,
                    StatusCode::INTERNAL_SERVER_ERROR
                );
                assert_eq!(snapshot(&f.h).await?, prior);
                Ok(())
            })
        })
        .await?;
    }
    let pending_id = pending_id(&complete)?;
    let pending = native::row(&f.h, PENDING, pending_id)
        .await?
        .ok_or_else(|| native::wire::fixture_error("authenticated pending absent"))?;
    for foreign_aad in [false, true] {
        let mut changed = pending.clone();
        if foreign_aad {
            changed["secret"]["aad"] = json!(FieldCipher::make_aad(&TenantId::new(), &pending_id));
        } else {
            changed["hash"] = json!("0".repeat(64));
        }
        with_record(&f, PENDING, pending_id, &pending, &changed, || {
            Box::pin(async {
                let prior = snapshot(&f.h).await?;
                assert_eq!(
                    f.h.request("GET", &fact_path(&complete)?, Some(&f.token), None).await.status,
                    StatusCode::INTERNAL_SERVER_ERROR
                );
                assert_eq!(
                    f.h.request(
                        "POST",
                        &format!("{}/complete", fact_path(&complete)?),
                        Some(&f.token),
                        Some(super::complete(&complete, good()))
                    )
                    .await
                    .status,
                    StatusCode::INTERNAL_SERVER_ERROR
                );
                assert_eq!(snapshot(&f.h).await?, prior);
                Ok(())
            })
        })
        .await?;
    }
    assert_eq!(f.get(&complete).await?, complete);
    let unfinished = f.admit(f.input("asset-inventory", "owned-forged-upstream", 0, 1)).await?;
    let incomplete = native::row(&f.h, PROGRESS, progress_id)
        .await?
        .ok_or_else(|| native::wire::fixture_error("unfinished progress absent"))?;
    assert!(incomplete["batch"]["partitions"]["0"]["terminal"].is_null());
    let mut forged_success = incomplete.clone();
    forged_success["batch"]["partitions"]["0"]["terminal"] = json!({"ok":true,"skipped":false,"degraded":false,
        "outcome_hash":"a".repeat(64),"finished_at":Timestamp::now()});
    with_record(&f, PROGRESS, progress_id, &incomplete, &forged_success, || {
        Box::pin(async {
            let prior = snapshot(&f.h).await?;
            assert_eq!(
                f.h.request("POST", ROOT, Some(&f.token), Some(f.input("log-pull", "owned-fabricated-success", 0, 1)))
                    .await
                    .status,
                StatusCode::INTERNAL_SERVER_ERROR
            );
            assert_eq!(snapshot(&f.h).await?, prior);
            Ok(())
        })
    })
    .await?;
    // Only real API Start and authenticated Complete may supply the missing terminal dependency.
    f.start(&unfinished).await?;
    f.complete(&unfinished, good()).await?;
    f.finish("log-pull", "owned-real-success-only", 0, 1, good()).await?;
    f.engine.count(2).await?;
    f.clean().await
}
