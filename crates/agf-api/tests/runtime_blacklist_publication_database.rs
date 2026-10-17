//! Actual SQL rollback, cross-instance CAS and original authority during the audit wait.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
mod configuration_audit_support;
mod runtime_blacklist_publication_database_support;
use agf_core::error::{DomainError, DomainResult};
use common::*;
use futures::FutureExt;
use runtime_blacklist_publication_database_support::*;
use std::panic::AssertUnwindSafe;

#[tokio::test]
#[ignore = "requires exact owned blacklist database/comment/OID"]
async fn independent_instances_have_one_blacklist_cas_winner_and_restart_sees_it() -> DomainResult<()> {
    let case = Case::open("blacklist-cas").await?;
    let created = case.add().await;
    let id = created["id"].as_str().unwrap();
    let uri = format!("/api/v1/runtime/blacklists/{id}");
    let second = case.sql.second_instance().await;
    let before = case.sql.h.state.store.audit_stats_durable(case.sql.h.tenant).await?;
    let payload = json!({"enabled":false,"expected_version":1});
    let (a, b) = tokio::join!(
        case.sql.h.request("PATCH", &uri, Some(&case.sql.h.admin), Some(payload.clone())),
        second.request("PATCH", &uri, Some(&second.admin), Some(payload))
    );
    let statuses = [a.status, b.status];
    assert_eq!(statuses.iter().filter(|status| **status == StatusCode::OK).count(), 1);
    assert_eq!(statuses.iter().filter(|status| **status == StatusCode::CONFLICT).count(), 1);
    assert_eq!(case.sql.h.state.store.audit_stats_durable(case.sql.h.tenant).await?.0, before.0 + 1);
    let fresh = case.sql.second_instance().await;
    let listed = fresh.get("/api/v1/runtime/blacklists").await.json();
    let row = listed.as_array().unwrap().iter().find(|row| row["id"] == id).unwrap();
    assert_eq!(row["version"], 2);
    assert_eq!(row["enabled"], false);
    let before = case.snapshot().await?;
    assert_eq!(
        fresh.request("DELETE", &format!("{uri}?expected_version=1"), Some(&fresh.admin), None).await.status,
        StatusCode::CONFLICT
    );
    assert_eq!(case.snapshot().await?, before);
    let foreign = case.sql.foreign_instance().await;
    assert!(
        !foreign.get("/api/v1/runtime/blacklists").await.json().as_array().unwrap().iter().any(|row| row["id"] == id)
    );
    assert!(fresh.state.store.audit_verify_durable(fresh.tenant).await?.passed);
    Ok(())
}

#[tokio::test]
#[ignore = "requires exact owned blacklist database/comment/OID"]
async fn rejected_audit_rolls_back_add_toggle_and_delete_and_restart_reads_unchanged() -> DomainResult<()> {
    let case = Case::open("blacklist-audit").await?;
    let fault = case.fault().await?;
    let before = case.snapshot().await?;
    let result = AssertUnwindSafe(async {
        let response = case.sql.h.post("/api/v1/runtime/blacklists", body()).await;
        assert!(response.status.is_server_error(), "{}", response.text);
        assert_eq!(case.snapshot().await?, before);
        Ok::<(), DomainError>(())
    })
    .catch_unwind()
    .await;
    case.unfault(&fault).await?;
    match result {
        Ok(value) => value?,
        Err(panic) => std::panic::resume_unwind(panic),
    }
    let created = case.add().await;
    let id = created["id"].as_str().unwrap();
    for method in ["PATCH", "DELETE"] {
        let before = case.snapshot().await?;
        let fault = case.fault().await?;
        let result = AssertUnwindSafe(async {
            let response = if method == "PATCH" {
                case.sql
                    .h
                    .request(
                        method,
                        &format!("/api/v1/runtime/blacklists/{id}"),
                        Some(&case.sql.h.admin),
                        Some(json!({"enabled":false,"expected_version":1})),
                    )
                    .await
            } else {
                case.sql
                    .h
                    .request(
                        method,
                        &format!("/api/v1/runtime/blacklists/{id}?expected_version=1"),
                        Some(&case.sql.h.admin),
                        None,
                    )
                    .await
            };
            assert!(response.status.is_server_error(), "{}", response.text);
            assert_eq!(case.snapshot().await?, before);
            let fresh = case.sql.second_instance().await;
            assert_eq!(json!(fresh.state.configurations.list::<Value>(fresh.tenant, KIND).await?), before["rows"]);
            Ok::<(), DomainError>(())
        })
        .catch_unwind()
        .await;
        case.unfault(&fault).await?;
        match result {
            Ok(value) => value?,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }
    assert!(case.sql.h.state.store.audit_verify_durable(case.sql.h.tenant).await?.passed);
    Ok(())
}

#[tokio::test]
#[ignore = "requires exact owned blacklist database/comment/OID"]
async fn revoking_original_key_during_blacklist_audit_wait_rolls_back_configuration_and_audit() -> DomainResult<()> {
    let case = Case::open("blacklist-key").await?;
    let created = case.add().await;
    let id = created["id"].as_str().unwrap();
    let (token, key_id) = key(&case).await?;
    let before = case.snapshot().await?;
    let gate = Gate::install(&case).await?;
    let (holder, pid) = gate.hold(&case).await?;
    let h = case.sql.h.clone();
    let uri = format!("/api/v1/runtime/blacklists/{id}");
    let task = tokio::spawn(async move {
        h.request("PATCH", &uri, Some(&token), Some(json!({"enabled":false,"expected_version":1}))).await
    });
    let result = AssertUnwindSafe(async {
        case.wait_blocked(pid).await?;
        revoke(&case, key_id).await
    })
    .catch_unwind()
    .await;
    holder.rollback().await.map_err(sql_error)?;
    let response = joined(task).await;
    gate.clean(&case).await?;
    match result {
        Ok(value) => value?,
        Err(panic) => std::panic::resume_unwind(panic),
    }
    assert_eq!(response?.status, StatusCode::FORBIDDEN);
    assert_eq!(case.snapshot().await?, before);
    Ok(())
}

#[tokio::test]
#[ignore = "requires exact owned blacklist database/comment/OID"]
async fn original_jwt_expiry_during_blacklist_audit_wait_cannot_publish() -> DomainResult<()> {
    let case = Case::open("blacklist-jwt").await?;
    let created = case.add().await;
    let id = created["id"].as_str().unwrap();
    let before = case.snapshot().await?;
    let gate = Gate::install(&case).await?;
    let (holder, pid) = gate.hold(&case).await?;
    let (token, claims) = short_token(&case.sql.h)?;
    let h = case.sql.h.clone();
    let uri = format!("/api/v1/runtime/blacklists/{id}");
    let task = tokio::spawn(async move {
        h.request("PATCH", &uri, Some(&token), Some(json!({"enabled":false,"expected_version":1}))).await
    });
    let result = AssertUnwindSafe(async {
        case.wait_blocked(pid).await?;
        wait_expired(&claims).await
    })
    .catch_unwind()
    .await;
    holder.rollback().await.map_err(sql_error)?;
    let response = joined(task).await;
    gate.clean(&case).await?;
    match result {
        Ok(value) => value?,
        Err(panic) => std::panic::resume_unwind(panic),
    }
    assert_eq!(response?.status, StatusCode::UNAUTHORIZED);
    assert_eq!(case.snapshot().await?, before);
    Ok(())
}
