//! Five owned SQL groups: actual CAS, audit rollback, current Key/JWT and endpoint writer locking.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
// Reuse the actual durable instance helper only; this module has no registered tests.
mod configuration_audit_support;
mod model_route_policy_atomicity_database_support;
use agf_core::error::{DomainError, DomainResult};
use common::*;
use futures::FutureExt;
use model_route_policy_atomicity_database_support::*;
use std::panic::AssertUnwindSafe;

#[tokio::test]
#[ignore = "requires exact owned route policy audit database/comment/OID"]
async fn independent_instances_have_one_cas_winner_and_restart_reads_the_committed_route() -> DomainResult<()> {
    let case = Case::open("route-cas").await?;
    let body = case.body().await?;
    let second = case.sql.second_instance().await;
    let before = case.sql.h.state.store.audit_stats_durable(case.sql.h.tenant).await?;
    let uri = case.uri();
    let (a, b) = tokio::join!(
        case.sql.h.request("PUT", &uri, Some(&case.sql.h.admin), Some(body.clone())),
        second.request("PUT", &uri, Some(&second.admin), Some(body))
    );
    assert_eq!([a.status, b.status].iter().filter(|s| **s == StatusCode::OK).count(), 1);
    assert_eq!([a.status, b.status].iter().filter(|s| **s == StatusCode::CONFLICT).count(), 1);
    assert_eq!(case.sql.h.state.store.audit_stats_durable(case.sql.h.tenant).await?.0, before.0 + 1);
    let fresh = case.sql.second_instance().await;
    let listed = fresh.get("/api/v1/models/route-policies").await;
    assert_eq!(listed.status, StatusCode::OK);
    let rows = listed.json();
    assert_eq!(rows.as_array().unwrap().iter().filter(|row| row["id"] == case.id().to_string()).count(), 1);
    assert_eq!(rows[0]["version"], 1);
    let foreign = case.sql.foreign_instance().await;
    assert_eq!(foreign.get("/api/v1/models/route-policies").await.json(), json!([]));
    assert!(case.sql.h.state.store.audit_verify_durable(case.sql.h.tenant).await?.passed);
    Ok(())
}

#[tokio::test]
#[ignore = "requires exact owned route policy audit database/comment/OID"]
async fn audit_failure_leaves_both_new_and_updated_configuration_and_projection_unchanged() -> DomainResult<()> {
    let case = Case::open("route-fault").await?;
    let body = case.body().await?;
    for version in [0, 1] {
        let mut next = body.clone();
        next["expectedVersion"] = json!(version);
        next["name"] = json!(format!("version-{version}"));
        let before = case.snapshot().await?;
        let fault = case.fault().await?;
        let result = AssertUnwindSafe(async {
            let response = case.sql.h.request("PUT", &case.uri(), Some(&case.sql.h.admin), Some(next.clone())).await;
            assert!(response.status.is_server_error());
            assert!(
                case.snapshot().await? == before,
                "Audit failure must preserve complete config, source, projection and chain"
            );
            let fresh = case.sql.second_instance().await;
            assert_eq!(json!(fresh.state.configurations.list::<Value>(fresh.tenant, KIND).await?), before["routes"]);
            Ok::<(), DomainError>(())
        })
        .catch_unwind()
        .await;
        case.unfault(&fault).await?;
        match result {
            Ok(value) => value?,
            Err(panic) => std::panic::resume_unwind(panic),
        }
        assert_eq!(
            case.sql.h.request("PUT", &case.uri(), Some(&case.sql.h.admin), Some(next)).await.status,
            StatusCode::OK
        );
    }
    assert_eq!(
        case.sql.h.state.configurations.get::<Value>(case.sql.h.tenant, KIND, case.id()).await?.unwrap()["version"],
        2
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires exact owned route policy audit database/comment/OID"]
async fn revoking_actual_key_during_route_configure_audit_wait_rolls_back_every_write() -> DomainResult<()> {
    let case = Case::open("route-key").await?;
    let body = case.body().await?;
    let (token, key_id) = key(&case).await?;
    let before = case.snapshot().await?;
    let gate = Gate::install(&case).await?;
    let (holder, pid) = gate.hold(&case).await?;
    let h = case.sql.h.clone();
    let uri = case.uri();
    let task = tokio::spawn(async move { h.request("PUT", &uri, Some(&token), Some(body)).await });
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
    assert!(case.snapshot().await? == before, "Revoked original Key must leave configuration and audit unchanged");
    Ok(())
}

#[tokio::test]
#[ignore = "requires exact owned route policy audit database/comment/OID"]
async fn original_jwt_expiry_while_waiting_on_route_audit_cannot_publish_configuration() -> DomainResult<()> {
    let case = Case::open("route-jwt").await?;
    let body = case.body().await?;
    let before = case.snapshot().await?;
    let gate = Gate::install(&case).await?;
    let (holder, pid) = gate.hold(&case).await?;
    let (token, claims) = short_token(&case.sql.h)?;
    let h = case.sql.h.clone();
    let uri = case.uri();
    let task = tokio::spawn(async move { h.request("PUT", &uri, Some(&token), Some(body)).await });
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
    assert!(case.snapshot().await? == before, "Expired original token must preserve all config/source/audit state");
    Ok(())
}

#[tokio::test]
#[ignore = "requires exact owned route policy audit database/comment/OID"]
async fn real_endpoint_writer_waits_behind_route_transaction_and_keeps_both_committed_versions() -> DomainResult<()> {
    let case = Case::open("route-source").await?;
    let input = case.body().await?;
    let source = input["primaryEndpointId"].as_str().unwrap().to_owned();
    let gate = Gate::install(&case).await?;
    let (holder, pid) = gate.hold(&case).await?;
    let h = case.sql.h.clone();
    let uri = case.uri();
    let route = tokio::spawn(async move { h.request("PUT", &uri, Some(&h.admin), Some(input)).await });
    let result = AssertUnwindSafe(async {
        let route_pid = case.wait_blocked(pid).await?;
        let h = case.sql.second_instance().await;
        let source_task = tokio::spawn(async move {
            h.request(
                "PUT",
                &format!("/api/v1/gateway/endpoints/{source}"),
                Some(&h.admin),
                Some(json!({
            "expected_version":1,"name":"owned-route-source","model":"owned-route-source","provider":"mock",
            "base_url":"http://mock.invalid/v1","enabled":false})),
            )
            .await
        });
        if let Err(error) = case.wait_blocked(route_pid).await {
            source_task.abort();
            let _ = source_task.await;
            return Err(error);
        }
        Ok(source_task)
    })
    .catch_unwind()
    .await;
    holder.rollback().await.map_err(sql_error)?;
    let route_result = joined(route).await;
    let source_result = match result {
        Ok(Ok(task)) => joined(task).await,
        Ok(Err(error)) => {
            gate.clean(&case).await?;
            return Err(error);
        }
        Err(panic) => {
            gate.clean(&case).await?;
            std::panic::resume_unwind(panic)
        }
    };
    gate.clean(&case).await?;
    assert_eq!(route_result?.status, StatusCode::OK);
    let source_result = source_result?;
    assert_eq!(source_result.status, StatusCode::OK);
    assert_eq!(source_result.json()["version"], 2);
    assert_eq!(source_result.json()["enabled"], false);
    assert_eq!(
        case.sql.h.state.configurations.get::<Value>(case.sql.h.tenant, KIND, case.id()).await?.unwrap()["version"],
        1
    );
    assert!(case.sql.h.state.store.audit_verify_durable(case.sql.h.tenant).await?.passed);
    Ok(())
}
