//! Five owned SQL behavior groups; no provider or embedding request is made.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
// Existing SqlCase methods create actual durable independent AppStates after owner preflight.
mod configuration_audit_support;
mod semantic_cache_profile_database_support;
use agf_core::{error::DomainResult, ids::Id};
use agf_storage::configuration::BoundedConfigurationList;
use common::*;
use futures::FutureExt;
use semantic_cache_profile_database_support::*;
use std::panic::AssertUnwindSafe;

#[tokio::test]
#[ignore = "requires exact owned semantic-profile database/comment/OID"]
async fn bounded_complete_catalog_is_rls_isolated_and_never_returns_prefix_or_oversize() -> DomainResult<()> {
    let case = Case::open("sp-bounded").await?;
    let h = &case.sql.h;
    let foreign = case.sql.foreign_instance().await;
    let kind = "owned-semantic-bound";
    for tenant in [h.tenant, foreign.tenant] {
        for index in 0..3 {
            h.state
                .configurations
                .put(tenant, kind, Id::new(), &json!({"tenant":tenant,"index":index,"safe":"中文\n"}))
                .await?;
        }
    }
    let before = h.state.configurations.list::<Value>(h.tenant, kind).await?;
    assert!(matches!(
        h.state.configurations.list_bounded::<Value>(h.tenant, kind, 2, 8192).await?,
        BoundedConfigurationList::TooMany
    ));
    assert!(matches!(
        h.state.configurations.list_bounded::<Value>(h.tenant, kind, 3, 1).await?,
        BoundedConfigurationList::TooLarge
    ));
    let BoundedConfigurationList::Complete(rows) =
        h.state.configurations.list_bounded::<Value>(h.tenant, kind, 3, 8192).await?
    else {
        return Err(invalid());
    };
    assert_eq!(rows, before);
    assert!(rows.iter().all(|row| row["tenant"] == json!(h.tenant)));
    assert!(
        matches!(h.state.configurations.list_bounded::<Value>(foreign.tenant,"absent-owned-kind",0,0).await?,BoundedConfigurationList::Complete(rows) if rows.is_empty())
    );
    let malformed = Id::new();
    h.state.configurations.put(h.tenant, "owned-malformed", malformed, &json!(false)).await?;
    assert!(
        h.state
            .configurations
            .list_bounded::<agf_api::model_gateway::StoredEndpoint>(h.tenant, "owned-malformed", 1, 8192)
            .await
            .is_err()
    );
    assert_eq!(h.state.configurations.list::<Value>(h.tenant, kind).await?, before);
    assert!(h.state.store.audit_verify_durable(h.tenant).await?.passed);
    Ok(())
}

#[tokio::test]
#[ignore = "requires exact owned semantic-profile database/comment/OID"]
async fn two_instances_have_one_cas_winner_and_actual_endpoint_writer_serializes_with_profile() -> DomainResult<()> {
    let case = Case::open("sp-cas-source").await?;
    let input = case.body().await?;
    let second = case.sql.second_instance().await;
    let before = case.sql.h.state.store.audit_stats_durable(case.sql.h.tenant).await?;
    let (a, b) = tokio::join!(
        case.sql.h.request("PUT", PROFILE, Some(&case.sql.h.admin), Some(input.clone())),
        second.request("PUT", PROFILE, Some(&second.admin), Some(input.clone()))
    );
    assert_eq!([a.status, b.status].iter().filter(|s| **s == StatusCode::OK).count(), 1);
    assert_eq!([a.status, b.status].iter().filter(|s| **s == StatusCode::CONFLICT).count(), 1);
    assert_eq!(case.sql.h.state.store.audit_stats_durable(case.sql.h.tenant).await?.0, before.0 + 1);
    let mut next = input.clone();
    next["expected_version"] = json!(1);
    let endpoint = input["settings"]["chat_endpoint_id"].as_str().ok_or_else(invalid)?.to_owned();
    let endpoint_path = format!("/api/v1/gateway/endpoints/{endpoint}");
    let source_input = json!({"expected_version":1,"name":"owned-profile-chat","model":"owned-profile-chat","provider":"mock","base_url":"http://mock.invalid/v1","local_deployment":true,"enabled":false});
    let gate = Gate::install(&case).await?;
    let (holder, pid) = gate.hold(&case).await?;
    let h = case.sql.h.clone();
    let task = tokio::spawn(async move { h.request("PUT", PROFILE, Some(&h.admin), Some(next)).await });
    let result = AssertUnwindSafe(async {
        let profile_pid = case.wait_blocked(pid).await?;
        let h = second.clone();
        let source_task =
            tokio::spawn(async move { h.request("PUT", &endpoint_path, Some(&h.admin), Some(source_input)).await });
        // The real model-assets writer shares the same governance order; it cannot commit mid-profile.
        let wait = case.wait_blocked(profile_pid).await;
        if let Err(error) = wait {
            source_task.abort();
            let _ = source_task.await;
            return Err(error);
        }
        Ok(source_task)
    })
    .catch_unwind()
    .await;
    holder.rollback().await.map_err(sql_error)?;
    let profile = joined(task).await;
    let source = match result {
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
    assert_eq!(profile?.status, StatusCode::OK);
    let source = source?;
    assert_eq!(source.status, StatusCode::OK);
    assert_eq!(source.json()["version"], 2);
    assert_eq!(source.json()["enabled"], false);
    let current = case.sql.h.get(PROFILE).await.json();
    assert_eq!(current["version"], 2);
    assert_eq!(current["placementVerified"], false);
    let before = case.snapshot().await?;
    let mut input = input;
    input["expected_version"] = json!(2);
    assert_eq!(
        case.sql.h.request("PUT", PROFILE, Some(&case.sql.h.admin), Some(input)).await.status,
        StatusCode::PRECONDITION_FAILED
    );
    assert_eq!(case.snapshot().await?, before);
    Ok(())
}

#[tokio::test]
#[ignore = "requires exact owned semantic-profile database/comment/OID"]
async fn configure_audit_failure_rolls_back_new_and_updated_profile_and_all_source_state() -> DomainResult<()> {
    let case = Case::open("sp-audit-fault").await?;
    let input = case.body().await?;
    for expected in [0, 1] {
        let mut attempted = input.clone();
        attempted["expected_version"] = json!(expected);
        let before = case.snapshot().await?;
        let fault = case.fault().await?;
        let result = AssertUnwindSafe(async {
            assert!(
                case.sql
                    .h
                    .request("PUT", PROFILE, Some(&case.sql.h.admin), Some(attempted.clone()))
                    .await
                    .status
                    .is_server_error()
            );
            assert_eq!(case.snapshot().await?, before);
            Ok::<(), agf_core::error::DomainError>(())
        })
        .catch_unwind()
        .await;
        case.unfault(&fault).await?;
        match result {
            Ok(result) => result?,
            Err(panic) => std::panic::resume_unwind(panic),
        }
        assert_eq!(
            case.sql.h.request("PUT", PROFILE, Some(&case.sql.h.admin), Some(attempted)).await.status,
            StatusCode::OK
        );
    }
    assert_eq!(case.sql.h.get(PROFILE).await.json()["version"], 2);
    Ok(())
}

#[tokio::test]
#[ignore = "requires exact owned semantic-profile database/comment/OID"]
async fn key_revoked_during_exact_configure_audit_wait_cannot_publish_profile() -> DomainResult<()> {
    let case = Case::open("sp-key-audit").await?;
    let input = case.body().await?;
    let (token, key_id) = key(&case).await?;
    let before = case.snapshot().await?;
    let gate = Gate::install(&case).await?;
    let (holder, pid) = gate.hold(&case).await?;
    let h = case.sql.h.clone();
    let task = tokio::spawn(async move { h.request("PUT", PROFILE, Some(&token), Some(input)).await });
    let result = AssertUnwindSafe(async {
        case.wait_blocked(pid).await?;
        revoke(&case, key_id).await
    })
    .catch_unwind()
    .await;
    holder.rollback().await.map_err(sql_error)?;
    let finished = joined(task).await;
    gate.clean(&case).await?;
    match result {
        Ok(result) => result?,
        Err(panic) => std::panic::resume_unwind(panic),
    }
    assert_eq!(finished?.status, StatusCode::FORBIDDEN);
    assert_eq!(case.snapshot().await?, before);
    Ok(())
}

#[tokio::test]
#[ignore = "requires exact owned semantic-profile database/comment/OID"]
async fn original_signed_jwt_expiring_during_configure_audit_wait_cannot_publish_profile() -> DomainResult<()> {
    let case = Case::open("sp-jwt-audit").await?;
    let input = case.body().await?;
    let before = case.snapshot().await?;
    let gate = Gate::install(&case).await?;
    let (holder, pid) = gate.hold(&case).await?;
    let (token, claims) = short_token(&case.sql.h)?;
    let h = case.sql.h.clone();
    let task = tokio::spawn(async move { h.request("PUT", PROFILE, Some(&token), Some(input)).await });
    let result = AssertUnwindSafe(async {
        case.wait_blocked(pid).await?;
        wait_expired(&claims).await
    })
    .catch_unwind()
    .await;
    holder.rollback().await.map_err(sql_error)?;
    let finished = joined(task).await;
    gate.clean(&case).await?;
    match result {
        Ok(result) => result?,
        Err(panic) => std::panic::resume_unwind(panic),
    }
    assert_eq!(finished?.status, StatusCode::UNAUTHORIZED);
    assert_eq!(case.snapshot().await?, before);
    Ok(())
}
