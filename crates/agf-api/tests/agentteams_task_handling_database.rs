//! Owned PostgreSQL acceptance definitions; never migrate a database without exact comment/OID preflight.
mod common;
// Legacy helpers provide SqlCase; this target deliberately uses only its owned-instance methods.
mod agentteams_task_handling_sql_support;
mod agentteams_task_handling_support;
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod configuration_audit_support;
use agentteams_task_handling_sql_support::{Case, Gate, key, revoke, sql_error};
use agentteams_task_handling_support::*;
use agf_core::{error::DomainResult, ids::Id};
use common::*;
use futures::FutureExt;
use std::panic::AssertUnwindSafe;

#[tokio::test]
async fn ordinary_fixture_still_uses_real_collector_handlers_and_current_opaque_proof() -> DomainResult<()> {
    let fixture = Fixture::new().await?;
    let event = fixture.push("fixture-proof-boundary", "error").await?;
    assert_eq!(fixture.failure_query().await?.total, 1);
    assert!(fixture.original(event).await?.is_object());
    let input = fixture.resolution(event, Id::new(), 0, "acknowledged").await;
    ok(&fixture.resolve(event, input).await, StatusCode::OK);
    assert_eq!(fixture.archive_input(event, Id::new()).await["event_ids"], json!([event]));
    assert!(fixture.snapshot().await?.is_object());
    Ok(())
}

#[tokio::test]
#[ignore = "requires an exact owned WP4 AGF_TEST_DATABASE_URL/comment/OID"]
async fn sql_single_snapshot_two_instances_cas_and_restart_receipts_preserve_originals() -> DomainResult<()> {
    let case = Case::open("wp4-cas").await?;
    let fixture = &case.fixture;
    let event = fixture.push("owned-sql-cas", "error").await?;
    let original = fixture.original(event).await?;
    assert_eq!(fixture.failure_query().await?.total, 1);
    let input = fixture.resolution(event, Id::new(), 0, "acknowledged").await;
    let second = case.second().await?;
    let path = format!("{ROOT}/events/{event}/resolution");
    // Independent harnesses bootstrap distinct admins; a durable Key preserves the original actor.
    let (token, _) = key(&fixture.h).await?;
    let (first, next) = tokio::join!(
        fixture.h.request("PUT", &path, Some(&token), Some(input.clone())),
        second.request("PUT", &path, Some(&token), Some(input.clone()))
    );
    ok(&first, StatusCode::OK);
    ok(&next, StatusCode::OK);
    assert_eq!(first.json(), next.json());
    let before = fixture.snapshot().await?;
    // The same UUID/body does not grant a different current actor ownership of that action.
    ok(&fixture.resolve(event, input.clone()).await, StatusCode::CONFLICT);
    assert_eq!(fixture.snapshot().await?, before);
    let request = id(&input["request_id"])?;
    assert_eq!(second.get(&format!("{ROOT}/requests/{request}")).await.json(), first.json());
    assert_eq!(fixture.snapshot().await?, before);
    assert_eq!(fixture.original(event).await?, original);
    let competing = fixture.resolution(event, Id::new(), 1, "resolved_by_operator").await;
    let rival = fixture.resolution(event, Id::new(), 1, "external_action_reported").await;
    let (first, next) =
        tokio::join!(fixture.resolve(event, competing), second.request("PUT", &path, Some(&second.admin), Some(rival)));
    assert_eq!([first.status, next.status].iter().filter(|status| **status == StatusCode::OK).count(), 1);
    assert_eq!([first.status, next.status].iter().filter(|status| **status == StatusCode::CONFLICT).count(), 1);
    assert!(fixture.h.state.store.audit_verify_durable(fixture.h.tenant).await?.passed);
    Ok(())
}
#[tokio::test]
#[ignore = "requires an exact owned WP4 AGF_TEST_DATABASE_URL/comment/OID"]
async fn resolution_and_archive_audit_failure_roll_back_whole_encrypted_state_and_uuid_claims() -> DomainResult<()> {
    let case = Case::open("wp4-rollback").await?;
    let fixture = &case.fixture;
    let event = fixture.push("owned-sql-rollback", "error").await?;
    let input = fixture.resolution(event, Id::new(), 0, "acknowledged").await;
    let before = fixture.snapshot().await?;
    let fault = case.fault().await?;
    let result = AssertUnwindSafe(async {
        let rejected = fixture.resolve(event, input.clone()).await;
        assert!(rejected.status.is_server_error());
        assert_eq!(fixture.snapshot().await?, before);
        Ok::<(), agf_core::error::DomainError>(())
    })
    .catch_unwind()
    .await;
    case.unfault(&fault).await?;
    match result {
        Ok(result) => result?,
        Err(panic) => std::panic::resume_unwind(panic),
    }
    ok(&fixture.resolve(event, input).await, StatusCode::OK);
    let archive = fixture.archive_input(event, Id::new()).await;
    let before = fixture.snapshot().await?;
    let fault = case.fault().await?;
    let result = AssertUnwindSafe(async {
        let rejected = fixture.h.post(&format!("{ROOT}/archive"), archive.clone()).await;
        assert!(rejected.status.is_server_error());
        assert_eq!(fixture.snapshot().await?, before);
        Ok::<(), agf_core::error::DomainError>(())
    })
    .catch_unwind()
    .await;
    case.unfault(&fault).await?;
    match result {
        Ok(result) => result?,
        Err(panic) => std::panic::resume_unwind(panic),
    }
    ok(&fixture.h.post(&format!("{ROOT}/archive"), archive).await, StatusCode::OK);
    Ok(())
}
#[tokio::test]
#[ignore = "requires an exact owned WP4 AGF_TEST_DATABASE_URL/comment/OID"]
async fn source_wait_then_current_key_revocation_rejects_without_claim_or_audit() -> DomainResult<()> {
    let case = Case::open("wp4-key-wait").await?;
    let fixture = &case.fixture;
    let event = fixture.push("owned-sql-authority", "error").await?;
    let input = fixture.resolution(event, Id::new(), 0, "acknowledged").await;
    let issued = fixture
        .h
        .post(
            "/api/v1/settings/api-keys",
            json!({"name":"wp4-owned-editor",
        "scopes":["alicloud:read","sources:read","alicloud:write","sources:write"]}),
        )
        .await;
    ok(&issued, StatusCode::CREATED);
    let issued = issued.json();
    let key = issued["plaintext"].as_str().ok_or_else(invalid)?.to_owned();
    let key_id = id(&issued["api_key"]["id"])?;
    let before = fixture.snapshot().await?;
    let (lock, pid) = case.source_lock().await?;
    let h = fixture.h.clone();
    let path = format!("{ROOT}/events/{event}/resolution");
    let task = tokio::spawn(async move { h.request("PUT", &path, Some(&key), Some(input)).await });
    case.wait_source(pid).await?;
    case.owner.verify(&case.sql.pool).await?;
    let changed =
        sqlx::query("UPDATE api_keys SET revoked=true,updated_at=now() WHERE tenant_id=$1 AND id=$2 AND NOT revoked")
            .bind(fixture.h.tenant.as_uuid())
            .bind(key_id.as_uuid())
            .execute(&case.sql.pool)
            .await
            .map_err(sql_error)?;
    assert_eq!(changed.rows_affected(), 1);
    lock.rollback().await.map_err(sql_error)?;
    let rejected = tokio::time::timeout(std::time::Duration::from_secs(20), task)
        .await
        .map_err(|_| invalid())?
        .map_err(|_| invalid())?;
    ok(&rejected, StatusCode::FORBIDDEN);
    assert_eq!(fixture.snapshot().await?, before);
    Ok(())
}
#[tokio::test]
#[ignore = "requires an exact owned WP4 AGF_TEST_DATABASE_URL/comment/OID"]
async fn original_columns_payload_and_cipher_tampering_fail_closed_without_success_audit() -> DomainResult<()> {
    let case = Case::open("wp4-evidence").await?;
    let fixture = &case.fixture;
    let event = fixture.push("owned-sql-evidence", "error").await?;
    let before = fixture.snapshot().await?;
    case.owner.verify(&case.sql.pool).await?;
    let mut tx = case.sql.pool.begin().await.map_err(sql_error)?;
    sqlx::query("UPDATE agentteams_audit SET source_id=$3 WHERE tenant_id=$1 AND id=$2")
        .bind(fixture.h.tenant.as_uuid())
        .bind(event.as_uuid())
        .bind(Id::new().as_uuid())
        .execute(&mut *tx)
        .await
        .map_err(sql_error)?;
    // The uncommitted corruption is checked on this owned connection by the same public decoder.
    let envelope:Value=sqlx::query_scalar("SELECT jsonb_build_object('id',id,'tenant_id',tenant_id,'source_id',source_id,'scope_id',scope_id,'binding_id',binding_id,'external_event_id',external_event_id,'content_hash',content_hash,'event_time',event_time,'received_at',received_at,'kind',kind,'payload',payload) FROM agentteams_audit WHERE tenant_id=$1 AND id=$2")
        .bind(fixture.h.tenant.as_uuid()).bind(event.as_uuid()).fetch_one(&mut *tx).await.map_err(sql_error)?;
    assert!(agf_ingest::pipeline::agentteams_failure_from_envelope(envelope, fixture.h.tenant).is_err());
    tx.rollback().await.map_err(sql_error)?;
    assert_eq!(fixture.snapshot().await?, before);
    ok(&fixture.resolve(event, fixture.resolution(event, Id::new(), 0, "acknowledged").await).await, StatusCode::OK);
    let before = fixture.snapshot().await?;
    let (record_id,payload):(uuid::Uuid,Value)=sqlx::query_as("SELECT id,payload FROM console_configurations WHERE tenant_id=$1 AND kind='agentteams-task-handling-record' AND deleted_at IS NULL")
        .bind(fixture.h.tenant.as_uuid()).fetch_one(&case.sql.pool).await.map_err(sql_error)?;
    let mut corrupted = payload.clone();
    corrupted["aad"] = json!("foreign-owned-aad");
    sqlx::query("UPDATE console_configurations SET payload=$3 WHERE tenant_id=$1 AND id=$2 AND kind='agentteams-task-handling-record'")
        .bind(fixture.h.tenant.as_uuid()).bind(record_id).bind(corrupted).execute(&case.sql.pool).await.map_err(sql_error)?;
    let result = AssertUnwindSafe(async {
        let rejected = fixture.h.get(&format!("{ROOT}/events/{event}")).await;
        assert!(rejected.status.is_server_error());
        Ok::<(), agf_core::error::DomainError>(())
    })
    .catch_unwind()
    .await;
    sqlx::query("UPDATE console_configurations SET payload=$3 WHERE tenant_id=$1 AND id=$2 AND kind='agentteams-task-handling-record'")
        .bind(fixture.h.tenant.as_uuid()).bind(record_id).bind(payload).execute(&case.sql.pool).await.map_err(sql_error)?;
    match result {
        Ok(result) => result?,
        Err(panic) => std::panic::resume_unwind(panic),
    }
    assert_eq!(fixture.snapshot().await?, before);
    Ok(())
}
#[tokio::test]
#[ignore = "requires an exact owned WP4 AGF_TEST_DATABASE_URL/comment/OID"]
async fn archive_ninety_nine_records_preserves_one_hundred_related_uuid_budget_and_last_capacity() -> DomainResult<()> {
    let case = Case::open("wp4-capacity").await?;
    let fixture = &case.fixture;
    let mut events = Vec::new();
    let mut receipts = Vec::new();
    for index in 0..128 {
        let event = fixture.push(&format!("capacity-{index}"), "error").await?;
        let request = Id::new();
        let input = fixture.resolution(event, request, 0, "resolved_by_operator").await;
        let accepted = fixture.resolve(event, input).await;
        ok(&accepted, StatusCode::OK);
        events.push(event);
        receipts.push((request, accepted.json()));
    }
    let extra = fixture.push("capacity-extra", "error").await?;
    let input = fixture.resolution(extra, Id::new(), 0, "acknowledged").await;
    ok(&fixture.resolve(extra, input).await, StatusCode::CONFLICT);
    let mut archive = fixture.archive_input(events[0], Id::new()).await;
    archive["event_ids"] = json!(&events[..99]);
    let archived = fixture.h.post(&format!("{ROOT}/archive"), archive.clone()).await;
    ok(&archived, StatusCode::OK);
    assert_eq!(archived.json()["changedCount"], 99);
    let state = fixture.h.get(ROOT).await.json();
    assert_eq!(state["activeHandledCount"], 29);
    assert_eq!(state["archivedCount"], 99);
    let before = fixture.snapshot().await?;
    assert_eq!(fixture.h.post(&format!("{ROOT}/archive"), archive).await.json(), archived.json());
    for (request, receipt) in receipts.iter().take(99) {
        assert_eq!(fixture.h.get(&format!("{ROOT}/requests/{request}")).await.json(), *receipt);
    }
    assert_eq!(fixture.snapshot().await?, before);
    ok(&fixture.resolve(extra, fixture.resolution(extra, Id::new(), 0, "acknowledged").await).await, StatusCode::OK);
    assert!(fixture.h.state.store.audit_verify_durable(fixture.h.tenant).await?.passed);
    Ok(())
}

#[tokio::test]
#[ignore = "requires an exact owned WP4 AGF_TEST_DATABASE_URL/comment/OID"]
async fn current_key_revocation_while_audit_waits_rolls_back_original_annotation_and_receipt() -> DomainResult<()> {
    let case = Case::open("wp4-audit-key").await?;
    let fixture = &case.fixture;
    let event = fixture.push("audit-key-original", "error").await?;
    let request = Id::new();
    let input = fixture.resolution(event, request, 0, "acknowledged").await;
    let (token, key_id) = key(&fixture.h).await?;
    let before = fixture.snapshot().await?;
    let gate = Gate::install(&case, request).await?;
    let (holder, pid) = gate.hold(&case).await?;
    let h = fixture.h.clone();
    let path = format!("{ROOT}/events/{event}/resolution");
    let mut task = tokio::spawn(async move { h.request("PUT", &path, Some(&token), Some(input)).await });
    let result = AssertUnwindSafe(async {
        case.wait_source(pid).await?;
        revoke(&case, key_id).await
    })
    .catch_unwind()
    .await;
    holder.rollback().await.map_err(sql_error)?;
    let finished = tokio::time::timeout(std::time::Duration::from_secs(20), &mut task).await;
    if finished.is_err() {
        task.abort();
        let _ = task.await;
    }
    gate.clean(&case).await?;
    match result {
        Ok(result) => result?,
        Err(panic) => std::panic::resume_unwind(panic),
    }
    let response = finished.map_err(|_| invalid())?.map_err(|_| invalid())?;
    ok(&response, StatusCode::FORBIDDEN);
    assert_eq!(fixture.snapshot().await?, before);
    assert!(fixture.h.state.store.audit_verify_durable(fixture.h.tenant).await?.passed);
    Ok(())
}

#[tokio::test]
#[ignore = "requires an exact owned WP4 AGF_TEST_DATABASE_URL/comment/OID"]
async fn original_signed_jwt_expiring_at_audit_wait_cannot_commit_an_annotation() -> DomainResult<()> {
    use agf_auth::claims::{IssueContext, TokenIssuer};
    let case = Case::open("wp4-audit-expiry").await?;
    let fixture = &case.fixture;
    let event = fixture.push("audit-expiry-original", "error").await?;
    let request = Id::new();
    let input = fixture.resolution(event, request, 0, "acknowledged").await;
    let before = fixture.snapshot().await?;
    let gate = Gate::install(&case, request).await?;
    let (holder, pid) = gate.hold(&case).await?;
    let existing = fixture.h.state.auth.issuer().verify(&fixture.h.admin)?;
    let issuer = TokenIssuer::new(
        &fixture.h.state.config.security.jwt_secret,
        existing.iss.clone(),
        existing.aud.clone(),
        10,
        fixture.h.state.config.security.jwt_refresh_ttl_secs,
    )?;
    let context = IssueContext {
        subject: Id::parse(&existing.sub).map_err(|_| invalid())?,
        tenant: TenantId::parse(&existing.tenant_id).map_err(|_| invalid())?,
        kind: existing.subject_kind,
        roles: existing.roles,
        superadmin: existing.superadmin,
        must_change_password: existing.must_change_password,
        session_id: existing.session_id,
    };
    let token = issuer.issue_access(&context, Timestamp::now())?;
    let claims = fixture.h.state.auth.issuer().verify(&token)?;
    let h = fixture.h.clone();
    let path = format!("{ROOT}/events/{event}/resolution");
    let mut task = tokio::spawn(async move { h.request("PUT", &path, Some(&token), Some(input)).await });
    let result = AssertUnwindSafe(async {
        case.wait_source(pid).await?;
        assert!(!claims.is_expired(Timestamp::now().unix_secs()));
        tokio::time::timeout(std::time::Duration::from_secs(12), async {
            while !claims.is_expired(Timestamp::now().unix_secs()) {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| invalid())?;
        Ok::<(), agf_core::error::DomainError>(())
    })
    .catch_unwind()
    .await;
    holder.rollback().await.map_err(sql_error)?;
    let finished = tokio::time::timeout(std::time::Duration::from_secs(20), &mut task).await;
    if finished.is_err() {
        task.abort();
        let _ = task.await;
    }
    gate.clean(&case).await?;
    match result {
        Ok(result) => result?,
        Err(panic) => std::panic::resume_unwind(panic),
    }
    let response = finished.map_err(|_| invalid())?.map_err(|_| invalid())?;
    ok(&response, StatusCode::UNAUTHORIZED);
    assert_eq!(fixture.snapshot().await?, before);
    Ok(())
}
