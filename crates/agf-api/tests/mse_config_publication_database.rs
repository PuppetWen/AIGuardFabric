//! Dedicated PostgreSQL acceptance. The exact run owner is checked before migrations or writes.
#[path = "mse_config_publication_support/database_authority.rs"]
mod authority;
mod common;
#[path = "mse_config_publication_support/database_completion.rs"]
mod completion;
#[allow(clippy::unwrap_used)] // The unchanged legacy fixture owns its pre-existing unwraps.
mod configuration_audit_support;
#[path = "mse_config_publication_support/database.rs"]
mod publication_db;
#[path = "mse_config_publication_support/database_gate.rs"]
mod publication_gate;
#[path = "mse_config_publication_support/transport.rs"]
mod transport;
#[path = "mse_config_publication_support/database_unknown.rs"]
mod unknown;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
};
use common::*;
use publication_gate::{Mode, Target, with_gate};
use transport::*;

#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_MSE_CONFIG_PUBLICATION_DATABASE_OWNER"]
async fn two_durable_instances_and_two_actors_can_claim_one_preview_only_once() -> DomainResult<()> {
    let case = publication_db::open("mse-pub-concurrent").await?;
    let f = Fixture::attach(case.h.clone()).await?;
    let preview = f.ready().await?;
    f.engine.reply(Reply::Normal).await;
    let second = route(case.second_instance().await, f.engine.address)?;
    let (token, _) = publication_db::key(&second).await?;
    let first = Id::new();
    let other = Id::new();
    f.engine.hold("POST", 1).await;
    let pending =
        Pending::start(f.h.clone(), format!("{BASE}/operations"), f.h.admin.clone(), apply_input(&preview, first)?);
    f.engine.waiting("POST", 1).await?;
    let refused =
        second.request("POST", &format!("{BASE}/operations"), Some(&token), Some(apply_input(&preview, other)?)).await;
    assert_eq!(refused.status, StatusCode::CONFLICT, "{}", refused.text);
    f.engine.release();
    let result = pending.finish().await?;
    assert_eq!(result.status, StatusCode::OK);
    verified(&result.json());
    assert_eq!(f.engine.counts().await, (3, 1));
    assert_eq!(read(&second, &receipt(first)).await?, result.json());
    assert_eq!(second.get(&receipt(other)).await.status, StatusCode::NOT_FOUND);
    assert_eq!(audits(&second, first, "mse-config-publication-claim").await?.len(), 1);
    assert_eq!(audits(&second, first, "mse-config-publication").await?.len(), 1);
    let seen = f.engine.seen().await;
    assert!(seen.iter().all(|r| r.authenticated));
    let writes: Vec<_> = seen.iter().filter(|r| r.method == "POST").collect();
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].cas.as_deref(), Some(agf_alicloud::mse::config_cas::content_md5(INITIAL).as_str()));
    assert_eq!(writes[0].fields["content"], f.engine.content().await);
    publication_db::chain(&second).await?;
    case.pool.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_MSE_CONFIG_PUBLICATION_DATABASE_OWNER"]
async fn claim_audit_rejection_rolls_back_every_candidate_before_any_provider_request() -> DomainResult<()> {
    let case = publication_db::open("mse-pub-claim-fault").await?;
    let f = Fixture::attach(case.h.clone()).await?;
    let preview = f.ready().await?;
    let request = Id::new();
    let before = snapshot(&f.h).await?;
    let second = route(case.second_instance().await, f.engine.address)?;
    with_gate(
        &case.pool,
        f.h.tenant,
        Target { kind: "mse-config-publication-claim", id: request, action: "configure" },
        Mode::Reject,
        move |_| {
            Box::pin(async move {
                let response = f.h.post(&format!("{BASE}/operations"), apply_input(&preview, request)?).await;
                assert!(response.status.is_server_error(), "{}", response.text);
                assert_eq!(snapshot(&f.h).await?, before);
                assert_eq!(snapshot(&second).await?, before);
                assert_eq!(f.engine.counts().await, (1, 0));
                assert_eq!(f.engine.content().await, INITIAL);
                assert_eq!(second.get(&receipt(request)).await.status, StatusCode::NOT_FOUND);
                publication_db::chain(&second).await
            })
        },
    )
    .await?;
    case.pool.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_MSE_CONFIG_PUBLICATION_DATABASE_OWNER"]
async fn actual_mock_write_and_authenticated_content_survive_an_independent_api_instance() -> DomainResult<()> {
    let case = publication_db::open("mse-pub-mock-restart").await?;
    let policy = publication_db::mock(&case.h).await?;
    let preview = publication_db::ready(&case.h, &policy).await?;
    let baseline = publication_db::mock_content(&case.h).await?;
    assert_eq!(baseline.0, 1);
    let request = Id::new();
    let result = publication_db::apply(&case.h, &preview, request).await?;
    assert_eq!(result["status"], "verified");
    assert_eq!(result["target"]["mocked"], true);
    let accepted = publication_db::mock_content(&case.h).await?;
    assert_eq!(accepted.0, 2);
    assert_ne!(accepted.1, baseline.1);
    let second = case.second_instance().await;
    assert_eq!(publication_db::mock_content(&second).await?, accepted);
    assert_eq!(read(&second, &receipt(request)).await?, result);
    let row =
        publication_db::row(&second, DETAIL, publication_db::content_id(second.tenant, request, "operation")).await?;
    assert_eq!(row["class"], "content");
    let desired = publication_db::decrypt(&second, &row["data"]["prepared"]["desired"])?;
    assert_eq!(desired, accepted.1);
    let before = snapshot(&second).await?;
    read(&second, BASE).await?;
    read(&second, &receipt(request)).await?;
    assert_eq!(snapshot(&second).await?, before);
    assert_eq!(audits(&second, request, "mse-config-publication").await?.len(), 1);
    publication_db::chain(&second).await?;
    case.pool.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_MSE_CONFIG_PUBLICATION_DATABASE_OWNER"]
async fn permanent_uuid_is_tenant_scoped_and_replay_cannot_switch_body_or_source() -> DomainResult<()> {
    let case = publication_db::open("mse-pub-uuid-scope").await?;
    let f = Fixture::attach(case.h.clone()).await?;
    let preview = f.ready().await?;
    let request = Id::new();
    let result = f.apply(&preview, request).await?;
    verified(&result);
    let second = route(case.second_instance().await, f.engine.address)?;
    configure(&second, f.engine.address, 1, false).await?;
    let before = snapshot(&second).await?;
    let replay = post(&second, &format!("{BASE}/operations"), apply_input(&preview, request)?).await?;
    assert_eq!(result["sourceCurrent"], true);
    assert_eq!(result["recoveryScopeId"], result["target"]["targetScopeId"]);
    assert_eq!(result["recoveryConfigurationVersion"], 1);
    assert_eq!(result["allowedActions"], json!(["read_receipt", "observe", "archive"]));
    assert_eq!(replay["sourceCurrent"], false);
    assert!(replay["recoveryScopeId"].is_null());
    assert!(replay["recoveryConfigurationVersion"].is_null());
    assert_eq!(replay["allowedActions"], json!(["read_receipt", "archive"]));
    let immutable = |value: &Value| -> DomainResult<Value> {
        let mut original = value.clone();
        let fields = original.as_object_mut().ok_or_else(|| DomainError::Internal("receipt object missing".into()))?;
        for key in ["sourceCurrent", "recoveryScopeId", "recoveryConfigurationVersion", "allowedActions"] {
            assert!(fields.remove(key).is_some(), "missing dynamic qualification field {key}");
        }
        Ok(original)
    };
    assert_eq!(immutable(&replay)?, immutable(&result)?);
    assert_eq!(read(&second, &receipt(request)).await?, replay);
    let mut changed = apply_input(&preview, request)?;
    changed["preview_id"] = json!(Id::new());
    assert_eq!(second.post(&format!("{BASE}/operations"), changed).await.status, StatusCode::CONFLICT);
    assert_eq!(snapshot(&second).await?, before);
    assert_eq!(f.engine.counts().await, (3, 1));
    let foreign = case.foreign_instance().await;
    assert_eq!(foreign.get(&receipt(request)).await.status, StatusCode::NOT_FOUND);
    let otherpolicy = publication_db::mock(&foreign).await?;
    let otherpreview = publication_db::ready(&foreign, &otherpolicy).await?;
    let other = publication_db::apply(&foreign, &otherpreview, request).await?;
    assert_eq!(other["target"]["mocked"], true);
    assert_ne!(other["target"]["targetScopeId"], result["target"]["targetScopeId"]);
    assert_eq!(snapshot(&second).await?, before);
    publication_db::chain(&second).await?;
    publication_db::chain(&foreign).await?;
    case.pool.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_MSE_CONFIG_PUBLICATION_DATABASE_OWNER"]
async fn archive_fault_retains_content_then_tombstone_cas_survives_restart_and_forbids_rollback() -> DomainResult<()> {
    let case = publication_db::open("mse-pub-archive-fault").await?;
    let policy = publication_db::mock(&case.h).await?;
    let preview = publication_db::ready(&case.h, &policy).await?;
    let request = Id::new();
    let original = publication_db::apply(&case.h, &preview, request).await?;
    let state = read(&case.h, BASE).await?;
    let generation = number(&state, "generation")?;
    let before = snapshot(&case.h).await?;
    let target = agf_api::integration_store::id(case.h.tenant, "alicloud-mse");
    let h = case.h.clone();
    with_gate(
        &case.pool,
        h.tenant,
        Target { kind: "mse-config-publication-archive", id: target, action: "update" },
        Mode::Reject,
        move |_| {
            Box::pin(async move {
                let response = publication_db::archive(&h, &[request], generation).await;
                assert!(response.status.is_server_error());
                assert_eq!(snapshot(&h).await?, before);
                publication_db::chain(&h).await
            })
        },
    )
    .await?;
    let response = publication_db::archive(&case.h, &[request], generation).await;
    assert_eq!(response.status, StatusCode::OK);
    let second = case.second_instance().await;
    let archived = read(&second, &receipt(request)).await?;
    assert_eq!(archived["status"], "archived");
    assert_eq!(archived["originalStatus"], original["status"]);
    let marker =
        publication_db::row(&second, DETAIL, publication_db::content_id(second.tenant, request, "operation")).await?;
    assert_eq!(marker["class"], "archived");
    assert!(!marker.to_string().contains("ciphertext"));
    assert_eq!(publication_db::archive(&second, &[request], generation).await.status, StatusCode::CONFLICT);
    let current = read(&second, BASE).await?;
    let unchanged = snapshot(&second).await?;
    let noop = publication_db::archive(&second, &[request], number(&current, "generation")?).await;
    assert_eq!(noop.status, StatusCode::OK);
    assert_eq!(noop.json()["unchanged"], true);
    assert_eq!(snapshot(&second).await?, unchanged);
    post(&second, &format!("{BASE}/operations"), apply_input(&preview, request)?).await?;
    assert_eq!(snapshot(&second).await?, unchanged);
    let observation = post(&second, &format!("{BASE}/observe"), observe_input()).await?;
    let state = read(&second, BASE).await?;
    let response = second
        .post(
            &format!("{BASE}/previews"),
            json!({"request_id":Id::new(),"configuration_version":1,
        "observation_id":id(&observation,"id")?,"expected_state_version":number(&state,"stateVersion")?,
        "change":{"action":"rollback","publication_id":request}}),
        )
        .await;
    assert_eq!(response.status, StatusCode::PRECONDITION_FAILED);
    publication_db::chain(&second).await?;
    case.pool.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_MSE_CONFIG_PUBLICATION_DATABASE_OWNER"]
async fn real_128_operation_capacity_and_single_100_detail_archive_preserve_all_permanent_facts() -> DomainResult<()> {
    let case = publication_db::open("mse-pub-bounded-batch").await?;
    let policy = publication_db::mock(&case.h).await?;
    let mut requests = Vec::new();
    // All ciphertext/AAD/signatures and IDs are produced by real API operations, not copied synthetic records.
    for _ in 0..127 {
        let preview = publication_db::ready(&case.h, &policy).await?;
        let request = Id::new();
        assert_eq!(publication_db::apply(&case.h, &preview, request).await?["status"], "verified");
        requests.push(request);
    }
    let preview = publication_db::ready(&case.h, &policy).await?;
    let second = case.second_instance().await;
    let left = Id::new();
    let right = Id::new();
    let operations_path = format!("{BASE}/operations");
    let (a, b) = tokio::join!(
        case.h.post(&operations_path, apply_input(&preview, left)?),
        second.post(&operations_path, apply_input(&preview, right)?)
    );
    assert_eq!([a.status, b.status].iter().filter(|status| **status == StatusCode::OK).count(), 1);
    assert_eq!([a.status, b.status].iter().filter(|status| **status == StatusCode::CONFLICT).count(), 1);
    requests.push(if a.status == StatusCode::OK { left } else { right });
    let state = read(&second, BASE).await?;
    assert_eq!(state["detailedRunCount"], 128);
    assert_eq!(state["operations"].as_array().map(Vec::len), Some(50));
    let main_id = agf_api::integration_store::id(second.tenant, "alicloud-mse");
    assert_eq!(publication_db::row(&second, MAIN, main_id).await?["operations"].as_array().map(Vec::len), Some(128));
    let mut facts = BTreeMap::new();
    for request in &requests {
        facts.insert(
            *request,
            publication_db::row(&second, FACT, publication_db::fact_id(second.tenant, *request)).await?,
        );
    }
    let unavailable = publication_db::ready(&second, &policy).await?;
    let full = snapshot(&second).await?;
    let rejected = second.post(&format!("{BASE}/operations"), apply_input(&unavailable, Id::new())?).await;
    assert_eq!(rejected.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(
        snapshot(&second).await?,
        full,
        "a rejected full-capacity apply must retain its preview and all business/audit records"
    );
    let generation = number(&read(&second, BASE).await?, "generation")?;
    let before_audits = second.state.store.audit_chain_durable(second.tenant, 0, i64::MAX).await?.len();
    let response = publication_db::archive(&second, &requests[..100], generation).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    assert_eq!(response.json()["archivedRequestIds"].as_array().map(Vec::len), Some(100));
    assert_eq!(second.state.store.audit_chain_durable(second.tenant, 0, i64::MAX).await?.len(), before_audits + 1);
    let state = read(&second, BASE).await?;
    assert_eq!(state["operations"].as_array().map(Vec::len), Some(28));
    assert_eq!(state["detailedRunCount"], 28);
    assert_eq!(state["archivedCount"], 100);
    for (index, request) in requests.iter().enumerate() {
        assert_eq!(
            publication_db::row(&second, FACT, publication_db::fact_id(second.tenant, *request)).await?,
            facts[request]
        );
        let detail =
            publication_db::row(&second, DETAIL, publication_db::content_id(second.tenant, *request, "operation"))
                .await?;
        assert_eq!(detail["class"], if index < 100 { "archived" } else { "content" });
        if index < 100 {
            assert!(!detail.to_string().contains("ciphertext"));
        }
    }
    assert_eq!(publication_db::mock_content(&second).await?.0, 129);
    let fresh = case.second_instance().await;
    assert_eq!(read(&fresh, &receipt(requests[0])).await?["status"], "archived");
    publication_db::chain(&fresh).await?;
    case.pool.close().await;
    Ok(())
}
