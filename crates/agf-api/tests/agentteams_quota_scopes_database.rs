//! Durable actual gateway enforcement across independent API instances and owned tenants.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod agentteams_quota_scope_support;
mod common;
mod configuration_audit_support;
use agentteams_quota_scope_support::*;
use common::*;
use configuration_audit_support::SqlCase;

async fn owner_check() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_quota_scopes_"));
    let expected = std::env::var("AGF_QUOTA_SCOPES_DATABASE_OWNER").expect("set the unique quota scopes SQL owner");
    let id = expected.strip_prefix("AIGuardFabric quota scopes SQL ").expect("wrong SQL owner task");
    assert!(id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect(&url).await.unwrap();
    let owner: Option<String> = sqlx::query_scalar(
        "SELECT shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(owner.as_deref(), Some(expected.as_str()), "database belongs to another task");
    pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a dedicated exact-owned quota scopes SQL database; no production/provider access"]
async fn actual_tokens_and_cost_survive_restart_for_each_scope_and_tenants_are_isolated() {
    owner_check().await; // Before SqlCase::open can run any migration or fixture write.
    for scope in ["tenant", "agent", "session"] {
        let case = SqlCase::open(&format!("quota-scope-{scope}")).await;
        let h = live(case.h.clone());
        let upstream = Loopback::start().await;
        let identities = configure(&h, &upstream).await;
        let tokens = quota(&h, scope, "tokens", "total", 100).await;
        let cost = quota(&h, scope, "cost", "total", 100).await;
        accepted(&call(&h, &identities[0], "durable-session").await);
        assert_settled(&h, &identities[0], "durable-session").await;
        assert_eq!(used(&h, &tokens).await, 100);
        assert_eq!(used(&h, &cost).await, 100);
        assert_eq!(upstream.calls(), 1);

        // This new instance has no process-local endpoint, quota or API Key cache from the call.
        let restarted = live(case.second_instance().await);
        assert_settled(&restarted, &identities[0], "durable-session").await;
        assert_eq!(used(&restarted, &tokens).await, 100);
        assert_eq!(used(&restarted, &cost).await, 100);
        denied(&call(&restarted, &identities[0], "durable-session").await, scope, "tokens/cost");
        assert_eq!(upstream.calls(), 1, "restart must not reset spent allowance");

        let foreign = live(case.foreign_instance().await);
        let foreign_identities = configure(&foreign, &upstream).await;
        assert!(foreign.get(QUOTAS).await.json()["items"].as_array().unwrap().is_empty());
        let other_tokens = quota(&foreign, scope, "tokens", "total", 100).await;
        let other_cost = quota(&foreign, scope, "cost", "total", 100).await;
        // Identical rule names/session strings in another tenant start with independent allowance.
        accepted(&call(&foreign, &foreign_identities[0], "durable-session").await);
        assert_eq!(upstream.calls(), 2);
        assert_eq!(used(&foreign, &other_tokens).await, 100);
        assert_eq!(used(&foreign, &other_cost).await, 100);
        assert_eq!(used(&restarted, &tokens).await, 100);
        assert_eq!(used(&restarted, &cost).await, 100);
        let cross_tenant = call(&foreign, &identities[0], "durable-session").await;
        assert_eq!(cross_tenant.status, StatusCode::FORBIDDEN, "{}", cross_tenant.text);
        assert_eq!(upstream.calls(), 2);
        case.pool.close().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a dedicated exact-owned quota scopes SQL database; no production/provider access"]
async fn two_instances_compete_for_the_last_request_slot_before_any_extra_upstream_call() {
    owner_check().await;
    let case = SqlCase::open("quota-last-slot").await;
    let h = live(case.h.clone());
    let upstream = Loopback::start().await;
    let identities = configure(&h, &upstream).await;
    let name = quota(&h, "tenant", "requests", "total", 1).await;
    let other = live(case.second_instance().await);
    let (left, right) =
        tokio::join!(call(&h, &identities[0], "parallel-a"), call(&other, &identities[1], "parallel-b"));
    assert_eq!([left.status, right.status].iter().filter(|status| **status == StatusCode::OK).count(), 1);
    assert_eq!(
        [left.status, right.status].iter().filter(|status| **status == StatusCode::TOO_MANY_REQUESTS).count(),
        1,
        "{} / {}",
        left.text,
        right.text
    );
    accepted(if left.status == StatusCode::OK { &left } else { &right });
    assert_eq!(upstream.calls(), 1, "SQL reservation must precede provider execution in both instances");
    assert_eq!(used(&h, &name).await, 1);
    assert_eq!(used(&other, &name).await, 1);
    assert_eq!(used(&live(case.second_instance().await), &name).await, 1);
    case.pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a dedicated exact-owned quota scopes SQL database; no production/provider access"]
async fn cancelled_inflight_call_releases_durable_concurrency_for_another_instance() {
    owner_check().await;
    let case = SqlCase::open("quota-cancelled-concurrency").await;
    let h = live(case.h.clone());
    let upstream = Loopback::start().await;
    let identities = configure(&h, &upstream).await;
    let name = quota(&h, "tenant", "concurrency", "day", 1).await;
    let other = live(case.second_instance().await);
    upstream.block();
    let pending = Pending::start(h.clone(), identities[0].clone(), "inflight");
    upstream.arrived().await;
    assert_eq!(used(&other, &name).await, 1);
    denied(&call(&other, &identities[1], "another-session").await, "tenant", "concurrency");
    assert_eq!(upstream.calls(), 1);
    pending.cancel().await;
    wait_released(&other, &name).await;
    upstream.release();
    accepted(&call(&other, &identities[1], "after-cancellation").await);
    assert_eq!(upstream.calls(), 2);
    assert_eq!(used(&h, &name).await, 0);
    assert_eq!(used(&other, &name).await, 0);
    case.pool.close().await;
}
