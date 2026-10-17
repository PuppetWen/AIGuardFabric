//! Twelve platform scope/dimension combinations exercised through actual priced HTTP calls.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod agentteams_quota_scope_support;
mod common;
use agentteams_quota_scope_support::*;
use common::*;

async fn cumulative(scope: &str, dimension: &str) {
    let h = live(setup().await);
    let upstream = Loopback::start().await;
    let identities = configure(&h, &upstream).await;
    let charge = if dimension == "requests" { 1 } else { 100 };
    let name = quota(&h, scope, dimension, "total", charge).await;
    accepted(&call(&h, &identities[0], "same-session").await);
    assert_settled(&h, &identities[0], "same-session").await;
    assert_eq!(upstream.calls(), 1);
    assert_eq!(used(&h, &name).await, charge, "{scope}/{dimension} must settle actual usage");

    // Tenant spans both identities; Agent survives session changes; Session spans Agents.
    let (identity, session) = match scope {
        "tenant" => (&identities[1], "new-session"),
        "agent" => (&identities[0], "new-session"),
        "session" => (&identities[1], "same-session"),
        _ => unreachable!(),
    };
    denied(&call(&h, identity, session).await, scope, dimension);
    assert_eq!(upstream.calls(), 1, "{scope}/{dimension}: rejected request reached upstream");
    assert_eq!(used(&h, &name).await, charge, "rejection must not consume an extra charge");

    if scope != "tenant" {
        let (identity, session) =
            if scope == "agent" { (&identities[1], "same-session") } else { (&identities[0], "new-session") };
        accepted(&call(&h, identity, session).await);
        assert_eq!(upstream.calls(), 2);
        // The list reports the sum of independent identity buckets, not a tenant shared limit.
        assert_eq!(used(&h, &name).await, charge * 2);
        denied(&call(&h, &identities[0], "same-session").await, scope, dimension);
        assert_eq!(upstream.calls(), 2);
    }
}

async fn concurrent(scope: &str) {
    let h = live(setup().await);
    let upstream = Loopback::start().await;
    let identities = configure(&h, &upstream).await;
    let name = quota(&h, scope, "concurrency", "minute", 1).await;
    upstream.block();
    let first = Pending::start(h.clone(), identities[0].clone(), "same-session");
    upstream.arrived().await;
    assert_eq!(used(&h, &name).await, 1);
    let (identity, session) = match scope {
        "tenant" => (&identities[1], "new-session"),
        "agent" => (&identities[0], "new-session"),
        "session" => (&identities[1], "same-session"),
        _ => unreachable!(),
    };
    denied(&call(&h, identity, session).await, scope, "concurrency");
    assert_eq!(upstream.calls(), 1);
    assert_eq!(used(&h, &name).await, 1);

    let independent = if scope == "tenant" {
        None
    } else {
        let (identity, session) = if scope == "agent" {
            (identities[1].clone(), "same-session")
        } else {
            (identities[0].clone(), "new-session")
        };
        let pending = Pending::start(h.clone(), identity, session);
        upstream.arrived().await;
        assert_eq!(used(&h, &name).await, 2);
        Some(pending)
    };
    let calls_before_finish = upstream.calls();
    upstream.release();
    accepted(&first.finish().await);
    if let Some(pending) = independent {
        accepted(&pending.finish().await);
    }
    assert_eq!(used(&h, &name).await, 0, "known completion must return concurrent capacity");
    accepted(&call(&h, &identities[0], "same-session").await);
    assert_eq!(upstream.calls(), calls_before_finish + 1);
    assert_eq!(used(&h, &name).await, 0);
}

// Separate names identify the exact failed combination in cargo test output.
macro_rules! cumulative_case {
    ($name:ident, $scope:literal, $dimension:literal) => {
        #[tokio::test]
        async fn $name() {
            cumulative($scope, $dimension).await;
        }
    };
}
macro_rules! concurrency_case {
    ($name:ident, $scope:literal) => {
        #[tokio::test]
        async fn $name() {
            concurrent($scope).await;
        }
    };
}
cumulative_case!(tenant_tokens_actual_gateway_usage, "tenant", "tokens");
cumulative_case!(tenant_requests_actual_gateway_usage, "tenant", "requests");
cumulative_case!(tenant_cost_actual_priced_gateway_usage, "tenant", "cost");
concurrency_case!(tenant_concurrency_actual_gateway_calls, "tenant");
cumulative_case!(agent_tokens_actual_gateway_usage, "agent", "tokens");
cumulative_case!(agent_requests_actual_gateway_usage, "agent", "requests");
cumulative_case!(agent_cost_actual_priced_gateway_usage, "agent", "cost");
concurrency_case!(agent_concurrency_actual_gateway_calls, "agent");
cumulative_case!(session_tokens_actual_gateway_usage, "session", "tokens");
cumulative_case!(session_requests_actual_gateway_usage, "session", "requests");
cumulative_case!(session_cost_actual_priced_gateway_usage, "session", "cost");
concurrency_case!(session_concurrency_actual_gateway_calls, "session");

#[tokio::test]
async fn session_window_does_not_change_tenant_or_agent_identity_scope() {
    // A session window is a non-rolling bucket. Only scope=session partitions by X-AGF-Session.
    for scope in ["tenant", "agent"] {
        let h = live(setup().await);
        let upstream = Loopback::start().await;
        let identities = configure(&h, &upstream).await;
        let name = quota(&h, scope, "requests", "session", 1).await;
        accepted(&call(&h, &identities[0], "session-one").await);
        denied(&call(&h, &identities[0], "session-two").await, scope, "requests");
        assert_eq!(upstream.calls(), 1);
        assert_eq!(used(&h, &name).await, 1);
    }
}
