//! 只在精确 Owned 数据库内装配生产身份后端，并证明事务不再借用第二条连接。
use crate::{audit_anchor_database_support::Owned, common::*, runtime_audit_persistence_support::*};
use agf_auth::service::{AuthBackend, InMemoryAuthBackend};
use agf_core::{enums::AssetKind, error::DomainResult, ids::Id};
use axum::extract::FromRequestParts;
use std::time::Duration;

mod wait;
pub(crate) use wait::revoked_during_audit_wait;

/// 显式装配内存账号 + 当前 SQL 配置，不能沿用 setup 的旧离线 MFA 配置引用。
pub(crate) async fn memory_identity(mut h: Harness) -> DomainResult<Harness> {
    let backend = Arc::new(InMemoryAuthBackend::new());
    for token in [&h.admin, &h.viewer] {
        let principal = identity_principal(&h, token).await;
        let tenant = principal.identity_tenant;
        let id = principal.subject_id.expect("真实账号主体");
        let mut user = h.state.auth_backend.find_user(tenant, id).await?.expect("原内存账号");
        let roles = h.state.auth_backend.roles_of(tenant, id).await?;
        user.version = 0;
        backend.save_account(&user, None, &roles).await?;
    }
    h.state.auth_backend = Arc::new(agf_api::auth_store::protected::ProtectedBackend::new(
        backend,
        h.state.configurations.clone(),
        &h.state.config.security.master_key_b64,
    ));
    h.app = build_router(h.state.clone()).layer(axum::middleware::map_request({
        let tenant = h.tenant;
        move |mut request: Request<Body>| {
            request.headers_mut().insert("x-agf-tenant", tenant.to_string().parse().unwrap());
            async move { request }
        }
    }));
    Ok(h)
}

/// 保留真实 JWT 标识，把测试原内存账号显式迁入同一独占 SQL 身份库。
pub(crate) async fn sql_identity(mut h: Harness) -> DomainResult<Harness> {
    let store = h.state.store.database().cloned().expect("Owned 必须使用 SQL Store");
    let backend = Arc::new(agf_api::auth_store::SqlAuthBackend::new(store));
    for token in [&h.admin, &h.viewer] {
        let principal = identity_principal(&h, token).await;
        let tenant = principal.identity_tenant;
        let id = principal.subject_id.expect("真实账号主体");
        if backend.find_user(tenant, id).await?.is_none() {
            let mut user = h.state.auth_backend.find_user(tenant, id).await?.expect("原内存账号");
            let roles = h.state.auth_backend.roles_of(tenant, id).await?;
            // 多个独立 Harness 共享 default 身份租户，但不能共享用户名或邮箱。
            user.username = format!("owned-{}", id.as_uuid().simple());
            user.email = format!("{}@owned.invalid", id.as_uuid().simple());
            user.version = 0;
            backend.save_account(&user, None, &roles).await?;
        }
    }
    h.state.auth_backend = Arc::new(agf_api::auth_store::protected::ProtectedBackend::new(
        backend,
        h.state.configurations.clone(),
        &h.state.config.security.master_key_b64,
    ));
    h.app = build_router(h.state.clone()).layer(axum::middleware::map_request({
        let tenant = h.tenant;
        move |mut request: Request<Body>| {
            request.headers_mut().insert("x-agf-tenant", tenant.to_string().parse().unwrap());
            async move { request }
        }
    }));
    Ok(h)
}

// 复制账号时只解析 JWT 原身份租户；普通 viewer 不能切到业务租户。
// 实际业务请求仍由下方 principal 和原路由中间件带租户头，跨租户保护不变。
async fn identity_principal(h: &Harness, token: &str) -> agf_api::Principal {
    let request = Request::builder()
        .uri("/api/v1/runtime/mcp/check")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let (mut parts, _) = request.into_parts();
    agf_api::Principal::from_request_parts(&mut parts, &h.state).await.unwrap()
}

async fn principal(h: &Harness, header: &str, value: &str) -> agf_api::Principal {
    let request = Request::builder()
        .uri("/api/v1/runtime/mcp/check")
        .header(header, value)
        .header("X-AGF-Tenant", h.tenant.to_string())
        .body(Body::empty())
        .unwrap();
    let (mut parts, _) = request.into_parts();
    agf_api::Principal::from_request_parts(&mut parts, &h.state).await.unwrap()
}

async fn bound_key(h: &Harness) -> (Id, String) {
    assert_eq!(seed_ai_assets(h).await.status, StatusCode::OK);
    let agent = asset_id_of(h, AssetKind::Agent);
    let response = h
        .post(
            "/api/v1/settings/api-keys",
            json!({
                "name":format!("owned-runtime-authority-{}",Id::new()),
                "scopes":["policies:read"],"bound_agent_id":agent
            }),
        )
        .await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.text);
    let id = serde_json::from_value(response.json()["api_key"]["id"].clone()).unwrap();
    (id, response.json()["plaintext"].as_str().unwrap().to_owned())
}

/// 8 连接的独占池持有 7 个空闲连接，剩余 1 个必须完成生产 SQL 用户及绑定 Key 提交。
pub(crate) async fn one_connection(owned: &Owned, h: &Harness) -> DomainResult<()> {
    owned.verify().await?;
    let (_, key) = bound_key(h).await;
    let actors = [actor(h).await, principal(h, "X-AGF-Key", &key).await];
    let template = records(h).await.remove(0);
    let before = facts(h).await.len();
    let mut guards = Vec::new();
    for _ in 0..7 {
        guards.push(owned.case.pool.acquire().await.unwrap());
    }
    for principal in actors {
        let mut record = template.clone();
        record.id = Id::new();
        record.agent_id = principal.agent_id;
        record.seal();
        for _ in 0..2 {
            tokio::time::timeout(
                Duration::from_secs(3),
                agf_api::runtime_audit::persist(&h.state, &principal, &record),
            )
            .await
            .expect("只剩一条池连接时，MCP 保存不得借第二条连接")?;
        }
        let response = tokio::time::timeout(Duration::from_secs(3), integrity(h, &record))
            .await
            .expect("单连接下完整性读取也必须完成");
        assert_eq!(response.status, StatusCode::OK, "{}", response.text);
        assert_eq!(response.json()["summary_matches"], true);
    }
    drop(guards);
    assert_eq!(facts(h).await.len(), before + 2, "每个 exact retry 只能有一条管理审计");
    owned.verify().await
}
