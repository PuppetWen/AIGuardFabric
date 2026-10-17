//! 测试脚手架：配置、响应包装、Harness 夹具、装配与通用请求辅助。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines, dead_code, unreachable_pub)]

use super::*;

// ===========================================================================
// 测试脚手架
// ===========================================================================

pub fn test_config() -> AppConfig {
    let env: BTreeMap<String, String> = [
        ("AGF_ENV", "test"),
        ("AGF_MOCK_MODE", "1"),
        ("AGF_JWT_SECRET", "unit-test-secret-key-at-least-32-bytes-long"),
        ("AGF_JWT_ISSUER", "aiguardfabric"),
        ("AGF_PROJECT_ROOT", "."),
        ("AGF_DATA_DIR", "./target/test-data"),
        ("AGF_LOG_LEVEL", "warn"),
        ("AGF_PASSWORD_MIN_LENGTH", "12"),
        ("AGF_MASTER_KEY_BASE64", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="),
        ("AGF_LOGIN_MAX_FAILURES", "3"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    agf_core::config::from_env_map(&env).expect("测试配置解析失败")
}

/// 一次响应。
#[derive(Debug)]
pub struct Resp {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub text: String,
    pub bytes: Vec<u8>,
}

impl Resp {
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.text).unwrap_or(Value::Null)
    }

    pub fn code(&self) -> String {
        self.json().get("code").and_then(Value::as_str).unwrap_or_default().to_string()
    }

    pub fn header(&self, name: &str) -> String {
        self.headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or_default().to_string()
    }

    pub fn content_type(&self) -> String {
        self.header("content-type")
    }
}

/// 测试夹具。
#[derive(Clone)]
pub struct Harness {
    pub app: Router,
    pub state: AppState,
    pub admin: String,
    pub viewer: String,
    pub api_key: String,
    pub tenant: TenantId,
    pub other_tenant: TenantId,
}

impl Harness {
    pub async fn request(&self, method: &str, uri: &str, token: Option<&str>, body: Option<Value>) -> Resp {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(token) = token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        if body.is_some() {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
        }
        let request = builder.body(body.map_or_else(Body::empty, |v| Body::from(v.to_string()))).expect("构造请求失败");
        send(&self.app, request).await
    }

    pub async fn request_with(&self, method: &str, uri: &str, headers: &[(&str, &str)], body: Option<Value>) -> Resp {
        let mut builder = Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        if body.is_some() {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
        }
        let request = builder.body(body.map_or_else(Body::empty, |v| Body::from(v.to_string()))).expect("构造请求失败");
        send(&self.app, request).await
    }

    pub async fn get(&self, uri: &str) -> Resp {
        self.request("GET", uri, Some(&self.admin), None).await
    }

    pub async fn post(&self, uri: &str, body: Value) -> Resp {
        self.request("POST", uri, Some(&self.admin), Some(body)).await
    }
}

pub async fn send(app: &Router, request: Request<Body>) -> Resp {
    let response = app.clone().oneshot(request).await.expect("路由执行失败");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 32 * 1024 * 1024).await.expect("读取响应体失败");
    let text = String::from_utf8_lossy(&bytes).to_string();
    Resp { status, headers, text, bytes: bytes.to_vec() }
}

pub async fn setup() -> Harness {
    setup_with_limits(RateLimitTiers::default()).await
}

pub async fn setup_with_limits(tiers: RateLimitTiers) -> Harness {
    let mut config = test_config();
    // Each harness owns its history directory; never read another case's or the deployment's samples.
    config.data_dir = format!("./target/test-data/harness-{}", agf_core::ids::Id::new());
    let mut state = AppState::offline(config).expect("AppState 装配失败");
    state.limiter = Arc::new(agf_api::middleware::RateLimiter::new(tiers));

    let tenant = TenantId::default_tenant();

    // 超级管理员（不改密）
    let created = state
        .ensure_bootstrap_admin(tenant, "admin", "admin@test.local", Some(ADMIN_PWD), false)
        .await
        .expect("创建引导管理员失败");
    let admin_user = match created {
        BootstrapOutcome::Created { user, .. } | BootstrapOutcome::AlreadyExists { user } => user,
    };
    let admin = state
        .auth
        .issue_for_user(&admin_user, tenant, vec!["superadmin".to_string()])
        .expect("签发管理员令牌失败")
        .access_token;

    // 只读观察者（用于 403 / 跨租户）
    let hasher = PasswordHasher::new(state.auth.policy().clone());
    let viewer_phc = hasher.hash_checked(VIEWER_PWD, "viewer").expect("哈希失败");
    let mut viewer_user = User::new_local(tenant, "viewer", "viewer@test.local");
    viewer_user.must_change_password = false;
    state
        .auth_backend
        .save_account(&viewer_user, Some(&viewer_phc), &["viewer".to_string()])
        .await
        .expect("保存账号失败");
    let viewer = state
        .auth
        .issue_for_user(&viewer_user, tenant, vec!["viewer".to_string()])
        .expect("签发观察者令牌失败")
        .access_token;

    // 首登必须改密的用户
    let newbie_phc = hasher.hash_checked(NEWBIE_PWD, "newbie").expect("哈希失败");
    let mut newbie = User::new_local(tenant, "newbie", "newbie@test.local");
    newbie.must_change_password = true;
    state
        .auth_backend
        .save_account(&newbie, Some(&newbie_phc), &["soc-analyst".to_string()])
        .await
        .expect("保存账号失败");

    // API Key（仅 assets:* 权限）
    let issued = state.api_keys.issue(ApiKeyIssueRequest {
        scopes: vec![Permission::from_raw("assets:*")],
        ..ApiKeyIssueRequest::named(tenant, "integration-test", Timestamp::now())
    });
    state.store.api_key_insert(issued.record.clone()).expect("写入 API Key 失败");

    let other = agf_api::tenant_directory::new("other-test".into(), "Other test tenant".into());
    let other_tenant = other.id;
    agf_api::tenant_directory::save(&state, other, true).await.expect("创建隔离租户");
    let app = build_router(state.clone());
    Harness { app, state, admin, viewer, api_key: issued.plaintext, tenant, other_tenant }
}

/// 发起一次资产发现导入，返回批次统计。
pub async fn ingest_mcp(h: &Harness, fingerprint: &str, endpoint: &str) -> Resp {
    h.post(
        "/api/v1/assets/discovery",
        json!({
            "source": "agent-report",
            "assets": [{
                "kind": "mcp-server",
                "name": format!("mcp-{fingerprint}"),
                "fingerprint": fingerprint,
                "endpoint": endpoint,
                "exposure_score": 82,
                "has_plaintext_secret": true,
            }]
        }),
    )
    .await
}
