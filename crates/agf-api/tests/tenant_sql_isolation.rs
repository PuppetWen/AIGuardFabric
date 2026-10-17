//! Two real tenant accounts must remain isolated across independent API instances.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::ids::Id;
use agf_storage::{Database, Store, objectstore::MemoryObjectStore};
use common::*;

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    tenant: Option<&str>,
    body: Option<Value>,
) -> Resp {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    if let Some(tenant) = tenant {
        builder = builder.header("x-agf-tenant", tenant);
    }
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    send(app, builder.body(body.map_or_else(Body::empty, |value| Body::from(value.to_string()))).unwrap()).await
}

async fn login(app: &Router, slug: &str, password: &str) -> String {
    let response = call(
        app,
        "POST",
        "/api/v1/auth/login",
        None,
        None,
        Some(json!({"tenant_slug":slug,"username":"manager","password":password})),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    response.json()["tokens"]["access_token"].as_str().unwrap().to_owned()
}

async fn provision(app: &Router, admin: &str, slug: &str) -> String {
    let created = call(
        app,
        "POST",
        "/api/v1/tenants",
        Some(admin),
        None,
        Some(json!({"slug":slug,"name":format!("Tenant {slug}")})),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
    let tenant = created.json()["id"].as_str().unwrap().to_owned();
    let user = call(
        app,
        "POST",
        "/api/v1/users",
        Some(admin),
        Some(&tenant),
        Some(json!({"username":"manager","email":format!("manager@{slug}.example.test"),
            "password":NEWBIE_PWD,"role":"admin"})),
    )
    .await;
    assert_eq!(user.status, StatusCode::CREATED, "{}", user.text);
    tenant
}

async fn activate(app: &Router, slug: &str, password: &str) -> String {
    let first = call(
        app,
        "POST",
        "/api/v1/auth/login",
        None,
        None,
        Some(json!({"tenant_slug":slug,"username":"manager","password":NEWBIE_PWD})),
    )
    .await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.text);
    let change = first.json()["change_token"].as_str().unwrap().to_owned();
    let changed =
        call(app, "POST", "/api/v1/auth/change-password", Some(&change), None, Some(json!({"new_password":password})))
            .await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.text);
    login(app, slug, password).await
}

fn application(name: &str) -> Value {
    json!({"request_id":Id::new(),"fingerprint":"shared-fingerprint","kind":"skill",
        "name":name,"owner":"manager","department":"Security","data_class":"internal",
        "note":"Tenant SQL isolation test","endpoint":"stdio:fixture","version":"1"})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn tenant_accounts_write_read_and_disable_across_instances() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").expect("AGF_TEST_DATABASE_URL");
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(8).connect(&url).await.unwrap();
    let database = Database::from_pool(pool.clone());
    database.migrate().await.unwrap();
    let store = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let mut config = test_config();
    if let Ok(data_dir) = std::env::var("AGF_TEST_DATA_DIR") {
        config.data_dir = data_dir;
    }
    let first = AppState::with_database(config.clone(), store.clone()).unwrap();
    let bootstrap = first
        .ensure_bootstrap_admin(TenantId::default_tenant(), "admin", "admin@test.local", Some(ADMIN_PWD), false)
        .await
        .unwrap();
    let user = match bootstrap {
        BootstrapOutcome::Created { user, .. } | BootstrapOutcome::AlreadyExists { user } => user,
    };
    let admin =
        first.auth.issue_for_user(&user, TenantId::default_tenant(), vec!["superadmin".into()]).unwrap().access_token;
    let app_a = build_router(first);
    let suffix = Id::new().as_uuid().simple().to_string();
    let slug_a = format!("sql-a-{suffix}");
    let slug_b = format!("sql-b-{suffix}");
    let tenant_a = provision(&app_a, &admin, &slug_a).await;
    let tenant_b = provision(&app_a, &admin, &slug_b).await;
    let second = AppState::with_database(config, store).unwrap();
    let app_b = build_router(second);
    for app in [&app_a, &app_b] {
        let directory = call(app, "GET", "/api/v1/tenants", Some(&admin), None, None).await;
        assert_eq!(directory.status, StatusCode::OK, "{}", directory.text);
        let tenants = directory.json();
        let row = tenants.as_array().unwrap().iter().find(|row| row["id"] == tenant_a).unwrap();
        assert_eq!(row["version"], 0);
        assert_eq!(row["directory_version"], 1);
        assert_eq!(row["directory_name"], format!("Tenant {slug_a}"));
    }
    let password_b = "Db7#qP2!mL9$Xy4";
    let token_a = activate(&app_b, &slug_a, ADMIN_PWD).await;
    let token_b = activate(&app_b, &slug_b, password_b).await;
    for (slug, wrong_password) in [(&slug_a, password_b), (&slug_b, ADMIN_PWD)] {
        assert_eq!(
            call(
                &app_a,
                "POST",
                "/api/v1/auth/login",
                None,
                None,
                Some(json!({"tenant_slug":slug,"username":"manager","password":wrong_password}))
            )
            .await
            .status,
            StatusCode::UNAUTHORIZED
        );
    }
    let write_a =
        call(&app_a, "POST", "/api/v1/assets/register", Some(&token_a), None, Some(application("Tenant A skill")))
            .await;
    assert_eq!(write_a.status, StatusCode::OK, "{}", write_a.text);
    let write_b =
        call(&app_b, "POST", "/api/v1/assets/register", Some(&token_b), None, Some(application("Tenant B skill")))
            .await;
    assert_eq!(write_b.status, StatusCode::OK, "{}", write_b.text);
    let id_a = write_a.json()["asset"]["id"].as_str().unwrap().to_owned();
    let id_b = write_b.json()["asset"]["id"].as_str().unwrap().to_owned();
    assert_ne!(id_a, id_b, "the same fingerprint belongs to two different assets");
    for app in [&app_a, &app_b] {
        let list_a = call(app, "GET", "/api/v1/assets", Some(&token_a), None, None).await;
        let list_b = call(app, "GET", "/api/v1/assets", Some(&token_b), None, None).await;
        assert_eq!(list_a.status, StatusCode::OK, "{}", list_a.text);
        assert_eq!(list_b.status, StatusCode::OK, "{}", list_b.text);
        assert_eq!(list_a.json()["total"], 1);
        assert_eq!(list_b.json()["total"], 1);
        assert_eq!(list_a.json()["items"][0]["id"], id_a);
        assert_eq!(list_b.json()["items"][0]["id"], id_b);
        assert_eq!(
            call(app, "GET", &format!("/api/v1/assets/{id_b}"), Some(&token_a), None, None).await.status,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            call(app, "GET", &format!("/api/v1/assets/{id_a}"), Some(&token_b), None, None).await.status,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            call(app, "GET", "/api/v1/assets", Some(&token_a), Some(&tenant_b), None).await.status,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(app, "GET", "/api/v1/assets", Some(&token_b), Some(&tenant_a), None).await.status,
            StatusCode::FORBIDDEN
        );
    }
    let path_b = format!("/api/v1/assets/{id_b}");
    let detail_b = call(&app_a, "GET", &path_b, Some(&token_b), None, None).await.json();
    let edit_b = json!({"name":"Tenant B revised skill","owner":"manager","department":"Security",
        "data_class":"restricted","expected_updated_at":detail_b["governance"]["updated_at"],
        "reason":"Cross-instance ownership review"});
    assert_eq!(
        call(&app_a, "PATCH", &path_b, Some(&token_a), None, Some(edit_b.clone())).await.status,
        StatusCode::NOT_FOUND
    );
    let own_edit = call(&app_b, "PATCH", &path_b, Some(&token_b), None, Some(edit_b)).await;
    assert_eq!(own_edit.status, StatusCode::OK, "{}", own_edit.text);
    assert_eq!(
        call(&app_a, "GET", &path_b, Some(&token_b), None, None).await.json()["asset"]["name"],
        "Tenant B revised skill"
    );
    let path_a = format!("/api/v1/assets/{id_a}");
    let changed = call(
        &app_b,
        "POST",
        &format!("{path_a}/transition"),
        Some(&token_a),
        None,
        Some(json!({"to":"under-review","note":"Reviewed by tenant A"})),
    )
    .await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.text);
    assert_eq!(
        call(&app_a, "GET", &path_a, Some(&token_a), None, None).await.json()["asset"]["lifecycle"],
        "under-review"
    );
    assert_eq!(
        call(
            &app_a,
            "POST",
            &format!("{path_a}/transition"),
            Some(&token_b),
            None,
            Some(json!({"to":"rejected","note":"Cross-tenant write"}))
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );
    let disabled = call(
        &app_a,
        "PATCH",
        &format!("/api/v1/tenants/{tenant_a}"),
        Some(&admin),
        None,
        Some(json!({"name":format!("Tenant {slug_a}"),"enabled":false,"expected_version":1})),
    )
    .await;
    assert_eq!(disabled.status, StatusCode::OK, "{}", disabled.text);
    let directory = call(&app_b, "GET", "/api/v1/tenants", Some(&admin), None, None).await;
    let tenants = directory.json();
    let row = tenants.as_array().unwrap().iter().find(|row| row["id"] == tenant_a).unwrap();
    assert_eq!(row["directory_version"], 2);
    assert_eq!(call(&app_b, "GET", "/api/v1/assets", Some(&token_a), None, None).await.status, StatusCode::FORBIDDEN);
    assert_eq!(call(&app_a, "GET", "/api/v1/assets", Some(&token_b), None, None).await.status, StatusCode::OK);
    pool.close().await;
}
