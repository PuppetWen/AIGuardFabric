//! Dedicated SQL tenants and independent API instances for configuration/audit rollback tests.
#![allow(dead_code)]
use crate::common::*;
#[path = "../common/sql_runtime_identity.rs"]
mod sql_runtime_identity;
use agf_core::{audit::AuditLog, ids::Id};
use agf_storage::{Database, Store, configuration::ConfigStore, objectstore::MemoryObjectStore};

pub(crate) struct SqlCase {
    pub(crate) h: Harness,
    pub(crate) pool: sqlx::PgPool,
    store: Arc<Store>,
}

impl SqlCase {
    pub(crate) async fn open(label: &str) -> Self {
        let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
        assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
        let pool = sqlx::postgres::PgPoolOptions::new().max_connections(8).connect(&url).await.unwrap();
        let database = Database::from_pool(pool.clone());
        database.migrate().await.unwrap();
        let store = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
        let tenant = agf_api::tenant_directory::new(format!("{label}-{}", Id::new()), label.into());
        let h = instance(store.clone(), tenant.id, None).await;
        agf_api::tenant_directory::save(&h.state, tenant, true).await.unwrap();
        Self { h, pool, store }
    }

    /// Fresh process-local locks and configuration cache, sharing only durable storage.
    pub(crate) async fn second_instance(&self) -> Harness {
        instance(self.store.clone(), self.h.tenant, Some(&self.h)).await
    }

    pub(crate) async fn foreign_instance(&self) -> Harness {
        let tenant = agf_api::tenant_directory::new(format!("foreign-{}", Id::new()), "Foreign audit tenant".into());
        agf_api::tenant_directory::save(&self.h.state, tenant.clone(), true).await.unwrap();
        instance(self.store.clone(), tenant.id, Some(&self.h)).await
    }

    pub(crate) async fn block_audit(&self) -> String {
        let name = format!("agf_test_revision_audit_{}", Id::new().as_uuid().simple());
        sqlx::query(&format!(
            "ALTER TABLE audit_logs ADD CONSTRAINT {name} CHECK (tenant_id <> '{}'::uuid) NOT VALID",
            self.h.tenant
        ))
        .execute(&self.pool)
        .await
        .unwrap();
        name
    }

    pub(crate) async fn unblock_audit(&self, name: &str) {
        assert!(
            name.starts_with("agf_test_revision_audit_")
                && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
        );
        sqlx::query(&format!("ALTER TABLE audit_logs DROP CONSTRAINT {name}")).execute(&self.pool).await.unwrap();
    }

    pub(crate) async fn rows(&self, kind: &str) -> Vec<Value> {
        let mut rows: Vec<Value> = self.h.state.configurations.list(self.h.tenant, kind).await.unwrap();
        rows.sort_by_key(Value::to_string);
        rows
    }

    pub(crate) async fn audit_stats(&self) -> (i64, String) {
        self.h.state.store.audit_stats_durable(self.h.tenant).await.unwrap()
    }
}

async fn instance(store: Arc<Store>, tenant: TenantId, identity: Option<&Harness>) -> Harness {
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(store.clone()));
    h.state.configurations = Arc::new(ConfigStore::new(Some(store)));
    if let Some(original) = identity {
        // 仅将原账号作为复制来源；下面重建后端，不共享进程内身份缓存或锁。
        h.state.auth_backend = original.state.auth_backend.clone();
        h.admin.clone_from(&original.admin);
        h.viewer.clone_from(&original.viewer);
    }
    // 原 User、角色、PHC、版本和 JWT 保持不变；MFA 读取绑定本实例配置。
    sql_runtime_identity::rebind(&mut h.state, &[tenant]).await.unwrap();
    h.tenant = tenant;
    h.app = build_router(h.state.clone()).layer(axum::middleware::map_request(move |mut request: Request<Body>| {
        request.headers_mut().insert("x-agf-tenant", tenant.to_string().parse().unwrap());
        async move { request }
    }));
    h
}

pub(crate) async fn audits(h: &Harness, kind: &str) -> Vec<AuditLog> {
    h.state
        .store
        .audit_chain_durable(h.tenant, 0, i64::MAX)
        .await
        .unwrap()
        .into_iter()
        .filter(|row| row.target.kind == kind)
        .collect()
}

pub(crate) fn assert_audit_failure(response: &Resp) {
    assert!(response.status.is_server_error(), "valid mutation must fail at audit commit: {}", response.text);
}
