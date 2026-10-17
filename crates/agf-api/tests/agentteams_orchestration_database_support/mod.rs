//! Separate exact-owned SQL database and normal durable accounts; no forced tenant middleware.
use crate::common::*;
use agf_core::ids::Id;
use agf_storage::{Database, Store, objectstore::MemoryObjectStore};
use futures::FutureExt;
use std::{future::Future, panic::AssertUnwindSafe};
mod audit_wait;
mod gate;

pub(crate) struct Case {
    pub(crate) h: Harness,
    pub(crate) pool: sqlx::PgPool,
    store: Arc<Store>,
    database: String,
    owner: String,
    oid: i64,
}
impl Case {
    pub(crate) async fn open(label: &str) -> Self {
        let owner = std::env::var("AGF_AGENTTEAMS_ORCHESTRATION_DATABASE_OWNER").unwrap();
        let run = owner
            .strip_prefix("AIGuardFabric AgentTeams orchestration SQL ")
            .filter(|run| run.len() == 32 && run.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
            .unwrap();
        let database = format!("agf_requirements_test_orchestration_{}", &run[..12]);
        let raw = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
        let url = url::Url::parse(&raw).unwrap();
        assert!(matches!(url.scheme(), "postgres" | "postgresql"));
        assert_eq!(url.host_str(), Some("127.0.0.1"));
        assert_eq!(url.port(), Some(5432));
        assert_eq!(url.path(), format!("/{database}"));
        assert!(url.query().is_none() && url.fragment().is_none());
        let pool = sqlx::postgres::PgPoolOptions::new().max_connections(10).connect(&raw).await.unwrap();
        let (actual,comment,oid):(String,Option<String>,i64)=sqlx::query_as("SELECT current_database(),shobj_description(oid,'pg_database'),oid::bigint FROM pg_database WHERE datname=current_database()").fetch_one(&pool).await.unwrap();
        assert_eq!(actual, database);
        assert_eq!(comment, Some(owner.clone()));
        assert!(oid > 0);
        let db = Database::from_pool(pool.clone());
        db.migrate().await.unwrap();
        let store = Arc::new(Store::new(db, None, Arc::new(MemoryObjectStore::new())));
        let tenant = agf_api::tenant_directory::new(format!("{label}-{}", Id::new()), label.into());
        let state = AppState::with_database(test_config(), store.clone()).unwrap();
        agf_api::tenant_directory::save(&state, tenant.clone(), true).await.unwrap();
        let h = instance(store.clone(), tenant.id).await;
        Self { h, pool, store, database, owner, oid }
    }
    pub(crate) async fn check(&self) {
        let actual:(String,Option<String>,i64)=sqlx::query_as("SELECT current_database(),shobj_description(oid,'pg_database'),oid::bigint FROM pg_database WHERE datname=current_database()").fetch_one(&self.pool).await.unwrap();
        assert_eq!(actual, (self.database.clone(), Some(self.owner.clone()), self.oid));
    }
    pub(crate) async fn second(&self) -> Harness {
        self.check().await;
        instance(self.store.clone(), self.h.tenant).await
    }
    pub(crate) async fn foreign(&self) -> Harness {
        self.check().await;
        let tenant = agf_api::tenant_directory::new(format!("foreign-orch-{}", Id::new()), "Foreign".into());
        agf_api::tenant_directory::save(&self.h.state, tenant.clone(), true).await.unwrap();
        instance(self.store.clone(), tenant.id).await
    }
    pub(crate) async fn fault<F, Fut>(&self, body: F)
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = ()>,
    {
        self.check().await;
        let name = format!("agf_orchestration_fault_{}", Id::new().as_uuid().simple());
        let ddl = format!(
            "ALTER TABLE audit_logs ADD CONSTRAINT {name} CHECK (tenant_id<>'{}'::uuid OR target->>'kind'<>'agentteams-application-orchestration') NOT VALID",
            self.h.tenant
        );
        sqlx::query(&ddl).execute(&self.pool).await.unwrap();
        let result = AssertUnwindSafe(body()).catch_unwind().await;
        self.check().await;
        sqlx::query(&format!("ALTER TABLE audit_logs DROP CONSTRAINT {name}")).execute(&self.pool).await.unwrap();
        if let Err(error) = result {
            std::panic::resume_unwind(error);
        }
    }
}
async fn instance(store: Arc<Store>, tenant: TenantId) -> Harness {
    let state = AppState::with_database(test_config(), store).unwrap();
    let saved =
        state.ensure_bootstrap_admin(tenant, "admin", "admin@owned.test", Some(ADMIN_PWD), false).await.unwrap();
    let user = match saved {
        BootstrapOutcome::Created { user, .. } | BootstrapOutcome::AlreadyExists { user } => user,
    };
    let admin = state.auth.issue_for_user(&user, tenant, vec!["superadmin".into()]).unwrap().access_token;
    if state.auth_backend.find_user_with_secret(tenant, "viewer").await.unwrap().is_none() {
        let mut viewer = User::new_local(tenant, "viewer", "viewer@owned.test");
        viewer.must_change_password = false;
        let phc = state.auth.hasher().hash_checked(VIEWER_PWD, "viewer").unwrap();
        state.auth_backend.save_account(&viewer, Some(&phc), &["viewer".into()]).await.unwrap();
    }
    let viewer = state.auth_backend.find_user_with_secret(tenant, "viewer").await.unwrap().unwrap().user;
    let viewer_token = state.auth.issue_for_user(&viewer, tenant, vec!["viewer".into()]).unwrap().access_token;
    Harness {
        app: build_router(state.clone()),
        state,
        admin,
        viewer: viewer_token,
        api_key: String::new(),
        tenant,
        other_tenant: tenant,
    }
}
