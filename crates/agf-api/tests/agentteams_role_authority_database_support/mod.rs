//! A dedicated, owner-checked database, real SQL identities, and two independent API states.
use crate::common::*;
use agf_core::ids::Id;
use agf_storage::{Database, Store, objectstore::MemoryObjectStore};
use futures::FutureExt;
use std::{future::Future, panic::AssertUnwindSafe};

mod audit_wait;
mod gate;

pub(crate) const BASE: &str = "/api/v1/alicloud/agentteams/role-mappings";
pub(crate) const CONFIG: &str = "/api/v1/alicloud/connections/alicloud-agentteams";
pub(crate) const KIND: &str = "agentteams-role-governance";
pub(crate) const INTENTS: &str = "agentteams-role-governance-intent";
pub(crate) const MARKER: &str = "agf.agentteams.role_governed";
const PREFIX: &str = "AIGuardFabric AgentTeams role authority SQL ";

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
        assert!(label.len() < 20);
        let owner = std::env::var("AGF_AGENTTEAMS_ROLE_DATABASE_OWNER").unwrap();
        let run = owner
            .strip_prefix(PREFIX)
            .filter(|run| run.len() == 32 && run.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
            .unwrap();
        let database = format!("agf_requirements_test_agentteams_role_{}", &run[..12]);
        let raw = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
        let url = url::Url::parse(&raw).unwrap();
        assert!(matches!(url.scheme(), "postgres" | "postgresql"));
        assert_eq!(url.host_str(), Some("127.0.0.1"));
        assert_eq!(url.port(), Some(5432));
        assert_eq!(url.path(), format!("/{database}"));
        assert!(url.query().is_none() && url.fragment().is_none());
        let pool = sqlx::postgres::PgPoolOptions::new().max_connections(10).connect(&raw).await.unwrap();
        let actual: (String, Option<String>, i64) = sqlx::query_as(
            "SELECT current_database(),shobj_description(oid,'pg_database'),oid::bigint
            FROM pg_database WHERE datname=current_database()",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(actual.0, database);
        assert_eq!(actual.1, Some(owner.clone()));
        assert!(actual.2 > 0);
        // No migration or tenant creation occurs before exact comment/name/OID ownership is established.
        let db = Database::from_pool(pool.clone());
        db.migrate().await.unwrap();
        let store = Arc::new(Store::new(db, None, Arc::new(MemoryObjectStore::new())));
        let tenant = agf_api::tenant_directory::new(format!("{label}-{}", Id::new()), label.into());
        let state = AppState::with_database(test_config(), store.clone()).unwrap();
        agf_api::tenant_directory::save(&state, tenant.clone(), true).await.unwrap();
        let h = instance(store.clone(), tenant.id).await;
        Self { h, pool, store, database, owner, oid: actual.2 }
    }
    pub(crate) async fn check(&self) {
        let actual: (String, Option<String>, i64) = sqlx::query_as(
            "SELECT current_database(),shobj_description(oid,'pg_database'),oid::bigint
            FROM pg_database WHERE datname=current_database()",
        )
        .fetch_one(&self.pool)
        .await
        .unwrap();
        assert_eq!(actual, (self.database.clone(), Some(self.owner.clone()), self.oid));
    }
    pub(crate) async fn second(&self) -> Harness {
        self.check().await;
        instance(self.store.clone(), self.h.tenant).await
    }
    pub(crate) async fn foreign(&self) -> Harness {
        self.check().await;
        let tenant = agf_api::tenant_directory::new(format!("role-foreign-{}", Id::new()), "Role foreign".into());
        agf_api::tenant_directory::save(&self.h.state, tenant.clone(), true).await.unwrap();
        instance(self.store.clone(), tenant.id).await
    }
    pub(crate) async fn fault<F, Fut>(&self, body: F)
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = ()>,
    {
        self.check().await;
        let name = format!("agf_role_audit_fault_{}", Id::new().as_uuid().simple());
        let command = format!(
            "ALTER TABLE audit_logs ADD CONSTRAINT {name} CHECK (tenant_id<>'{}'::uuid OR target->>'kind'<>'{KIND}') NOT VALID",
            self.h.tenant
        );
        sqlx::query(&command).execute(&self.pool).await.unwrap();
        let result = AssertUnwindSafe(body()).catch_unwind().await;
        self.check().await;
        sqlx::query(&format!("ALTER TABLE audit_logs DROP CONSTRAINT {name}")).execute(&self.pool).await.unwrap();
        if let Err(error) = result {
            std::panic::resume_unwind(error);
        }
    }
    pub(crate) async fn snapshot(&self) -> Value {
        let rows: Vec<Value> = self.h.state.configurations.list(self.h.tenant, KIND).await.unwrap();
        let facts: Vec<Value> = self.h.state.configurations.list(self.h.tenant, INTENTS).await.unwrap();
        let audits = self.h.state.store.audit_stats_durable(self.h.tenant).await.unwrap();
        json!({"rows":rows,"facts":facts,"audits":audits})
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
pub(crate) struct Worker {
    pub(crate) asset: Id,
    pub(crate) draft: Value,
}
pub(crate) async fn prepare(h: &Harness) -> Worker {
    let saved = h
        .request(
            "PUT",
            CONFIG,
            Some(&h.admin),
            Some(json!({"enabled":true,"mock":true,"expected_version":0,
        "settings":{"instance_id":"inst-role-owned","region_id":"cn-hangzhou","account_id":"role-owned-no-cloud"}})),
        )
        .await;
    assert_eq!(saved.status, StatusCode::OK);
    let sync = h
        .post(
            "/api/v1/alicloud/agentteams/sync",
            json!({"request_id":Id::new(),"configuration_version":1,"confirm_live":false}),
        )
        .await;
    assert_eq!(sync.status, StatusCode::OK);
    let view = h.get(BASE).await;
    assert_eq!(view.status, StatusCode::OK);
    let value = view.json();
    let role = value["roles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|role| role["name"] == "viewer" && role["selectable"] == true)
        .unwrap();
    let worker = value["workers"].as_array().unwrap().iter().find(|worker| worker["cloudRole"].is_string()).unwrap();
    let asset = Id::parse(worker["assetId"].as_str().unwrap()).unwrap();
    let role_id = Id::parse(role["id"].as_str().unwrap()).unwrap();
    Worker {
        asset,
        draft: json!({"request_id":Id::new(),"expected_version":0,"confirm_local_constraint":true,
        "change":{"action":"adopt","configuration_version":1,"observed_at":worker["observedAt"],"worker_name":worker["workerName"],
        "team_name":worker["teamName"],"cloud_role":worker["cloudRole"],"role_id":role_id}}),
    }
}
pub(crate) async fn save(h: &Harness, worker: &Worker, input: Value) -> Resp {
    h.request("PUT", &format!("{BASE}/{}", worker.asset), Some(&h.admin), Some(input)).await
}
pub(crate) async fn key(h: &Harness, asset: Option<Id>, scopes: &[&str]) -> String {
    let created = h
        .post(
            "/api/v1/settings/api-keys",
            json!({"name":format!("owned-role-{}",Id::new()),"bound_agent_id":asset,"scopes":scopes}),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED);
    created.json()["plaintext"].as_str().unwrap().into()
}
pub(crate) fn disable(version: u64) -> Value {
    json!({"request_id":Id::new(),"expected_version":version,"confirm_local_constraint":true,"change":{"action":"disable"}})
}
