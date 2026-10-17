use crate::{common::*, configuration_audit_support::SqlCase};
use agf_core::{credential::KeyBackend, enums::DataClass, error::DomainResult, ids::Id};
use agf_storage::{Database, FieldCipher, semantic_response_cache::*};

pub(crate) struct Fixture {
    pub(crate) case: SqlCase,
    pub(crate) issuer: DomainIssuer,
    pub(crate) source: Id,
    pub(crate) payload: Value,
}

impl std::fmt::Debug for Fixture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Fixture(<owned-encrypted-semantic-cache>)")
    }
}

impl Fixture {
    pub(crate) async fn open(label: &str) -> Self {
        check_owner().await;
        let case = SqlCase::open(label).await;
        let source = Id::new();
        let payload = json!({"version":1,"enabled":true,"placement":"owned-loopback-fixture"});
        case.h.state.configurations.put(case.h.tenant, "semantic-cache-fixture", source, &payload).await.unwrap();
        Self { case, issuer: DomainIssuer::from_server_key([7; 32]).unwrap(), source, payload }
    }
    pub(crate) fn repository(&self) -> SqlRepository {
        SqlRepository::new(
            Database::from_pool(self.case.pool.clone()),
            self.issuer.clone(),
            FieldCipher::new(&[9; 32], "semantic-test", KeyBackend::LocalFile).unwrap(),
        )
    }
    pub(crate) fn evidence(&self) -> ServerSemanticEvidence {
        ServerSemanticEvidence {
            tenant: self.case.h.tenant,
            subject_id: self.source,
            subject_kind: "user".into(),
            identity_tenant: self.case.h.tenant,
            session: Some("owned-sql-session".into()),
            agent_id: None,
            department: None,
            data_class: DataClass::Public,
            internal_placement_verified: false,
            chat_endpoint: self.source,
            chat_model: "owned-chat".into(),
            chat_model_revision: "v1".into(),
            embedding_endpoint: Id::new(),
            embedding_model: "owned-embedding".into(),
            embedding_model_revision: "v1".into(),
            dimensions: 3,
            transport_mode: "mock".into(),
            cache_configuration_version: 1,
            fences: vec![
                ConfigurationFence::from_server_record("semantic-cache-fixture", self.source, 1, &self.payload)
                    .unwrap(),
            ],
            fixed_request: json!({"temperature":0,"messages":[{"role":"user","content":null}]}),
            authority_deadline_ms: chrono::Utc::now().timestamp_millis() + 300_000,
        }
    }
    pub(crate) async fn admit(&self, domain: &TrustedSemanticDomain, text: &str, ttl: u32) -> Id {
        let database = Database::from_pool(self.case.pool.clone());
        let mut tx = database.begin_tenant(domain.tenant()).await.unwrap();
        let id = self.repository().admit_in_transaction(&mut tx, domain, admission(text, ttl)).await.unwrap();
        tx.commit().await.unwrap();
        id
    }
    pub(crate) async fn stats(&self) -> (i64, i64, String) {
        sqlx::query_as("SELECT count(*),coalesce(sum(sealed_bytes),0)::bigint,coalesce(md5(string_agg(encode(payload,'hex'),'' ORDER BY id)),'') FROM semantic_response_cache_v2 WHERE tenant_id=$1")
            .bind(self.case.h.tenant.as_uuid()).fetch_one(&self.case.pool).await.unwrap()
    }
}

pub(crate) fn admission(text: &str, ttl: u32) -> Admission {
    Admission::new(
        vec![1.0, 0.01, 0.0],
        PlainResponse::from_canonical(
            json!({"id":"owned-result","model":"owned-chat","message":{"role":"assistant","content":text},
        "finish_reason":"stop","usage":{"prompt_tokens":11,"completion_tokens":3}}),
            "owned-chat",
        )
        .unwrap(),
        ttl,
    )
    .unwrap()
}
pub(crate) fn query() -> SearchVector {
    SearchVector::new(vec![1.0, 0.0, 0.0], 0.99, 0.0001).unwrap()
}

#[derive(Debug)]
pub(crate) struct Authority<'a>(pub(crate) &'a Fixture);
#[async_trait::async_trait]
impl SemanticReadAuthority for Authority<'_> {
    async fn revalidate(&self, domain: &TrustedSemanticDomain) -> DomainResult<()> {
        for fence in domain.configuration_fences() {
            let value: Option<Value> =
                self.0.case.h.state.configurations.get(domain.tenant(), fence.kind(), fence.id()).await?;
            if !value.as_ref().is_some_and(|value| fence.matches(value).unwrap_or(false)) {
                return Err(agf_core::error::DomainError::PreconditionFailed("Owned fixture source changed".into()));
            }
        }
        Ok(())
    }
}

pub(crate) async fn check_owner() {
    // This preflight runs before SqlCase performs migrations or any mutation.
    let owner = std::env::var("AGF_SEMANTIC_CACHE_DATABASE_OWNER").unwrap();
    let run = owner.strip_prefix("AIGuardFabric WP7 semantic cache test ").unwrap();
    assert!(run.len() == 32 && run.bytes().all(|byte| byte.is_ascii_hexdigit()));
    let database = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    let url = url::Url::parse(&database).unwrap();
    let expected = format!("agf_requirements_test_semantic_cache_{}", &run[..12]);
    assert_eq!(url.path(), format!("/{expected}"));
    assert!(matches!(url.host_str(), Some("127.0.0.1" | "localhost")));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect(&database).await.unwrap();
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SET TRANSACTION READ ONLY").execute(&mut *tx).await.unwrap();
    let (name,comment):(String,Option<String>)=sqlx::query_as("SELECT current_database(),shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()")
        .fetch_one(&mut *tx).await.unwrap();
    assert_eq!(name, expected);
    assert_eq!(comment.as_deref(), Some(owner.as_str()));
    let expected_oid = std::env::var("AGF_SEMANTIC_CACHE_DATABASE_OID").unwrap().parse::<i64>().unwrap();
    let oid: i64 = sqlx::query_scalar("SELECT oid::bigint FROM pg_database WHERE datname=current_database()")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(oid, expected_oid);
    tx.commit().await.unwrap();
    pool.close().await;
}
