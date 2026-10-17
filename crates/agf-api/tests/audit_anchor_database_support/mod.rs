//! 迁移前必须证明精确归属；每个 ignored 用例使用单独的新数据库。
use crate::{common::*, configuration_audit_support::SqlCase};
use agf_core::{
    audit::SignedAuditAnchor,
    error::{DomainError, DomainResult},
    ids::Id,
};
use agf_storage::audit_anchor::{AuditAnchorSigner, AuditWitness, checkpoint_management};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::path::PathBuf;

pub(crate) struct Owned {
    pub case: SqlCase,
    owner: String,
    name: String,
    oid: i64,
    data: PathBuf,
}
fn invalid() -> DomainError {
    DomainError::PreconditionFailed(
        "Audit anchor SQL requires an exact exclusive owned database and data directory".into(),
    )
}
async fn identity(pool: &PgPool) -> DomainResult<(String, i64, Option<String>, String, String)> {
    sqlx::query_as("SELECT current_database(),oid::bigint,shobj_description(oid,'pg_database'),pg_get_userbyid(datdba),current_user::text FROM pg_database WHERE datname=current_database()")
        .fetch_one(pool).await.map_err(|error|agf_storage::map_sqlx_err("audit_anchor_fixture_identity",&error))
}
impl Owned {
    pub(crate) async fn open(label: &str) -> DomainResult<Self> {
        let owner = std::env::var("AGF_AUDIT_ANCHOR_DATABASE_OWNER").map_err(|_| invalid())?;
        let run = owner.strip_prefix("AIGuardFabric audit anchor SQL ").ok_or_else(invalid)?;
        if run.len() != 32 || !run.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
            return Err(invalid());
        }
        let name = format!("agf_requirements_test_anchor_{run}");
        let raw = std::env::var("AGF_TEST_DATABASE_URL").map_err(|_| invalid())?;
        let url = url::Url::parse(&raw).map_err(|_| invalid())?;
        if !matches!(url.scheme(), "postgres" | "postgresql")
            || url.host_str() != Some("127.0.0.1")
            || url.port() != Some(5432)
            || url.path() != format!("/{name}")
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(invalid());
        }
        let data = PathBuf::from(std::env::var_os("AGF_AUDIT_ANCHOR_DATA_DIR").ok_or_else(invalid)?);
        if !data.is_absolute() || std::fs::read(data.join(".runner-owner"))? != owner.as_bytes() {
            return Err(invalid());
        }
        let mut path = PathBuf::new();
        for part in data.components() {
            if matches!(part, std::path::Component::ParentDir) {
                return Err(invalid());
            }
            path.push(part);
            let metadata = std::fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                return Err(invalid());
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if metadata.file_attributes() & 0x400 != 0 {
                    return Err(invalid());
                }
            }
        }
        // 管理连接和迁移及应用连接各自独立核对同一 OID。
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&raw)
            .await
            .map_err(|error| agf_storage::map_sqlx_err("audit_anchor_fixture_connect", &error))?;
        let before = identity(&pool).await?;
        pool.close().await;
        if before.0 != name || before.1 <= 0 || before.2.as_deref() != Some(owner.as_str()) || before.3 != before.4 {
            return Err(invalid());
        }
        let mut case = SqlCase::open(label).await;
        Arc::make_mut(&mut case.h.state.config).data_dir = data.to_string_lossy().into_owned();
        case.h.app = build_router(case.h.state.clone()).layer(axum::middleware::map_request({
            let tenant = case.h.tenant;
            move |mut request: Request<Body>| {
                request.headers_mut().insert("x-agf-tenant", tenant.to_string().parse().unwrap());
                async move { request }
            }
        }));
        let owned = Self { case, owner, name, oid: before.1, data };
        owned.verify().await?;
        Ok(owned)
    }
    pub(crate) async fn verify(&self) -> DomainResult<()> {
        let actual = identity(&self.case.pool).await?;
        if actual.0 != self.name
            || actual.1 != self.oid
            || actual.2.as_deref() != Some(self.owner.as_str())
            || actual.3 != actual.4
            || std::fs::read(self.data.join(".runner-owner"))? != self.owner.as_bytes()
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub(crate) async fn fresh(&self) -> DomainResult<Harness> {
        self.verify().await?;
        let mut h = self.case.second_instance().await;
        Arc::make_mut(&mut h.state.config).data_dir = self.data.to_string_lossy().into_owned();
        h.app = build_router(h.state.clone()).layer(axum::middleware::map_request({
            let tenant = h.tenant;
            move |mut request: Request<Body>| {
                request.headers_mut().insert("x-agf-tenant", tenant.to_string().parse().unwrap());
                async move { request }
            }
        }));
        Ok(h)
    }
    pub(crate) fn witness(&self, agent: Option<Id>) -> DomainResult<AuditWitness> {
        AuditWitness::acquire(&self.data, self.case.h.tenant, agent)
    }
    pub(crate) fn signer(&self) -> DomainResult<AuditAnchorSigner> {
        AuditAnchorSigner::from_base64(&self.case.h.state.config.security.master_key_b64)
    }
    pub(crate) async fn checkpoint(&self) -> DomainResult<SignedAuditAnchor> {
        self.verify().await?;
        let witness = self.witness(None)?;
        let previous = witness.read()?;
        let database = self.case.h.state.store.database().ok_or_else(invalid)?;
        let mut tx = database.db().begin_tenant(self.case.h.tenant).await?;
        let value = checkpoint_management(&mut tx, &self.signer()?, previous.as_ref()).await?;
        tx.commit().await?;
        witness.advance(&value)?;
        Ok(value)
    }
}
