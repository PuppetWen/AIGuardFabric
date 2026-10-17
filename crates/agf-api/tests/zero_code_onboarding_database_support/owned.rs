//! Check database name/comment/OID before migrations; source and scratch reject links.
use super::fail;
use agf_core::{error::DomainResult, ids::Id};
use agf_storage::{Database, Store, objectstore::MemoryObjectStore};
use serde_json::json;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

const PREFIX: &str = "AIGuardFabric zero code onboarding SQL ";
pub(super) struct Owned {
    pub(super) pool: sqlx::PgPool,
    pub(super) store: Arc<Store>,
    pub(super) root: PathBuf,
    pub(super) project: PathBuf,
    pub(super) sdk: PathBuf,
    name: String,
    comment: String,
    oid: i64,
    marker: String,
}

pub(super) fn plain(path: &Path) -> DomainResult<()> {
    for part in path.ancestors() {
        let metadata = std::fs::symlink_metadata(part).map_err(|_| fail("path metadata"))?;
        if metadata.file_type().is_symlink() {
            return Err(fail("source or runtime data link"));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(fail("source or runtime data reparse"));
            }
        }
    }
    Ok(())
}

impl Owned {
    pub(super) async fn open() -> DomainResult<Self> {
        let comment = std::env::var("AGF_ZERO_CODE_DATABASE_OWNER").map_err(|_| fail("owner ENV required"))?;
        let run = comment
            .strip_prefix(PREFIX)
            .filter(|run| run.len() == 32 && run.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
            .ok_or_else(|| fail("owner format"))?;
        let name = format!("agf_requirements_test_zero_code_{}", &run[..12]);
        let raw = std::env::var("AGF_TEST_DATABASE_URL").map_err(|_| fail("database URL required"))?;
        let address = url::Url::parse(&raw).map_err(|_| fail("database URL"))?;
        if !matches!(address.scheme(), "postgres" | "postgresql")
            || address.host_str() != Some("127.0.0.1")
            || address.port() != Some(5432)
            || address.path() != format!("/{name}")
            || address.query().is_some()
            || address.fragment().is_some()
        {
            return Err(fail("exact owned loopback database required"));
        }
        let base =
            PathBuf::from(std::env::var_os("AGF_ZERO_CODE_TEST_DIR").ok_or_else(|| fail("task directory required"))?);
        if !base.is_absolute() {
            return Err(fail("absolute task directory"));
        }
        plain(&base)?;
        if base.file_name().and_then(|v| v.to_str()) != Some(format!("wp2-zero-code-sql-v1-data-{run}").as_str())
            || std::fs::read_to_string(base.join(".task-owner"))
                .map_err(|_| fail("runtime owner"))?
                .trim_start_matches('\u{feff}')
                .trim()
                != format!("AIGuardFabric requirements completion 20260920:zero-code-onboarding-sql:{run}")
        {
            return Err(fail("runtime directory owner"));
        }
        let owner = std::fs::read_to_string(base.parent().ok_or_else(|| fail("task parent"))?.join("task-owner.txt"))
            .map_err(|_| fail("task owner"))?;
        if !["AIGuardFabric requirements completion local 20260920", "AIGuardFabric requirements completion 20260920"]
            .contains(&owner.trim_start_matches('\u{feff}').trim())
        {
            return Err(fail("foreign task directory"));
        }
        let project =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().map_err(|_| fail("project root"))?;
        plain(&project)?;
        let sdk = PathBuf::from(std::env::var_os("AGF_ZERO_CODE_SDK_ROOT").ok_or_else(|| fail("SDKROOT required"))?);
        if !sdk.is_absolute() {
            return Err(fail("absolute SDKROOT"));
        }
        plain(&sdk)?;
        // Canonical equality proves identity; keep the verified nonverbatim ENV path for Node 24.
        let canonical_sdk = sdk.canonicalize().map_err(|_| fail("SDKROOT"))?;
        if canonical_sdk
            != project.join("sdk/agentteams").canonicalize().map_err(|_| fail("installed project SDKROOT"))?
        {
            return Err(fail("SDKROOT must be this compiled project's installed source"));
        }
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(12)
            .connect(&raw)
            .await
            .map_err(|_| fail("database connect"))?;
        let actual: (String,Option<String>,i64) = sqlx::query_as("SELECT current_database(),shobj_description(oid,'pg_database'),oid::bigint FROM pg_database WHERE datname=current_database()")
            .fetch_one(&pool).await.map_err(|_| fail("database identity read"))?;
        if actual.0 != name || actual.1.as_deref() != Some(comment.as_str()) || actual.2 <= 0 {
            pool.close().await;
            return Err(fail("foreign database before migration"));
        }
        let root = base.join(format!("zero-code-case-{}", Id::new().as_uuid().simple()));
        std::fs::create_dir(&root).map_err(|_| fail("fresh owned case"))?;
        plain(&root)?;
        let marker =
            json!({"owner":comment,"project":project,"sdkRoot":sdk,"database":name,"oid":actual.2}).to_string();
        write_new(&root.join(".owner"), marker.as_bytes())?;
        let database = Database::from_pool(pool.clone());
        let owned = Self {
            pool,
            store: Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new()))),
            root,
            project,
            sdk,
            name,
            comment,
            oid: actual.2,
            marker,
        };
        owned.check().await?;
        owned.store.db().migrate().await?;
        Ok(owned)
    }
    pub(super) async fn check(&self) -> DomainResult<()> {
        let actual:(String,Option<String>,i64)=sqlx::query_as("SELECT current_database(),shobj_description(oid,'pg_database'),oid::bigint FROM pg_database WHERE datname=current_database()")
            .fetch_one(&self.pool).await.map_err(|_| fail("database identity read"))?;
        if actual != (self.name.clone(), Some(self.comment.clone()), self.oid) {
            return Err(fail("database ownership changed"));
        }
        Ok(())
    }
    pub(super) async fn finish(&self) -> DomainResult<()> {
        self.check().await?;
        plain(&self.root)?;
        if std::fs::read_to_string(self.root.join(".owner")).map_err(|_| fail("case owner"))? != self.marker {
            return Err(fail("case owner changed"));
        }
        let mut pending = vec![self.root.clone()];
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(dir).map_err(|_| fail("case walk"))? {
                let path = entry.map_err(|_| fail("case entry"))?.path();
                plain(&path)?;
                if path.is_dir() {
                    pending.push(path);
                }
            }
        }
        self.pool.close().await;
        // Called only after all business children and listeners have been joined.
        std::fs::remove_dir_all(&self.root).map_err(|_| fail("owned case cleanup"))
    }
}
pub(super) fn write_new(path: &Path, bytes: &[u8]) -> DomainResult<()> {
    use std::io::Write;
    let mut file =
        std::fs::OpenOptions::new().create_new(true).write(true).open(path).map_err(|_| fail("new owned file"))?;
    file.write_all(bytes).map_err(|_| fail("owned file write"))
}
