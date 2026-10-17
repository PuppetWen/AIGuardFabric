//! Fail closed before migrations/writes; root owns lifecycle and removal of these exact task-only resources.
use super::*;
use std::path::{Path, PathBuf};

pub(super) const OWNER_PREFIX: &str = "AIGuardFabric Scheduler native UI host ";
const DATABASE_PREFIX: &str = "agf_requirements_test_scheduler_native_ui_";
pub(super) struct Owner {
    pub(super) pool: sqlx::PgPool,
    pub(super) database: String,
    pub(super) project: PathBuf,
    pub(super) dist: PathBuf,
    pub(super) data: PathBuf,
    run: PathBuf,
    comment: String,
    oid: i64,
}
impl Owner {
    pub(super) async fn open(login: &identity::Login) -> DomainResult<Self> {
        if std::env::var("AGF_SCHEDULER_NATIVE_UI_OWNER").ok().as_deref() != Some(login.owner.as_str()) {
            return Err(fail("database_owner_env"));
        }
        let project =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().map_err(|_| fail("project"))?;
        let case = project.join(".tmp/codex-requirements-20260920/scheduler-native-ui-host").join(&login.run_id);
        no_links(&case, false)?;
        marker(&case, &login.owner)?;
        let data = case.join("data");
        no_links(&data, true)?;
        marker(&data, &login.owner)?;
        let dist = case.join("dist");
        no_links(&dist, true)?;
        marker(&dist, &login.owner)?;
        if !dist.join("index.html").is_file() {
            return Err(fail("dist_index"));
        }
        let database = format!("{DATABASE_PREFIX}{}", &login.run_id[..12]);
        let raw = std::env::var("AGF_TEST_DATABASE_URL").map_err(|_| fail("database_url"))?;
        let url = url::Url::parse(&raw).map_err(|_| fail("database_url"))?;
        if !matches!(url.scheme(), "postgres" | "postgresql")
            || url.host_str() != Some("127.0.0.1")
            || url.port() != Some(5432)
            || url.path() != format!("/{database}")
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(fail("database_url_scope"));
        }
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(12)
            .acquire_timeout(std::time::Duration::from_secs(20))
            .connect(&raw)
            .await
            .map_err(|_| fail("database_connect"))?;
        let actual = identity(&pool).await?;
        if actual.0 != database || actual.1.as_deref() != Some(login.owner.as_str()) || actual.2 <= 0 {
            return Err(fail("database_pre_migration"));
        }
        let owner =
            Self { pool, database, project, dist, data, run: case, comment: login.owner.clone(), oid: actual.2 };
        if owner.stop_requested()? {
            return Err(fail("stop_request_before_start"));
        }
        Ok(owner)
    }
    pub(super) async fn check(&self) -> DomainResult<()> {
        if identity(&self.pool).await? != (self.database.clone(), Some(self.comment.clone()), self.oid) {
            return Err(fail("database_identity_changed"));
        }
        Ok(())
    }
    pub(super) async fn empty(&self) -> DomainResult<()> {
        self.check().await?;
        let count: i64 = sqlx::query_scalar(
            "SELECT (SELECT count(*) FROM users)+(SELECT count(*) FROM api_keys)+
             (SELECT count(*) FROM console_configurations)+(SELECT count(*) FROM audit_logs)",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|_| fail("database_empty"))?;
        if count != 0 {
            return Err(fail("database_not_fresh"));
        }
        Ok(())
    }
    pub(super) fn stop_requested(&self) -> DomainResult<bool> {
        // Only this exact run-owned filename can request shutdown; no caller path or secret is accepted.
        no_links(&self.run, false)?;
        marker(&self.run, &self.comment)?;
        let stop = self.run.join(".stop-request");
        let meta = match std::fs::symlink_metadata(&stop) {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(_) => return Err(fail("stop_request_metadata")),
        };
        no_links(&stop, false)?;
        if !meta.is_file() || meta.len() > 512 {
            return Err(fail("stop_request_shape"));
        }
        use std::io::Read;
        let mut value = String::new();
        std::fs::File::open(stop)
            .map_err(|_| fail("stop_request_read"))?
            .take(513)
            .read_to_string(&mut value)
            .map_err(|_| fail("stop_request_read"))?;
        let value = value.strip_prefix('\u{feff}').unwrap_or(&value);
        let line = value.strip_suffix("\r\n").or_else(|| value.strip_suffix('\n')).unwrap_or(value);
        if value.len() > 512 || line != self.comment {
            return Err(fail("stop_request_owner"));
        }
        Ok(true)
    }
}
async fn identity(pool: &sqlx::PgPool) -> DomainResult<(String, Option<String>, i64)> {
    sqlx::query_as("SELECT current_database(),shobj_description(oid,'pg_database'),oid::bigint FROM pg_database WHERE datname=current_database()")
        .fetch_one(pool).await.map_err(|_| fail("database_identity"))
}
fn marker(path: &Path, expected: &str) -> DomainResult<()> {
    let marker = path.join(".task-owner");
    no_links(&marker, false)?;
    let value = std::fs::read_to_string(marker).map_err(|_| fail("path_owner"))?;
    if value.trim_start_matches('\u{feff}').trim() != expected {
        return Err(fail("path_owner"));
    }
    Ok(())
}
fn no_links(path: &Path, recursive: bool) -> DomainResult<()> {
    for ancestor in path.ancestors() {
        check_node(ancestor)?;
    }
    if recursive && path.is_dir() {
        for child in std::fs::read_dir(path).map_err(|_| fail("path_read"))? {
            let child = child.map_err(|_| fail("path_read"))?.path();
            check_node(&child)?;
            if child.is_dir() {
                no_links(&child, true)?;
            }
        }
    }
    Ok(())
}
fn check_node(path: &Path) -> DomainResult<()> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| fail("path_metadata"))?;
    if meta.file_type().is_symlink() {
        return Err(fail("path_symlink"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return Err(fail("path_reparse"));
        }
    }
    Ok(())
}
