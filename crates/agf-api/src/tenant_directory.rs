//! 平台租户目录。全局目录仅供登录定位及超管操作，业务数据仍走租户 RLS 事务。
use crate::state::AppState;
use agf_core::{
    audit::AuditLog,
    error::{DomainError, DomainResult},
    ids::TenantId,
    time::Timestamp,
};
use agf_storage::AuditRepo;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub id: TenantId,
    #[serde(default = "initial_version")]
    pub version: u64,
    pub slug: String,
    pub name: String,
    pub enabled: bool,
    pub created_at: Timestamp,
}

fn initial_version() -> u64 {
    1
}

fn default_entry() -> Entry {
    Entry {
        id: TenantId::default_tenant(),
        version: initial_version(),
        slug: "default".into(),
        name: "默认租户".into(),
        enabled: true,
        created_at: Timestamp::now(),
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Directory {
    entries: Vec<Entry>,
}
impl Default for Directory {
    fn default() -> Self {
        Self { entries: vec![default_entry()] }
    }
}
fn storage_error(error: sqlx::Error) -> DomainError {
    if error.as_database_error().is_some_and(sqlx::error::DatabaseError::is_unique_violation) {
        return DomainError::Conflict("租户标识已存在".into());
    }
    tracing::error!(%error, "租户目录数据库操作失败");
    DomainError::DependencyUnavailable { dependency: "postgres".into(), cause: "租户目录暂不可用".into() }
}

pub async fn list(state: &AppState) -> DomainResult<Vec<Entry>> {
    if let Some(store) = state.store.database() {
        let rows: Vec<serde_json::Value> =
            sqlx::query_scalar("SELECT to_jsonb(t) FROM tenants t WHERE deleted_at IS NULL ORDER BY created_at, id")
                .fetch_all(store.db().pool())
                .await
                .map_err(storage_error)?;
        return rows.into_iter().map(|row| serde_json::from_value(row).map_err(Into::into)).collect();
    }
    Ok(state
        .configurations
        .get::<Directory>(
            TenantId::default_tenant(),
            "tenant-directory",
            crate::model_routes::tenant_record_id(TenantId::default_tenant()),
        )
        .await?
        .unwrap_or_default()
        .entries)
}

pub async fn get(state: &AppState, id: TenantId) -> DomainResult<Entry> {
    if let Some(store) = state.store.database() {
        let row: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT to_jsonb(t) FROM tenants t WHERE id=$1 AND deleted_at IS NULL")
                .bind(id.as_uuid())
                .fetch_optional(store.db().pool())
                .await
                .map_err(storage_error)?;
        return row
            .map(serde_json::from_value)
            .transpose()?
            .ok_or_else(|| DomainError::NotFound { entity: "tenant", id: id.to_string() });
    }
    list(state)
        .await?
        .into_iter()
        .find(|row| row.id == id)
        .ok_or_else(|| DomainError::NotFound { entity: "tenant", id: id.to_string() })
}

pub async fn resolve(state: &AppState, value: &str) -> DomainResult<Entry> {
    let value = value.trim();
    if let Some(store) = state.store.database() {
        let row: Option<serde_json::Value> = if let Ok(id) = TenantId::parse(value) {
            sqlx::query_scalar("SELECT to_jsonb(t) FROM tenants t WHERE id=$1 AND enabled AND deleted_at IS NULL")
                .bind(id.as_uuid())
                .fetch_optional(store.db().pool())
                .await
                .map_err(storage_error)?
        } else {
            sqlx::query_scalar("SELECT to_jsonb(t) FROM tenants t WHERE slug=$1 AND enabled AND deleted_at IS NULL")
                .bind(value.to_ascii_lowercase())
                .fetch_optional(store.db().pool())
                .await
                .map_err(storage_error)?
        };
        return row
            .map(serde_json::from_value)
            .transpose()?
            .ok_or_else(|| DomainError::Unauthenticated("租户不存在或已停用".into()));
    }
    list(state)
        .await?
        .into_iter()
        .find(|row| row.enabled && (row.slug.eq_ignore_ascii_case(value) || row.id.to_string() == value))
        .ok_or_else(|| DomainError::Unauthenticated("租户不存在或已停用".into()))
}

pub async fn save(state: &AppState, entry: Entry, create: bool) -> DomainResult<Entry> {
    save_inner(state, entry, create, None).await
}

pub async fn save_audited(state: &AppState, entry: Entry, create: bool, audit: AuditLog) -> DomainResult<Entry> {
    save_inner(state, entry, create, Some(audit)).await
}

async fn save_inner(
    state: &AppState,
    mut entry: Entry,
    create: bool,
    mut audit: Option<AuditLog>,
) -> DomainResult<Entry> {
    entry.name = entry.name.trim().into();
    entry.slug = entry.slug.trim().to_ascii_lowercase();
    if entry.name.is_empty()
        || entry.name.len() > 128
        || entry.slug.len() < 2
        || entry.slug.len() > 64
        || !entry.slug.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
    {
        return Err(DomainError::Validation(
            "名称须为 1..128 字节；租户标识须为 2..64 位小写字母、数字或短横线".into(),
        ));
    }
    if entry.id == TenantId::default_tenant() && !entry.enabled {
        return Err(DomainError::Validation("默认管理租户不能停用".into()));
    }
    let expected_version = if create {
        entry.version = initial_version();
        None
    } else {
        let current = entry.version;
        if current == 0 {
            return Err(DomainError::Validation("租户版本必须大于零".into()));
        }
        entry.version = current.checked_add(1).ok_or_else(|| DomainError::Conflict("租户版本已达上限".into()))?;
        Some(i64::try_from(current).map_err(|_| DomainError::Conflict("租户版本已达上限".into()))?)
    };
    if let Some(audit) = audit.as_mut() {
        audit.target.id = Some(entry.id.to_string());
        audit.target.name = Some(entry.slug.clone());
    }
    if let Some(store) = state.store.database() {
        let audit_tenant = audit.as_ref().map_or(entry.id, |item| item.tenant_id);
        let mut tx = store.db().begin_tenant(audit_tenant).await?;
        // The global tenant directory is written as the platform role. Restore the
        // tenant RLS role before appending the audit record in this same transaction.
        sqlx::query("SET LOCAL ROLE NONE").execute(&mut *tx).await.map_err(storage_error)?;
        if create {
            sqlx::query("INSERT INTO tenants (id,slug,name,enabled,created_at) VALUES ($1,$2,$3,$4,$5)")
                .bind(entry.id.as_uuid())
                .bind(&entry.slug)
                .bind(&entry.name)
                .bind(entry.enabled)
                .bind(entry.created_at.as_datetime())
                .execute(&mut *tx)
                .await
                .map_err(storage_error)?;
        } else {
            let result = sqlx::query(
                "UPDATE tenants SET name=$2,enabled=$3,version=version+1,updated_at=now()
                 WHERE id=$1 AND version=$4 AND deleted_at IS NULL",
            )
            .bind(entry.id.as_uuid())
            .bind(&entry.name)
            .bind(entry.enabled)
            .bind(expected_version)
            .execute(&mut *tx)
            .await
            .map_err(storage_error)?;
            if result.rows_affected() == 0 {
                let exists: bool =
                    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM tenants WHERE id=$1 AND deleted_at IS NULL)")
                        .bind(entry.id.as_uuid())
                        .fetch_one(&mut *tx)
                        .await
                        .map_err(storage_error)?;
                return if exists {
                    Err(DomainError::Conflict("租户已被其他管理员修改，请刷新后重试".into()))
                } else {
                    Err(DomainError::NotFound { entity: "tenant", id: entry.id.to_string() })
                };
            }
        }
        sqlx::query("SET LOCAL ROLE agf_tenant_runtime").execute(&mut *tx).await.map_err(storage_error)?;
        let sealed = if let Some(item) = audit.as_ref() {
            Some(AuditRepo::append_log(&mut tx, item.clone()).await?)
        } else {
            None
        };
        tx.commit().await?;
        if let Some(sealed) = sealed {
            if let Err(error) = state.store.hydrate_audit(&sealed) {
                tracing::warn!(%error, "已提交的租户审计内存投影刷新失败");
            }
        }
    } else {
        state
            .configurations
            .mutate::<Directory, _>(
                TenantId::default_tenant(),
                "tenant-directory",
                crate::model_routes::tenant_record_id(TenantId::default_tenant()),
                |directory| {
                    if create && directory.entries.iter().any(|row| row.slug == entry.slug) {
                        return Err(DomainError::Conflict("租户标识已存在".into()));
                    }
                    if !create {
                        let Some(current) = directory.entries.iter().find(|row| row.id == entry.id) else {
                            return Err(DomainError::NotFound { entity: "tenant", id: entry.id.to_string() });
                        };
                        if current.version != entry.version - 1 {
                            return Err(DomainError::Conflict("租户已被其他管理员修改，请刷新后重试".into()));
                        }
                    }
                    directory.entries.retain(|row| row.id != entry.id);
                    directory.entries.push(entry.clone());
                    Ok(())
                },
            )
            .await?;
        if let Some(audit) = audit {
            state.store.audit_append_durable(audit).await?;
        }
    }
    Ok(entry)
}

pub fn new(slug: String, name: String) -> Entry {
    Entry { id: TenantId::new(), version: initial_version(), slug, name, enabled: true, created_at: Timestamp::now() }
}
