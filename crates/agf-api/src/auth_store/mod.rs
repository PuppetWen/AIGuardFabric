//! PostgreSQL 认证后端：租户事务、账号与角色原子更新，拒绝静默内存降级。
use agf_auth::service::AuthBackend;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    user::{LoginAttempt, RefreshTokenRecord, User, UserWithSecret},
};
use async_trait::async_trait;
use serde_json::Value;
use sqlx::Row;
use std::sync::Arc;

mod accounts;
pub mod protected;

#[derive(Debug)]
pub struct SqlAuthBackend {
    store: Arc<agf_storage::Store>,
}

impl SqlAuthBackend {
    pub fn new(store: Arc<agf_storage::Store>) -> Self {
        Self { store }
    }
}

fn db_error(error: sqlx::Error) -> DomainError {
    if error.as_database_error().is_some_and(sqlx::error::DatabaseError::is_unique_violation) {
        return DomainError::Conflict("用户名或邮箱已存在".into());
    }
    tracing::error!(error = %error, "认证数据库操作失败");
    DomainError::DependencyUnavailable { dependency: "postgres".into(), cause: "认证数据读写失败".into() }
}

fn decode<T: serde::de::DeserializeOwned>(value: Value) -> DomainResult<T> {
    serde_json::from_value(value).map_err(|e| DomainError::Internal(format!("认证记录格式错误: {e}")))
}

#[async_trait]
impl AuthBackend for SqlAuthBackend {
    fn current_user_authority(
        &self,
        _tenant: TenantId,
        _user: Id,
    ) -> DomainResult<agf_auth::service::CurrentUserAuthority> {
        Ok(agf_auth::service::CurrentUserAuthority::Sql {
            store_identity: Arc::as_ptr(&self.store).addr(),
            mfa_configuration_identity: None,
        })
    }

    async fn provision_federated(&self, user: &User, roles: &[String]) -> DomainResult<()> {
        let mut tx = self.store.db().begin_tenant(user.tenant_id).await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!("federated:{}:{}", user.tenant_id, user.id))
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE tenant_id=$1 AND id=$2)")
            .bind(user.tenant_id.as_uuid())
            .bind(user.id.as_uuid())
            .fetch_one(&mut *tx)
            .await
            .map_err(db_error)?;
        if !exists {
            accounts::save(&mut tx, user, None).await?;
            accounts::assign_roles(&mut tx, user, roles).await?;
        }
        tx.commit().await
    }
    async fn password_history(&self, tenant: TenantId, id: Id) -> DomainResult<Vec<String>> {
        let mut tx = self.store.db().begin_tenant(tenant).await?;
        let value: Option<Value> = sqlx::query_scalar(
            "SELECT password_history FROM users WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL",
        )
        .bind(tenant.as_uuid())
        .bind(id.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;
        tx.commit().await?;
        value.map(decode).transpose().map(Option::unwrap_or_default)
    }
    async fn list_users(&self, tenant: TenantId) -> DomainResult<Vec<User>> {
        let mut tx = self.store.db().begin_tenant(tenant).await?;
        let values: Vec<Value> = sqlx::query_scalar(
            "SELECT to_jsonb(u) - 'password_hash' || jsonb_build_object('last_login_ip', host(last_login_ip))
             FROM users u WHERE tenant_id=$1 AND deleted_at IS NULL ORDER BY created_at, id",
        )
        .bind(tenant.as_uuid())
        .fetch_all(&mut *tx)
        .await
        .map_err(db_error)?;
        tx.commit().await?;
        values.into_iter().map(decode).collect()
    }

    async fn find_user_with_secret(&self, tenant: TenantId, username: &str) -> DomainResult<Option<UserWithSecret>> {
        let mut tx = self.store.db().begin_tenant(tenant).await?;
        let row = sqlx::query(
            "SELECT to_jsonb(u) - 'password_hash' || jsonb_build_object('last_login_ip', host(last_login_ip)) AS data,
             password_hash FROM users u WHERE tenant_id=$1 AND lower(username)=lower($2) AND deleted_at IS NULL",
        )
        .bind(tenant.as_uuid())
        .bind(username)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;
        tx.commit().await?;
        row.map(|r| {
            Ok(UserWithSecret {
                user: decode(r.try_get("data").map_err(db_error)?)?,
                password_hash: r.try_get("password_hash").map_err(db_error)?,
            })
        })
        .transpose()
    }

    async fn find_user(&self, tenant: TenantId, id: Id) -> DomainResult<Option<User>> {
        let mut tx = self.store.db().begin_tenant(tenant).await?;
        let value: Option<Value> = sqlx::query_scalar(
            "SELECT to_jsonb(u) - 'password_hash' || jsonb_build_object('last_login_ip', host(last_login_ip))
             FROM users u WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL",
        )
        .bind(tenant.as_uuid())
        .bind(id.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;
        tx.commit().await?;
        value.map(decode).transpose()
    }

    async fn save_user(&self, user: &User, password_hash: Option<&str>) -> DomainResult<()> {
        let mut tx = self.store.db().begin_tenant(user.tenant_id).await?;
        accounts::save(&mut tx, user, password_hash).await?;
        tx.commit().await
    }

    async fn save_account(&self, user: &User, password_hash: Option<&str>, roles: &[String]) -> DomainResult<()> {
        let mut tx = self.store.db().begin_tenant(user.tenant_id).await?;
        accounts::save(&mut tx, user, password_hash).await?;
        accounts::assign_roles(&mut tx, user, roles).await?;
        tx.commit().await
    }

    async fn roles_of(&self, tenant: TenantId, user_id: Id) -> DomainResult<Vec<String>> {
        let mut tx = self.store.db().begin_tenant(tenant).await?;
        let roles = sqlx::query_scalar(
            "SELECT r.name FROM role_bindings b JOIN roles r ON r.id=b.role_id AND r.tenant_id=b.tenant_id
             JOIN users u ON u.id=b.subject_id AND u.tenant_id=b.tenant_id
             WHERE b.tenant_id=$1 AND b.subject_id=$2 AND b.subject_kind='user'
             AND b.deleted_at IS NULL AND r.deleted_at IS NULL AND u.deleted_at IS NULL
             AND (b.expires_at IS NULL OR b.expires_at>now()) ORDER BY r.name",
        )
        .bind(tenant.as_uuid())
        .bind(user_id.as_uuid())
        .fetch_all(&mut *tx)
        .await
        .map_err(db_error)?;
        tx.commit().await?;
        Ok(roles)
    }

    async fn store_refresh(&self, record: &RefreshTokenRecord) -> DomainResult<()> {
        let mut tx = self.store.db().begin_tenant(record.tenant_id).await?;
        sqlx::query(
            "INSERT INTO refresh_tokens (id, tenant_id, user_id, token_fingerprint, device, expires_at,
             revoked, revoked_reason, created_at)
             SELECT id, tenant_id, user_id, token_fingerprint, device, expires_at, revoked, revoked_reason, created_at
             FROM jsonb_populate_record(NULL::refresh_tokens, $1)",
        )
        .bind(serde_json::to_value(record).map_err(|e| DomainError::Internal(e.to_string()))?)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        tx.commit().await
    }

    async fn find_refresh(&self, tenant: TenantId, fingerprint: &str) -> DomainResult<Option<RefreshTokenRecord>> {
        let mut tx = self.store.db().begin_tenant(tenant).await?;
        let value: Option<Value> =
            sqlx::query_scalar("SELECT to_jsonb(r) FROM refresh_tokens r WHERE tenant_id=$1 AND token_fingerprint=$2")
                .bind(tenant.as_uuid())
                .bind(fingerprint)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_error)?;
        tx.commit().await?;
        value.map(decode).transpose()
    }

    async fn revoke_refresh(&self, tenant: TenantId, id: Id, reason: &str) -> DomainResult<bool> {
        let mut tx = self.store.db().begin_tenant(tenant).await?;
        let changed = sqlx::query(
            "UPDATE refresh_tokens SET revoked=true, revoked_reason=$3 WHERE tenant_id=$1 AND id=$2 AND NOT revoked",
        )
        .bind(tenant.as_uuid())
        .bind(id.as_uuid())
        .bind(reason)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        tx.commit().await?;
        Ok(changed.rows_affected() == 1)
    }

    async fn record_attempt(&self, attempt: &LoginAttempt) -> DomainResult<()> {
        let Some(tenant) = attempt.tenant_id else {
            return Ok(());
        };
        let mut tx = self.store.db().begin_tenant(tenant).await?;
        let mut value = serde_json::to_value(attempt).map_err(|e| DomainError::Internal(e.to_string()))?;
        if attempt.source_ip.parse::<std::net::IpAddr>().is_err() {
            value["source_ip"] = Value::Null;
        }
        sqlx::query(
            "INSERT INTO login_attempts (id, tenant_id, username, source_ip, user_agent, success, failure_code, at)
             SELECT id, tenant_id, username, source_ip, user_agent, success, failure_code, at
             FROM jsonb_populate_record(NULL::login_attempts, $1)",
        )
        .bind(value)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        tx.commit().await
    }
}
