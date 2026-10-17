//! `ApiKeyRepo`：API Key（`X-AGF-Key`）的 PostgreSQL 读写与水合回读。
//!
//! ## 为什么必须有这个仓储
//!
//! 在此之前 `api_keys` 只有内存后端（`ApiStore::api_key_insert`），`agf-server` 一重启
//! 内存即空 ⇒ **已签发的服务凭据全部失效**：`agf-scheduler` 的 `asset-inventory`
//! （`GET /assets/stats`）与 `rule-hot-reload`（`POST /policies/reload`）用 `.env` 里的
//! `AGF_SCHEDULER_API_KEY` 调用，重启后**必然 401**（`detail: API Key 无效`），
//! 且 `/tasks` 的 `failures` 永久 > 0。本仓储把 Key 落到 §7 既有的 `api_keys` 表
//! （内嵌 0001 迁移已建表，**无需新增迁移**），使平台重启后校验仍然生效。
//!
//! ## 安全口径（与 `agf_auth::api_key` 一致）
//!
//! - 库里**只有** `prefix`（定位用）+ `key_fingerprint`（`SHA-256(盐‖明文)` hex 前 32 位），
//!   **明文永不落库**，因此水合回读的是"能校验、不能还原"的记录；
//! - `revoked` / `expires_at` / `allowed_cidrs` / `scopes` 随行回读，
//!   重启后**不会**把已吊销或已过期的 Key 重新变有效；
//! - 明文只在签发响应里出现一次（`agf_auth::api_key::IssuedApiKey`），与本仓储无关。

use super::*;

use crate::db::{TenantTransaction, map_sqlx_err};
use agf_core::error::{DomainError, DomainResult};
use agf_core::ids::{Id, TenantId};
use agf_core::rbac::{ApiKey, Permission};
use agf_core::time::Timestamp;

impl ApiKeyRepo {
    /// 写入 API Key（幂等：按 `key_fingerprint` 更新，不存在则插入）。
    ///
    /// # Errors
    /// SQL 执行失败。
    pub async fn insert(tx: &mut TenantTransaction<'_>, key: &ApiKey) -> DomainResult<()> {
        let updated = sqlx::query(
            r"UPDATE api_keys SET
                 name = $1, prefix = $2, scopes = $3, bound_agent_id = $4, expires_at = $5,
                 last_used_at = $6, allowed_cidrs = $7, revoked = $8, updated_at = now()
               WHERE key_fingerprint = $9 AND deleted_at IS NULL
               RETURNING id",
        )
        .bind(&key.name)
        .bind(&key.prefix)
        .bind(permissions_to_json(&key.scopes))
        .bind(key.bound_agent_id.as_ref().map(Id::as_uuid))
        .bind(key.expires_at.as_ref().map(Timestamp::as_datetime))
        .bind(key.last_used_at.as_ref().map(Timestamp::as_datetime))
        .bind(serde_json::to_value(&key.allowed_cidrs).unwrap_or(serde_json::Value::Null))
        .bind(key.revoked)
        .bind(&key.key_fingerprint)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|e| map_sqlx_err("update_api_key_by_fingerprint", &e))?;
        if updated.is_some() {
            return Ok(());
        }

        sqlx::query(
            r"INSERT INTO api_keys (
                 id, tenant_id, name, prefix, key_fingerprint, scopes, bound_agent_id,
                 expires_at, last_used_at, allowed_cidrs, revoked, created_at, updated_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,now())",
        )
        .bind(key.id.as_uuid())
        .bind(key.tenant_id.as_uuid())
        .bind(&key.name)
        .bind(&key.prefix)
        .bind(&key.key_fingerprint)
        .bind(permissions_to_json(&key.scopes))
        .bind(key.bound_agent_id.as_ref().map(Id::as_uuid))
        .bind(key.expires_at.as_ref().map(Timestamp::as_datetime))
        .bind(key.last_used_at.as_ref().map(Timestamp::as_datetime))
        .bind(serde_json::to_value(&key.allowed_cidrs).unwrap_or(serde_json::Value::Null))
        .bind(key.revoked)
        .bind(key.created_at.as_datetime())
        .execute(&mut **tx)
        .await
        .map_err(|e| map_sqlx_err("insert_api_key", &e))?;
        Ok(())
    }

    /// 按前缀定位候选 Key（**不含已吊销**，与内存后端 `api_key_by_prefix` 同语义）。
    ///
    /// # Errors
    /// SQL 执行失败。
    pub async fn by_prefix(tx: &mut TenantTransaction<'_>, prefix: &str) -> DomainResult<Option<ApiKey>> {
        let row = sqlx::query("SELECT * FROM api_keys WHERE prefix = $1 AND NOT revoked AND deleted_at IS NULL")
            .bind(prefix)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|e| map_sqlx_err("api_key_by_prefix", &e))?;
        row.as_ref().map(row_to_api_key).transpose()
    }

    /// Read one key through the current tenant's row-level security policy.
    pub async fn by_id(tx: &mut TenantTransaction<'_>, id: Id) -> DomainResult<Option<ApiKey>> {
        let row = sqlx::query("SELECT * FROM api_keys WHERE id = $1 AND deleted_at IS NULL")
            .bind(id.as_uuid())
            .fetch_optional(&mut **tx)
            .await
            .map_err(|e| map_sqlx_err("api_key_by_id", &e))?;
        row.as_ref().map(row_to_api_key).transpose()
    }

    /// 列出全部 Key（含**已吊销**：吊销状态必须随重启保持，水合要如实回读）。
    ///
    /// 顺序按 `created_at` 升序，保证水合顺序与签发顺序一致、结果可复现。
    ///
    /// # Errors
    /// SQL 执行失败。
    pub async fn list_all(tx: &mut TenantTransaction<'_>, limit: i64) -> DomainResult<Vec<ApiKey>> {
        let rows = sqlx::query("SELECT * FROM api_keys WHERE deleted_at IS NULL ORDER BY created_at ASC LIMIT $1")
            .bind(limit)
            .fetch_all(&mut **tx)
            .await
            .map_err(|e| map_sqlx_err("list_api_keys", &e))?;
        rows.iter().map(row_to_api_key).collect()
    }

    /// 吊销（软标记；记录不存在时返回 `NotFound`）。
    ///
    /// # Errors
    /// 记录不存在或 SQL 失败。
    pub async fn revoke(tx: &mut TenantTransaction<'_>, id: Id) -> DomainResult<()> {
        let affected = sqlx::query("UPDATE api_keys SET revoked = true, updated_at = now() WHERE id = $1")
            .bind(id.as_uuid())
            .execute(&mut **tx)
            .await
            .map_err(|e| map_sqlx_err("revoke_api_key", &e))?
            .rows_affected();
        if affected == 0 {
            return Err(DomainError::NotFound { entity: "api-key", id: id.to_string() });
        }
        Ok(())
    }

    /// Lock the tenant's key and revoke it once; an already revoked key is unchanged.
    ///
    /// The caller can append a success audit only when the returned flag is true,
    /// in this same transaction. Missing and deleted keys remain `NotFound`.
    pub async fn revoke_once(tx: &mut TenantTransaction<'_>, id: Id) -> DomainResult<(ApiKey, bool)> {
        let tenant = tx.tenant();
        let row =
            sqlx::query("SELECT * FROM api_keys WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL FOR UPDATE")
                .bind(id.as_uuid())
                .bind(tenant.as_uuid())
                .fetch_optional(&mut **tx)
                .await
                .map_err(|e| map_sqlx_err("lock_api_key_for_revocation", &e))?
                .ok_or_else(|| DomainError::NotFound { entity: "api-key", id: id.to_string() })?;
        let mut key = row_to_api_key(&row)?;
        if key.revoked {
            return Ok((key, false));
        }
        Self::revoke(tx, id).await?;
        key.revoked = true;
        Ok((key, true))
    }
}

/// 行 → [`ApiKey`]（`scopes` / `allowed_cidrs` 为 jsonb）。
///
/// # Errors
/// 主键/租户列读取失败（列类型不符属于结构性错误，如实报错而不是静默造默认值）。
pub(crate) fn row_to_api_key(row: &sqlx::postgres::PgRow) -> DomainResult<ApiKey> {
    let scopes: Vec<String> = serde_json::from_value(json_from(row, "scopes")).unwrap_or_default();
    Ok(ApiKey {
        id: uuid_col(row, "id")?,
        tenant_id: TenantId::from_uuid(
            row.try_get("tenant_id").map_err(|e| DomainError::Internal(format!("列 tenant_id: {e}")))?,
        ),
        name: row.try_get("name").unwrap_or_default(),
        prefix: row.try_get("prefix").unwrap_or_default(),
        key_fingerprint: row.try_get("key_fingerprint").unwrap_or_default(),
        scopes: scopes.iter().map(|s| Permission::from_raw(s.clone())).collect(),
        bound_agent_id: row.try_get::<Option<uuid::Uuid>, _>("bound_agent_id").ok().flatten().map(Id::from_uuid),
        expires_at: ts_opt(row, "expires_at"),
        last_used_at: ts_opt(row, "last_used_at"),
        allowed_cidrs: serde_json::from_value(json_from(row, "allowed_cidrs")).unwrap_or_default(),
        revoked: row.try_get("revoked").unwrap_or(false),
        created_at: ts_col(row, "created_at"),
    })
}

/// `scopes` → jsonb（`Permission` 是透明字符串新类型，序列化为裸字符串数组）。
fn permissions_to_json(scopes: &[Permission]) -> serde_json::Value {
    serde_json::to_value(scopes.iter().map(Permission::as_str).collect::<Vec<_>>()).unwrap_or(serde_json::Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 落库形状必须是**裸字符串数组**（`api_keys.scopes` 是 jsonb；水合按 `Vec<String>` 回读）。
    #[test]
    fn scopes_are_persisted_as_plain_string_array() {
        let json = permissions_to_json(&[Permission::from_raw("assets:read"), Permission::from_raw("policies:write")]);
        assert_eq!(json, serde_json::json!(["assets:read", "policies:write"]));
        let back: Vec<String> = serde_json::from_value(json).unwrap_or_default();
        assert_eq!(back, vec!["assets:read".to_string(), "policies:write".to_string()]);
        assert_eq!(permissions_to_json(&[]), serde_json::json!([]));
    }

    /// 通配 scope 原样落库（校验期由 `Permission::matches` 解释，不在写入期展开）。
    #[test]
    fn wildcard_scope_is_stored_verbatim() {
        assert_eq!(permissions_to_json(&[Permission::from_raw("assets:*")]), serde_json::json!(["assets:*"]));
    }
}
