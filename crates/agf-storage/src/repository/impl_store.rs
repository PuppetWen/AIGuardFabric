//! 由 `repository.rs` 拆分：`impl_Store`/`json_from` 等 9 项（纯搬移，逻辑不变）。
use super::*;

use crate::db::{Database, TenantTransaction, is_safe_identifier};
use crate::objectstore::ObjectStore;
use crate::redis_store::RedisStore;
use agf_core::enums::Severity;
use agf_core::error::{DomainError, DomainResult};
use agf_core::ids::{Id, TenantId};
use agf_core::time::Timestamp;
use std::collections::BTreeMap;
use tracing::warn;

impl Store {
    /// 构造。
    #[must_use]
    pub fn new(db: Database, redis: Option<RedisStore>, objects: std::sync::Arc<dyn ObjectStore>) -> Self {
        Self { db, redis, objects }
    }

    /// 数据库句柄。
    #[must_use]
    pub const fn db(&self) -> &Database {
        &self.db
    }

    /// Redis 句柄（可能未启用）。
    #[must_use]
    pub const fn redis(&self) -> Option<&RedisStore> {
        self.redis.as_ref()
    }

    /// 对象存储句柄。
    #[must_use]
    pub fn objects(&self) -> &std::sync::Arc<dyn ObjectStore> {
        &self.objects
    }

    /// 在租户上下文中执行一个操作：闭包返回 `DomainResult<T>`，成功自动提交、失败自动回滚。
    ///
    /// 闭包接收 `&mut TenantTransaction`，可自由进行多次异步查询。
    ///
    /// # Errors
    /// 事务开启/提交失败，或闭包内部错误。
    pub async fn with_tenant<T, F>(&self, tenant: TenantId, f: F) -> DomainResult<T>
    where
        F: for<'c, 't> FnOnce(&'c mut TenantTransaction<'t>) -> BoxFuture<'c, DomainResult<T>>,
    {
        let mut tx = self.db.begin_tenant(tenant).await?;
        let outcome = f(&mut tx).await;
        match outcome {
            Ok(value) => {
                tx.commit().await?;
                Ok(value)
            }
            Err(e) => {
                if let Err(rb) = tx.rollback().await {
                    warn!(error = %rb, "事务回滚失败");
                }
                Err(e)
            }
        }
    }

    /// 健康探测（数据库必须可用；Redis/对象存储问题只降级为告警）。
    ///
    /// # Errors
    /// 数据库不可达。
    pub async fn health(&self) -> DomainResult<StoreHealth> {
        self.db.ping().await?;
        let redis_ok = match &self.redis {
            Some(r) => r.ping().await.is_ok(),
            None => false,
        };
        let objects_ok = self.objects.health().await.is_ok();
        Ok(StoreHealth {
            database: true,
            redis: redis_ok,
            objects: objects_ok,
            object_backend: self.objects.backend().to_string(),
        })
    }

    /// 平台统计（总览大屏）。
    ///
    /// # Errors
    /// SQL 执行失败。
    pub async fn platform_stats(&self, tenant: TenantId) -> DomainResult<PlatformStats> {
        self.with_tenant(tenant, |tx| {
            Box::pin(async move {
                // 显式类型标注：sqlx 0.8 的 `Executor` 只对 `&mut PgConnection` 实现，
                // 而 `Transaction` 通过 `Deref` 暴露内层连接，因此必须写成 `&mut **tx`。
                let conn: &mut sqlx::PgConnection = tx;
                let assets = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM assets WHERE deleted_at IS NULL")
                    .fetch_one(&mut *conn)
                    .await
                    .unwrap_or(0);
                let assets_production = sqlx::query_scalar::<_, i64>(
                    "SELECT count(*) FROM assets WHERE deleted_at IS NULL AND lifecycle = 'production'",
                )
                .fetch_one(&mut *conn)
                .await
                .unwrap_or(0);
                let shadow_mcps = sqlx::query_scalar::<_, i64>(
                    "SELECT count(*) FROM mcps WHERE NOT registered AND deleted_at IS NULL",
                )
                .fetch_one(&mut *conn)
                .await
                .unwrap_or(0);
                let alerts_active = sqlx::query_scalar::<_, i64>(
                    "SELECT count(*) FROM alerts WHERE state IN ('open','acknowledged','escalated')",
                )
                .fetch_one(&mut *conn)
                .await
                .unwrap_or(0);
                let findings_open = sqlx::query_scalar::<_, i64>(
                    "SELECT count(*) FROM findings WHERE deleted_at IS NULL AND state = 'pending'",
                )
                .fetch_one(&mut *conn)
                .await
                .unwrap_or(0);
                let findings_critical = sqlx::query_scalar::<_, i64>(
                    "SELECT count(*) FROM findings WHERE deleted_at IS NULL AND severity = 'critical' \
                     AND state NOT IN ('false-positive','fixed')",
                )
                .fetch_one(&mut *conn)
                .await
                .unwrap_or(0);
                let cases_open = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM cases WHERE state <> 'closed'")
                    .fetch_one(&mut *conn)
                    .await
                    .unwrap_or(0);
                let events_today =
                    sqlx::query_scalar::<_, i64>("SELECT count(*) FROM events WHERE time >= date_trunc('day', now())")
                        .fetch_one(&mut *conn)
                        .await
                        .unwrap_or(0);
                let policies = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM policies WHERE deleted_at IS NULL")
                    .fetch_one(&mut *conn)
                    .await
                    .unwrap_or(0);
                let rules_enabled = sqlx::query_scalar::<_, i64>(
                    "SELECT count(*) FROM risk_rules WHERE enabled AND deleted_at IS NULL",
                )
                .fetch_one(&mut *conn)
                .await
                .unwrap_or(0);
                Ok(PlatformStats {
                    assets,
                    assets_production,
                    shadow_mcps,
                    alerts_active,
                    findings_open,
                    findings_critical,
                    cases_open,
                    events_today,
                    policies,
                    rules_enabled,
                })
            })
        })
        .await
    }

    /// 各表行数快照（平台运维页，跨租户）。
    ///
    /// # Errors
    /// 查询失败。
    pub async fn table_counts(&self, tables: &[&str]) -> DomainResult<BTreeMap<String, i64>> {
        let mut out = BTreeMap::new();
        for t in tables {
            if !is_safe_identifier(t) {
                warn!(table = t, "跳过非法表名");
                continue;
            }
            match self.db.table_count(t).await {
                Ok(n) => {
                    out.insert((*t).to_string(), n);
                }
                Err(e) => warn!(table = t, error = %e, "统计表行数失败"),
            }
        }
        Ok(out)
    }
}

// ===========================================================================
// 行 → 领域对象
// ===========================================================================

pub(crate) fn json_from(row: &sqlx::postgres::PgRow, col: &str) -> serde_json::Value {
    row.try_get::<serde_json::Value, _>(col).unwrap_or(serde_json::Value::Null)
}

pub(crate) fn uuid_col(row: &sqlx::postgres::PgRow, col: &str) -> DomainResult<Id> {
    row.try_get::<uuid::Uuid, _>(col).map(Id::from_uuid).map_err(|e| DomainError::Internal(format!("列 {col}: {e}")))
}

pub(crate) fn ts_col(row: &sqlx::postgres::PgRow, col: &str) -> Timestamp {
    row.try_get::<chrono::DateTime<chrono::Utc>, _>(col)
        .map(Timestamp::from_datetime)
        .unwrap_or_else(|_| Timestamp::now())
}

pub(crate) fn ts_opt(row: &sqlx::postgres::PgRow, col: &str) -> Option<Timestamp> {
    row.try_get::<Option<chrono::DateTime<chrono::Utc>>, _>(col).ok().flatten().map(Timestamp::from_datetime)
}

pub(crate) fn severity_col(row: &sqlx::postgres::PgRow, col: &str) -> Severity {
    let raw: String = row.try_get(col).unwrap_or_else(|_| "info".to_string());
    Severity::parse(&raw).unwrap_or(Severity::Info)
}

/// 把一行所有列转成 JSON 对象（列表接口的通用投影，避免为每个表写一遍映射）。
pub(crate) fn row_to_json_object(row: &sqlx::postgres::PgRow) -> serde_json::Value {
    use sqlx::Column;
    let mut map = serde_json::Map::new();
    for (i, col) in row.columns().iter().enumerate() {
        map.insert(col.name().to_string(), decode_column(row, i));
    }
    serde_json::Value::Object(map)
}

pub(crate) fn decode_column(row: &sqlx::postgres::PgRow, idx: usize) -> serde_json::Value {
    use sqlx::ValueRef;
    match row.try_get_raw(idx) {
        Ok(v) if v.is_null() => return serde_json::Value::Null,
        Ok(_) => {}
        Err(_) => return serde_json::Value::Null,
    }
    let ty = row.column_type_info_public(idx);
    match ty.as_str() {
        "BOOL" => row.try_get::<bool, _>(idx).map(|v| serde_json::json!(v)).unwrap_or(serde_json::Value::Null),
        "INT2" => row.try_get::<i16, _>(idx).map(|v| serde_json::json!(v)).unwrap_or(serde_json::Value::Null),
        "INT4" => row.try_get::<i32, _>(idx).map(|v| serde_json::json!(v)).unwrap_or(serde_json::Value::Null),
        "INT8" => row.try_get::<i64, _>(idx).map(|v| serde_json::json!(v)).unwrap_or(serde_json::Value::Null),
        "FLOAT4" => row.try_get::<f32, _>(idx).map(|v| serde_json::json!(v)).unwrap_or(serde_json::Value::Null),
        "FLOAT8" => row.try_get::<f64, _>(idx).map(|v| serde_json::json!(v)).unwrap_or(serde_json::Value::Null),
        "JSON" | "JSONB" => row.try_get::<serde_json::Value, _>(idx).unwrap_or(serde_json::Value::Null),
        "UUID" => row
            .try_get::<uuid::Uuid, _>(idx)
            .map(|v| serde_json::Value::String(v.to_string()))
            .unwrap_or(serde_json::Value::Null),
        "TIMESTAMPTZ" | "TIMESTAMP" => row
            .try_get::<chrono::DateTime<chrono::Utc>, _>(idx)
            .map(|v| serde_json::Value::String(v.to_rfc3339()))
            .unwrap_or(serde_json::Value::Null),
        "DATE" => row
            .try_get::<chrono::NaiveDate, _>(idx)
            .map(|v| serde_json::Value::String(v.to_string()))
            .unwrap_or(serde_json::Value::Null),
        _ => row.try_get::<String, _>(idx).map(serde_json::Value::String).unwrap_or(serde_json::Value::Null),
    }
}

impl ColumnTypeInfo for sqlx::postgres::PgRow {
    fn column_type_info_public(&self, idx: usize) -> String {
        use sqlx::{Column, TypeInfo};
        self.columns().get(idx).map(|c| c.type_info().name().to_string()).unwrap_or_default()
    }
}
