//! 由 `repository.rs` 拆分：`row_to_policy`/`impl_EventRepo` 等 4 项（纯搬移，逻辑不变）。
use super::*;

use crate::db::{TenantTransaction, map_sqlx_err};
use agf_core::enums::{PolicyAction, Severity};
use agf_core::error::{DomainError, DomainResult};
use agf_core::event::{Event, RawLog};
use agf_core::ids::{Id, TenantId};
use agf_core::policy::Policy;
use agf_core::time::Timestamp;
use std::collections::BTreeMap;

pub(crate) fn row_to_policy(row: &sqlx::postgres::PgRow) -> Policy {
    use agf_core::enums::InterceptPoint;
    use agf_core::policy::{PolicyLanguage, StructuredCondition};
    let lang_raw: String = row.try_get("language").unwrap_or_else(|_| "structured".to_string());
    let action_raw: String = row.try_get("action").unwrap_or_else(|_| "audit".to_string());
    let points: Vec<String> = serde_json::from_value(json_from(row, "intercept_points")).unwrap_or_default();
    Policy {
        id: Id::from_uuid(row.try_get("id").unwrap_or_else(|_| uuid::Uuid::nil())),
        tenant_id: TenantId::from_uuid(row.try_get("tenant_id").unwrap_or_else(|_| uuid::Uuid::nil())),
        name: row.try_get("name").unwrap_or_default(),
        description: row.try_get("description").unwrap_or_default(),
        language: PolicyLanguage::parse(&lang_raw).unwrap_or(PolicyLanguage::Structured),
        source: row.try_get("source").unwrap_or_default(),
        structured: serde_json::from_value::<StructuredCondition>(json_from(row, "structured")).unwrap_or_default(),
        action: PolicyAction::parse(&action_raw).unwrap_or(PolicyAction::Audit),
        priority: u32::try_from(row.try_get::<i32, _>("priority").unwrap_or(100)).unwrap_or(100),
        intercept_points: points
            .iter()
            .filter_map(|p| {
                [
                    InterceptPoint::McpProxy,
                    InterceptPoint::AiGateway,
                    InterceptPoint::ProcessHook,
                    InterceptPoint::Collector,
                ]
                .into_iter()
                .find(|i| i.as_str() == p)
            })
            .collect(),
        scope_agent_ids: serde_json::from_value(json_from(row, "scope_agent_ids")).unwrap_or_default(),
        scope_departments: serde_json::from_value(json_from(row, "scope_departments")).unwrap_or_default(),
        enabled: row.try_get("enabled").unwrap_or(true),
        dry_run: row.try_get("dry_run").unwrap_or(false),
        quota_id: row.try_get::<Option<uuid::Uuid>, _>("quota_id").ok().flatten().map(Id::from_uuid),
        degrade_endpoint_id: row
            .try_get::<Option<uuid::Uuid>, _>("degrade_endpoint_id")
            .ok()
            .flatten()
            .map(Id::from_uuid),
        content_hash: row.try_get("content_hash").unwrap_or_default(),
        signature: row.try_get("signature").unwrap_or_default(),
        version: u32::try_from(row.try_get::<i32, _>("version").unwrap_or(1)).unwrap_or(1),
        created_at: ts_col(row, "created_at"),
        updated_at: ts_col(row, "updated_at"),
        deleted_at: None,
    }
}

impl EventRepo {
    /// 写入归一化事件。
    ///
    /// # Errors
    /// SQL 执行失败。
    pub async fn insert(tx: &mut TenantTransaction<'_>, e: &Event) -> DomainResult<()> {
        sqlx::query(
            r#"INSERT INTO events (id, tenant_id, time, ingested_at, category, action, action_raw, severity,
                source_id, source_name, protocol, parser_id, parser_name, vendor, product, host, "user",
                network, ai, message, raw, raw_ref, raw_hash, redacted, tags, extra)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26)
               ON CONFLICT (tenant_id, time, id) DO NOTHING"#,
        )
        .bind(e.id.as_uuid())
        .bind(e.tenant_id.as_uuid())
        .bind(e.time.as_datetime())
        .bind(e.ingested_at.as_datetime())
        .bind(e.category.as_str())
        .bind(e.action.as_str())
        .bind(&e.action_raw)
        .bind(e.severity.as_str())
        .bind(e.source_id.as_uuid())
        .bind(&e.source_name)
        .bind(e.protocol.as_str())
        .bind(e.parser_id.map(|v| v.as_uuid()))
        .bind(&e.parser_name)
        .bind(&e.vendor)
        .bind(&e.product)
        .bind(serde_json::to_value(&e.host).unwrap_or(serde_json::Value::Null))
        .bind(serde_json::to_value(&e.user).unwrap_or(serde_json::Value::Null))
        .bind(serde_json::to_value(&e.network).unwrap_or(serde_json::Value::Null))
        .bind(serde_json::to_value(&e.ai).unwrap_or(serde_json::Value::Null))
        .bind(&e.message)
        .bind(&e.raw)
        .bind(&e.raw_ref)
        .bind(&e.raw_hash)
        .bind(e.redacted)
        .bind(serde_json::to_value(&e.tags).unwrap_or(serde_json::Value::Null))
        .bind(serde_json::to_value(&e.extra).unwrap_or(serde_json::Value::Null))
        .execute(&mut **tx)
        .await
        .map_err(|e| map_sqlx_err("insert_event", &e))?;
        Ok(())
    }

    /// Insert bounded multi-row statements in the caller's tenant transaction.
    /// The return value retains the existing accepted-input count, including retries.
    pub async fn insert_batch(tx: &mut TenantTransaction<'_>, events: &[Event]) -> DomainResult<usize> {
        if events.iter().any(|event| event.tenant_id != tx.tenant()) {
            return Err(DomainError::Validation("Event batch contains another tenant".into()));
        }
        // 26 binds per event. The 512-row cap bounds SQL/memory below PostgreSQL's
        // 65,535 bind limit even when a caller supplies a much larger batch.
        for chunk in events.chunks(512) {
            let mut query = sqlx::QueryBuilder::<sqlx::Postgres>::new(
                r#"INSERT INTO events (id, tenant_id, time, ingested_at, category, action, action_raw, severity,
                source_id, source_name, protocol, parser_id, parser_name, vendor, product, host, "user",
                network, ai, message, raw, raw_ref, raw_hash, redacted, tags, extra) "#,
            );
            query.push_values(chunk, |mut row, event| {
                row.push_bind(event.id.as_uuid())
                    .push_bind(event.tenant_id.as_uuid())
                    .push_bind(event.time.as_datetime())
                    .push_bind(event.ingested_at.as_datetime())
                    .push_bind(event.category.as_str())
                    .push_bind(event.action.as_str())
                    .push_bind(&event.action_raw)
                    .push_bind(event.severity.as_str())
                    .push_bind(event.source_id.as_uuid())
                    .push_bind(&event.source_name)
                    .push_bind(event.protocol.as_str())
                    .push_bind(event.parser_id.map(|id| id.as_uuid()))
                    .push_bind(&event.parser_name)
                    .push_bind(&event.vendor)
                    .push_bind(&event.product)
                    .push_bind(serde_json::to_value(&event.host).unwrap_or(serde_json::Value::Null))
                    .push_bind(serde_json::to_value(&event.user).unwrap_or(serde_json::Value::Null))
                    .push_bind(serde_json::to_value(&event.network).unwrap_or(serde_json::Value::Null))
                    .push_bind(serde_json::to_value(&event.ai).unwrap_or(serde_json::Value::Null))
                    .push_bind(&event.message)
                    .push_bind(&event.raw)
                    .push_bind(&event.raw_ref)
                    .push_bind(&event.raw_hash)
                    .push_bind(event.redacted)
                    .push_bind(serde_json::to_value(&event.tags).unwrap_or(serde_json::Value::Null))
                    .push_bind(serde_json::to_value(&event.extra).unwrap_or(serde_json::Value::Null));
            });
            query.push(" ON CONFLICT (tenant_id, time, id) DO NOTHING");
            query.build().execute(&mut **tx).await.map_err(|error| map_sqlx_err("insert_events", &error))?;
        }
        Ok(events.len())
    }

    /// Store raw evidence in bounded statements, preserving existing parse state on retry.
    /// An ID reused for different evidence fails the caller's whole transaction.
    pub async fn insert_raw_batch(tx: &mut TenantTransaction<'_>, raws: &[RawLog]) -> DomainResult<()> {
        let mut identities = std::collections::HashMap::<Id, &RawLog>::with_capacity(raws.len());
        for raw in raws {
            if raw.tenant_id != tx.tenant() {
                return Err(DomainError::Validation("Raw batch contains another tenant".into()));
            }
            if let Some(previous) = identities.insert(raw.id, raw) {
                if previous.source_id != raw.source_id
                    || previous.protocol != raw.protocol
                    || previous.payload_hash != raw.payload_hash
                    || previous.payload_b64 != raw.payload_b64
                    || previous.bytes != raw.bytes
                    || previous.origin != raw.origin
                {
                    return Err(DomainError::Conflict("原始日志 ID 与既有内容冲突".into()));
                }
            }
        }
        // 12 binds per raw row, never more than 6,144 binds per statement.
        for chunk in raws.chunks(512) {
            let mut query = sqlx::QueryBuilder::<sqlx::Postgres>::new(
                "INSERT INTO raw_logs (id, tenant_id, source_id, received_at, protocol, payload_b64, payload_hash,
                bytes, origin, parsed, parse_error, event_id) ",
            );
            query.push_values(chunk, |mut row, raw| {
                row.push_bind(raw.id.as_uuid())
                    .push_bind(raw.tenant_id.as_uuid())
                    .push_bind(raw.source_id.as_uuid())
                    .push_bind(raw.received_at.as_datetime())
                    .push_bind(raw.protocol.as_str())
                    .push_bind(&raw.payload_b64)
                    .push_bind(&raw.payload_hash)
                    .push_bind(i32::try_from(raw.bytes).unwrap_or(i32::MAX))
                    .push_bind(&raw.origin)
                    .push_bind(raw.parsed)
                    .push_bind(&raw.parse_error)
                    .push_bind(raw.event_id.map(|id| id.as_uuid()));
            });
            query.push(" ON CONFLICT (id) DO NOTHING RETURNING id");
            let inserted: std::collections::HashSet<uuid::Uuid> = query
                .build_query_scalar()
                .fetch_all(&mut **tx)
                .await
                .map_err(|error| map_sqlx_err("insert_raw_logs", &error))?
                .into_iter()
                .collect();
            let conflicts: Vec<uuid::Uuid> =
                chunk.iter().map(|raw| raw.id.as_uuid()).filter(|id| !inserted.contains(id)).collect();
            if conflicts.is_empty() {
                continue;
            }
            // A separate statement sees a concurrent insert after ON CONFLICT waits
            // for it. RLS also makes an ID owned by another tenant fail closed.
            let existing = sqlx::query(
                "SELECT id, tenant_id, source_id, protocol, payload_hash, payload_b64, bytes, origin
                 FROM raw_logs WHERE id=ANY($1)",
            )
            .bind(&conflicts)
            .fetch_all(&mut **tx)
            .await
            .map_err(|error| map_sqlx_err("check_existing_raw_logs", &error))?;
            let mut verified = std::collections::HashSet::new();
            for row in existing {
                let id: uuid::Uuid = row.try_get("id").map_err(|error| map_sqlx_err("read_raw_id", &error))?;
                let Some(raw) = identities.get(&Id::from_uuid(id)) else {
                    return Err(DomainError::Conflict("原始日志 ID 与既有内容冲突".into()));
                };
                let same = row.try_get::<uuid::Uuid, _>("tenant_id").ok() == Some(raw.tenant_id.as_uuid())
                    && row.try_get::<uuid::Uuid, _>("source_id").ok() == Some(raw.source_id.as_uuid())
                    && row.try_get::<String, _>("protocol").ok().as_deref() == Some(raw.protocol.as_str())
                    && row.try_get::<String, _>("payload_hash").ok().as_deref() == Some(raw.payload_hash.as_str())
                    && row.try_get::<String, _>("payload_b64").ok().as_deref() == Some(raw.payload_b64.as_str())
                    && row.try_get::<i32, _>("bytes").ok() == Some(i32::try_from(raw.bytes).unwrap_or(i32::MAX))
                    && row.try_get::<String, _>("origin").ok().as_deref() == Some(raw.origin.as_str());
                if !same {
                    return Err(DomainError::Conflict("原始日志 ID 与既有内容冲突".into()));
                }
                verified.insert(id);
            }
            if conflicts.iter().any(|id| !verified.contains(id)) {
                return Err(DomainError::Conflict("原始日志 ID 与既有内容冲突".into()));
            }
        }
        Ok(())
    }

    /// 查询事件（时间倒序）。
    ///
    /// # Errors
    /// SQL 执行失败。
    pub async fn list(
        tx: &mut TenantTransaction<'_>,
        from: Timestamp,
        to: Timestamp,
        severity: Option<Severity>,
        limit: i64,
    ) -> DomainResult<Vec<serde_json::Value>> {
        let rows = sqlx::query(
            r#"SELECT id, time, category, action, severity, source_name, vendor, product, message, host, "user", network, ai
               FROM events WHERE time >= $1 AND time < $2 AND ($3::text IS NULL OR severity = $3)
               ORDER BY time DESC LIMIT $4"#,
        )
        .bind(from.as_datetime())
        .bind(to.as_datetime())
        .bind(severity.map(|s| s.as_str().to_string()))
        .bind(limit)
        .fetch_all(&mut **tx)
        .await
        .map_err(|e| map_sqlx_err("list_events", &e))?;
        Ok(rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "id": r.try_get::<uuid::Uuid, _>("id").map(|u| u.to_string()).unwrap_or_default(),
                    "time": r.try_get::<chrono::DateTime<chrono::Utc>, _>("time").map(|t| t.to_rfc3339()).unwrap_or_default(),
                    "category": r.try_get::<String, _>("category").unwrap_or_default(),
                    "action": r.try_get::<String, _>("action").unwrap_or_default(),
                    "severity": r.try_get::<String, _>("severity").unwrap_or_default(),
                    "source_name": r.try_get::<String, _>("source_name").unwrap_or_default(),
                    "vendor": r.try_get::<String, _>("vendor").unwrap_or_default(),
                    "product": r.try_get::<String, _>("product").unwrap_or_default(),
                    "message": r.try_get::<String, _>("message").unwrap_or_default(),
                    "host": json_from(r, "host"),
                    "user": json_from(r, "user"),
                    "network": json_from(r, "network"),
                    "ai": json_from(r, "ai"),
                })
            })
            .collect())
    }

    /// 保存原始日志（保真层，供回放）。
    ///
    /// # Errors
    /// SQL 执行失败。
    pub async fn insert_raw(tx: &mut TenantTransaction<'_>, raw: &RawLog) -> DomainResult<()> {
        let inserted = sqlx::query(
            "INSERT INTO raw_logs (id, tenant_id, source_id, received_at, protocol, payload_b64, payload_hash,
                bytes, origin, parsed, parse_error, event_id)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(raw.id.as_uuid())
        .bind(raw.tenant_id.as_uuid())
        .bind(raw.source_id.as_uuid())
        .bind(raw.received_at.as_datetime())
        .bind(raw.protocol.as_str())
        .bind(&raw.payload_b64)
        .bind(&raw.payload_hash)
        .bind(i32::try_from(raw.bytes).unwrap_or(i32::MAX))
        .bind(&raw.origin)
        .bind(raw.parsed)
        .bind(&raw.parse_error)
        .bind(raw.event_id.map(|v| v.as_uuid()))
        .execute(&mut **tx)
        .await
        .map_err(|e| map_sqlx_err("insert_raw_log", &e))?
        .rows_affected();
        if inserted == 0 {
            // A replayed message is harmless, but an ID reused for different content must fail.
            // Keep the existing parse state: replay may already have marked the raw log parsed.
            let existing =
                sqlx::query("SELECT tenant_id, source_id, protocol, payload_hash, origin FROM raw_logs WHERE id=$1")
                    .bind(raw.id.as_uuid())
                    .fetch_optional(&mut **tx)
                    .await
                    .map_err(|e| map_sqlx_err("check_existing_raw_log", &e))?;
            let same = existing.as_ref().is_some_and(|row| {
                row.try_get::<uuid::Uuid, _>("tenant_id").ok() == Some(raw.tenant_id.as_uuid())
                    && row.try_get::<uuid::Uuid, _>("source_id").ok() == Some(raw.source_id.as_uuid())
                    && row.try_get::<String, _>("protocol").ok().as_deref() == Some(raw.protocol.as_str())
                    && row.try_get::<String, _>("payload_hash").ok().as_deref() == Some(raw.payload_hash.as_str())
                    && row.try_get::<String, _>("origin").ok().as_deref() == Some(raw.origin.as_str())
            });
            if !same {
                return Err(DomainError::Conflict("原始日志 ID 与既有内容冲突".into()));
            }
        }
        Ok(())
    }

    /// 拉取未解析的原始日志（回放/重解析）。
    ///
    /// # Errors
    /// SQL 执行失败。
    pub async fn unparsed_raw(tx: &mut TenantTransaction<'_>, limit: i64) -> DomainResult<Vec<RawLog>> {
        let rows = sqlx::query("SELECT * FROM raw_logs WHERE NOT parsed ORDER BY received_at ASC LIMIT $1")
            .bind(limit)
            .fetch_all(&mut **tx)
            .await
            .map_err(|e| map_sqlx_err("list_unparsed_raw", &e))?;
        let tenant = tx.tenant();
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let proto_raw: String = r.try_get("protocol").unwrap_or_else(|_| "file".into());
            out.push(RawLog {
                id: uuid_col(&r, "id")?,
                tenant_id: tenant,
                source_id: uuid_col(&r, "source_id")?,
                received_at: ts_col(&r, "received_at"),
                protocol: parse_ingest_protocol(&proto_raw),
                payload_b64: r.try_get("payload_b64").unwrap_or_default(),
                payload_hash: r.try_get("payload_hash").unwrap_or_default(),
                bytes: usize::try_from(r.try_get::<i32, _>("bytes").unwrap_or(0)).unwrap_or(0),
                origin: r.try_get("origin").unwrap_or_default(),
                parsed: r.try_get("parsed").unwrap_or(false),
                parse_error: r.try_get("parse_error").unwrap_or(None),
                event_id: r.try_get::<Option<uuid::Uuid>, _>("event_id").ok().flatten().map(Id::from_uuid),
            });
        }
        Ok(out)
    }

    /// 事件按严重等级统计。
    ///
    /// # Errors
    /// SQL 执行失败。
    pub async fn count_by_severity(
        tx: &mut TenantTransaction<'_>,
        from: Timestamp,
        to: Timestamp,
    ) -> DomainResult<BTreeMap<String, i64>> {
        let rows =
            sqlx::query("SELECT severity, count(*) AS n FROM events WHERE time >= $1 AND time < $2 GROUP BY severity")
                .bind(from.as_datetime())
                .bind(to.as_datetime())
                .fetch_all(&mut **tx)
                .await
                .map_err(|e| map_sqlx_err("count_events", &e))?;
        Ok(rows
            .iter()
            .map(|r| (r.try_get::<String, _>("severity").unwrap_or_default(), r.try_get::<i64, _>("n").unwrap_or(0)))
            .collect())
    }
}

pub(crate) fn parse_ingest_protocol(raw: &str) -> agf_core::enums::IngestProtocol {
    use agf_core::enums::IngestProtocol as P;
    P::all().into_iter().find(|p| p.as_str() == raw).unwrap_or(P::File)
}
