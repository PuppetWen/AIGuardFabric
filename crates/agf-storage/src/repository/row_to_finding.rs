//! 由 `repository.rs` 拆分：`row_to_finding`/`parse_finding_state` 等 6 项（纯搬移，逻辑不变）。
use super::*;

use crate::db::{TenantTransaction, map_sqlx_err};
use agf_core::audit::{AuditAction, AuditActor, AuditLog, AuditOutcome, AuditTarget, GENESIS_HASH};
use agf_core::enums::{PolicyAction, RiskDomain};
use agf_core::error::{DomainError, DomainResult};
use agf_core::ids::{Id, TenantId};
use agf_core::policy::Policy;
use agf_core::risk::Finding;
use agf_core::time::Timestamp;
use tracing::debug;

pub(crate) fn row_to_finding(row: &sqlx::postgres::PgRow) -> DomainResult<Finding> {
    let dom_raw: String = row.try_get("domain").map_err(|e| DomainError::Internal(e.to_string()))?;
    let state_raw: String = row.try_get("state").unwrap_or_default();
    let ev_raw: String = row.try_get("evidence_level").unwrap_or_default();
    let audit_raw: Option<String> = row.try_get("audit_mode").unwrap_or(None);
    Ok(Finding {
        id: uuid_col(row, "id")?,
        tenant_id: TenantId::from_uuid(row.try_get("tenant_id").map_err(|e| DomainError::Internal(e.to_string()))?),
        title: row.try_get("title").unwrap_or_default(),
        severity: severity_col(row, "severity"),
        domain: RiskDomain::parse(&dom_raw).map_err(|e| DomainError::Parse(format!("domain: {e}")))?,
        category: row.try_get("category").unwrap_or_default(),
        cwe: row.try_get("cwe").unwrap_or(None),
        cvss: row.try_get("cvss").unwrap_or(None),
        target: row.try_get("target").unwrap_or_default(),
        asset_id: row.try_get::<Option<uuid::Uuid>, _>("asset_id").ok().flatten().map(Id::from_uuid),
        summary: row.try_get("summary").unwrap_or_default(),
        description: row.try_get("description").unwrap_or_default(),
        poc: row.try_get("poc").unwrap_or_default(),
        fix: row.try_get("fix").unwrap_or_default(),
        patch: row.try_get("patch").unwrap_or(None),
        state: parse_finding_state(&state_raw),
        evidence_level: parse_evidence_level(&ev_raw),
        evidence_refs: serde_json::from_value(json_from(row, "evidence_refs")).unwrap_or_default(),
        evidence: Vec::new(),
        rule_ids: serde_json::from_value(json_from(row, "rule_ids")).unwrap_or_default(),
        rule_keys: serde_json::from_value(json_from(row, "rule_keys")).unwrap_or_default(),
        llm_verdict: serde_json::from_value(json_from(row, "llm_verdict")).ok(),
        confidence: row.try_get("confidence").unwrap_or(0.0),
        source_origin: row.try_get("source_origin").unwrap_or_else(|_| "manual".to_string()),
        audit_mode: audit_raw.as_deref().and_then(|a| match a {
            "static" => Some(agf_core::risk::AuditMode::Static),
            "dynamic" => Some(agf_core::risk::AuditMode::Dynamic),
            _ => None,
        }),
        chain: row.try_get("chain").unwrap_or(None),
        chain_tracer: row.try_get("chain_tracer").unwrap_or(None),
        chain_verdict: row.try_get("chain_verdict").unwrap_or(None),
        baseline: row.try_get("baseline").unwrap_or(None),
        diff_evidence: row.try_get("diff_evidence").unwrap_or(None),
        marker_echo: row.try_get("marker_echo").unwrap_or(None),
        request_pkt: row.try_get("request_pkt").unwrap_or(None),
        response_pkt: row.try_get("response_pkt").unwrap_or(None),
        impact: row.try_get("impact").unwrap_or(None),
        verify_note: row.try_get("verify_note").unwrap_or(None),
        retest_note: row.try_get("retest_note").unwrap_or(None),
        first_seen_at: ts_col(row, "first_seen_at"),
        last_seen_at: ts_col(row, "last_seen_at"),
        created_at: ts_col(row, "created_at"),
        updated_at: ts_col(row, "updated_at"),
        deleted_at: None,
    })
}

pub(crate) fn parse_finding_state(raw: &str) -> agf_core::risk::FindingState {
    use agf_core::risk::FindingState as S;
    match raw.replace('_', "-").as_str() {
        "code-reviewed" => S::CodeReviewed,
        "verified" => S::Verified,
        "false-positive" => S::FalsePositive,
        "fixed" => S::Fixed,
        _ => S::Pending,
    }
}

pub(crate) fn parse_evidence_level(raw: &str) -> agf_core::enums::EvidenceLevel {
    use agf_core::enums::EvidenceLevel as E;
    match raw {
        "partial" => E::Partial,
        "confirmed" => E::Confirmed,
        "impact" => E::Impact,
        _ => E::Unknown,
    }
}

impl AuditRepo {
    /// 追加审计记录（自动取链尾哈希并封存）。
    ///
    /// # Errors
    /// SQL 执行失败。
    #[allow(clippy::too_many_arguments)]
    pub async fn append(
        tx: &mut TenantTransaction<'_>,
        action: AuditAction,
        outcome: AuditOutcome,
        actor: AuditActor,
        target: AuditTarget,
        before: Option<serde_json::Value>,
        after: Option<serde_json::Value>,
        changed_fields: Vec<String>,
        note: &str,
    ) -> DomainResult<Id> {
        let entry = AuditLog {
            id: Id::new(),
            tenant_id: tx.tenant(),
            sequence: 0,
            action,
            outcome,
            actor,
            target,
            before,
            after,
            changed_fields,
            request_id: None,
            error: None,
            note: note.to_string(),
            prev_hash: String::new(),
            entry_hash: String::new(),
            at: Timestamp::now(),
        };
        Ok(Self::append_log(tx, entry).await?.id)
    }

    /// Append a supplied audit event and return the database-sealed chain entry.
    ///
    /// # Errors
    /// The tenant is inconsistent or the SQL transaction fails.
    pub async fn append_log(tx: &mut TenantTransaction<'_>, mut entry: AuditLog) -> DomainResult<AuditLog> {
        if entry.tenant_id != tx.tenant() {
            return Err(DomainError::Validation("审计租户与数据库事务不一致".into()));
        }
        // The first entry has no row to lock. Serialize tail reads and inserts across instances.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!("{}:audit-chain", tx.tenant()))
            .execute(&mut **tx)
            .await
            .map_err(|e| map_sqlx_err("audit_chain_lock", &e))?;
        let tail = sqlx::query("SELECT sequence, entry_hash FROM audit_logs ORDER BY sequence DESC LIMIT 1")
            .fetch_optional(&mut **tx)
            .await
            .map_err(|e| map_sqlx_err("audit_tail", &e))?;
        let (seq, prev_hash) = match tail {
            Some(r) => (
                r.try_get::<i64, _>("sequence").unwrap_or(0) + 1,
                r.try_get::<String, _>("entry_hash").unwrap_or_else(|_| GENESIS_HASH.to_string()),
            ),
            None => (1, GENESIS_HASH.to_string()),
        };
        entry.sequence = seq;
        entry.prev_hash = prev_hash;
        if entry.before.is_some() || entry.after.is_some() {
            // preserve_order keeps insertion order, while PostgreSQL JSONB normalizes it
            // (including nested objects and numeric spelling). Hash the stored values.
            (entry.before, entry.after) = sqlx::query_as::<_, (Option<serde_json::Value>, Option<serde_json::Value>)>(
                "SELECT $1::jsonb, $2::jsonb",
            )
            .bind(&entry.before)
            .bind(&entry.after)
            .fetch_one(&mut **tx)
            .await
            .map_err(|e| map_sqlx_err("audit_snapshot_normalization", &e))?;
        }
        entry.entry_hash.clear();
        entry.seal();
        sqlx::query(
            "INSERT INTO audit_logs (id, tenant_id, sequence, action, outcome, actor, target, before, after,
                changed_fields, request_id, error, note, prev_hash, entry_hash, at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",
        )
        .bind(entry.id.as_uuid())
        .bind(entry.tenant_id.as_uuid())
        .bind(entry.sequence)
        .bind(entry.action.as_str())
        .bind(entry.outcome.as_str())
        .bind(serde_json::to_value(&entry.actor).unwrap_or(serde_json::Value::Null))
        .bind(serde_json::to_value(&entry.target).unwrap_or(serde_json::Value::Null))
        .bind(&entry.before)
        .bind(&entry.after)
        .bind(serde_json::to_value(&entry.changed_fields).unwrap_or(serde_json::Value::Null))
        .bind(&entry.request_id)
        .bind(&entry.error)
        .bind(&entry.note)
        .bind(&entry.prev_hash)
        .bind(&entry.entry_hash)
        .bind(entry.at.as_datetime())
        .execute(&mut **tx)
        .await
        .map_err(|e| match map_sqlx_err("append_audit", &e) {
            // Audit rows are server-generated; an integrity rejection is a storage fault,
            // not an invalid business request from the caller.
            DomainError::Validation(_) => {
                DomainError::Internal("append_audit: audit persistence rejected the event".into())
            }
            other => other,
        })?;
        debug!(sequence = seq, action = entry.action.as_str(), "审计记录已追加");
        Ok(entry)
    }

    /// 读取审计链用于完整性校验。
    ///
    /// # Errors
    /// SQL 执行失败。
    pub async fn load_chain(
        tx: &mut TenantTransaction<'_>,
        from_sequence: i64,
        limit: i64,
    ) -> DomainResult<Vec<AuditLog>> {
        let rows = sqlx::query("SELECT * FROM audit_logs WHERE sequence >= $1 ORDER BY sequence ASC LIMIT $2")
            .bind(from_sequence)
            .bind(limit)
            .fetch_all(&mut **tx)
            .await
            .map_err(|e| map_sqlx_err("load_audit_chain", &e))?;
        rows.iter().map(|row| row_to_audit(row, tx.tenant())).collect()
    }

    /// 链统计。
    ///
    /// # Errors
    /// SQL 执行失败。
    pub async fn chain_stats(tx: &mut TenantTransaction<'_>) -> DomainResult<(i64, String)> {
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_logs")
            .fetch_one(&mut **tx)
            .await
            .map_err(|e| map_sqlx_err("audit_stats", &e))?;
        let tail = sqlx::query("SELECT entry_hash FROM audit_logs ORDER BY sequence DESC LIMIT 1")
            .fetch_optional(&mut **tx)
            .await
            .map_err(|e| map_sqlx_err("audit_tail_hash", &e))?;
        Ok((
            n,
            tail.and_then(|r| r.try_get::<String, _>("entry_hash").ok()).unwrap_or_else(|| GENESIS_HASH.to_string()),
        ))
    }
}

pub(super) fn row_to_audit(r: &sqlx::postgres::PgRow, tenant: TenantId) -> DomainResult<AuditLog> {
    let action_raw: String = r.try_get("action").unwrap_or_default();
    let outcome_raw: String = r.try_get("outcome").unwrap_or_default();
    Ok(AuditLog {
        id: uuid_col(r, "id")?,
        tenant_id: tenant,
        sequence: r.try_get("sequence").unwrap_or(0),
        action: parse_audit_action(&action_raw),
        outcome: match outcome_raw.as_str() {
            "failure" => AuditOutcome::Failure,
            "denied" => AuditOutcome::Denied,
            _ => AuditOutcome::Success,
        },
        actor: serde_json::from_value(json_from(r, "actor")).unwrap_or_else(|_| AuditActor {
            id: None,
            kind: "unknown".into(),
            name: "unknown".into(),
            source_ip: None,
            user_agent: None,
            session_id: None,
        }),
        target: serde_json::from_value(json_from(r, "target")).unwrap_or_else(|_| AuditTarget {
            kind: "unknown".into(),
            id: None,
            name: None,
        }),
        before: r.try_get("before").unwrap_or(None),
        after: r.try_get("after").unwrap_or(None),
        changed_fields: serde_json::from_value(json_from(r, "changed_fields")).unwrap_or_default(),
        request_id: r.try_get("request_id").unwrap_or(None),
        error: r.try_get("error").unwrap_or(None),
        note: r.try_get("note").unwrap_or_default(),
        prev_hash: r.try_get("prev_hash").unwrap_or_default(),
        entry_hash: r.try_get("entry_hash").unwrap_or_default(),
        at: ts_col(r, "at"),
    })
}

pub(crate) fn parse_audit_action(raw: &str) -> AuditAction {
    match raw.replace('_', "-").as_str() {
        "login" => AuditAction::Login,
        "logout" => AuditAction::Logout,
        "create" => AuditAction::Create,
        "read" => AuditAction::Read,
        "update" => AuditAction::Update,
        "delete" => AuditAction::Delete,
        "export" => AuditAction::Export,
        "execute" => AuditAction::Execute,
        "configure" => AuditAction::Configure,
        "grant" => AuditAction::Grant,
        "approve" => AuditAction::Approve,
        "contain" => AuditAction::Contain,
        _ => AuditAction::System,
    }
}

impl PolicyRepo {
    /// 按名称写入或更新策略。
    ///
    /// # Errors
    /// SQL 执行失败。
    pub async fn upsert(tx: &mut TenantTransaction<'_>, p: &Policy) -> DomainResult<Id> {
        let hash = p.compute_hash();
        let points: Vec<&str> = p.intercept_points.iter().map(agf_core::enums::InterceptPoint::as_str).collect();
        let updated = sqlx::query(
            r"UPDATE policies SET description = $1, language = $2, source = $3, structured = $4,
                 action = $5, priority = $6, intercept_points = $7, scope_agent_ids = $8,
                 scope_departments = $9, enabled = $10, dry_run = $11, quota_id = $12,
                 degrade_endpoint_id = $13, content_hash = $14, signature = $15,
                 version = version + 1, updated_at = now()
               WHERE name = $16 AND deleted_at IS NULL RETURNING id",
        )
        .bind(&p.description)
        .bind(p.language.as_str())
        .bind(&p.source)
        .bind(serde_json::to_value(&p.structured).unwrap_or(serde_json::Value::Null))
        .bind(p.action.as_str())
        .bind(i32::try_from(p.priority).unwrap_or(100))
        .bind(serde_json::to_value(&points).unwrap_or(serde_json::Value::Null))
        .bind(serde_json::to_value(&p.scope_agent_ids).unwrap_or(serde_json::Value::Null))
        .bind(serde_json::to_value(&p.scope_departments).unwrap_or(serde_json::Value::Null))
        .bind(p.enabled)
        .bind(p.dry_run)
        .bind(p.quota_id.map(|v| v.as_uuid()))
        .bind(p.degrade_endpoint_id.map(|v| v.as_uuid()))
        .bind(&hash)
        .bind(&p.signature)
        .bind(&p.name)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|e| map_sqlx_err("update_policy", &e))?;
        if let Some(row) = updated {
            let id: uuid::Uuid = row.try_get("id").map_err(|e| DomainError::Internal(e.to_string()))?;
            return Ok(Id::from_uuid(id));
        }
        sqlx::query(
            r"INSERT INTO policies (id, tenant_id, name, description, language, source, structured, action,
                priority, intercept_points, scope_agent_ids, scope_departments, enabled, dry_run,
                quota_id, degrade_endpoint_id, content_hash, signature, version, created_at, updated_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)",
        )
        .bind(p.id.as_uuid())
        .bind(p.tenant_id.as_uuid())
        .bind(&p.name)
        .bind(&p.description)
        .bind(p.language.as_str())
        .bind(&p.source)
        .bind(serde_json::to_value(&p.structured).unwrap_or(serde_json::Value::Null))
        .bind(p.action.as_str())
        .bind(i32::try_from(p.priority).unwrap_or(100))
        .bind(serde_json::to_value(&points).unwrap_or(serde_json::Value::Null))
        .bind(serde_json::to_value(&p.scope_agent_ids).unwrap_or(serde_json::Value::Null))
        .bind(serde_json::to_value(&p.scope_departments).unwrap_or(serde_json::Value::Null))
        .bind(p.enabled)
        .bind(p.dry_run)
        .bind(p.quota_id.map(|v| v.as_uuid()))
        .bind(p.degrade_endpoint_id.map(|v| v.as_uuid()))
        .bind(&hash)
        .bind(&p.signature)
        .bind(i32::try_from(p.version).unwrap_or(1))
        .bind(p.created_at.as_datetime())
        .bind(p.updated_at.as_datetime())
        .execute(&mut **tx)
        .await
        .map_err(|e| map_sqlx_err("insert_policy", &e))?;
        Ok(p.id)
    }

    /// 列出启用策略（优先级升序）。
    ///
    /// # Errors
    /// SQL 执行失败。
    pub async fn list_enabled(tx: &mut TenantTransaction<'_>) -> DomainResult<Vec<Policy>> {
        let rows = sqlx::query("SELECT * FROM policies WHERE enabled AND deleted_at IS NULL ORDER BY priority ASC")
            .fetch_all(&mut **tx)
            .await
            .map_err(|e| map_sqlx_err("list_policies", &e))?;
        Ok(rows.iter().map(row_to_policy).collect())
    }

    /// 列出全部策略（含停用，控制台用）。
    ///
    /// # Errors
    /// SQL 执行失败。
    pub async fn list_all(tx: &mut TenantTransaction<'_>) -> DomainResult<Vec<serde_json::Value>> {
        let rows = sqlx::query("SELECT * FROM policies WHERE deleted_at IS NULL ORDER BY priority ASC")
            .fetch_all(&mut **tx)
            .await
            .map_err(|e| map_sqlx_err("list_all_policies", &e))?;
        Ok(rows.iter().map(row_to_json_object).collect())
    }

    /// 记录策略命中（运行时审计）。
    ///
    /// # Errors
    /// SQL 执行失败。
    #[allow(clippy::too_many_arguments)]
    pub async fn record_hit(
        tx: &mut TenantTransaction<'_>,
        policy_id: Id,
        policy_name: &str,
        action: PolicyAction,
        intercept_point: &str,
        session_id: &str,
        agent_id: Option<Id>,
        excerpt: &str,
        enforced: bool,
    ) -> DomainResult<()> {
        sqlx::query(
            "INSERT INTO policy_hits (id, tenant_id, policy_id, policy_name, action, intercept_point,
                session_id, agent_id, request_excerpt, enforced, at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        )
        .bind(Id::new().as_uuid())
        .bind(tx.tenant().as_uuid())
        .bind(policy_id.as_uuid())
        .bind(policy_name)
        .bind(action.as_str())
        .bind(intercept_point)
        .bind(session_id)
        .bind(agent_id.map(|v| v.as_uuid()))
        .bind(excerpt)
        .bind(enforced)
        .bind(Timestamp::now().as_datetime())
        .execute(&mut **tx)
        .await
        .map_err(|e| map_sqlx_err("record_policy_hit", &e))?;
        Ok(())
    }
}
