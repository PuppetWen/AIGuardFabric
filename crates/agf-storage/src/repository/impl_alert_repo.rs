//! Durable alert merging and state changes, serialized per tenant/dedup key.
use super::*;
use crate::db::{TenantTransaction, map_sqlx_err};
use agf_core::{
    enums::{AlertState, RiskDomain, Severity},
    error::{DomainError, DomainResult},
    ids::Id,
    time::Timestamp,
};

impl AlertRepo {
    /// 按去重键 upsert（聚合降噪）。
    ///
    /// 返回 `(告警 id, 是否新建)`。
    ///
    /// # Errors
    /// SQL 执行失败。
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_dedup(
        tx: &mut TenantTransaction<'_>,
        dedup_key: &str,
        title: &str,
        description: &str,
        severity: Severity,
        domain: Option<RiskDomain>,
        asset_ids: &[Id],
        finding_ids: &[Id],
        sla_due_at: Option<Timestamp>,
    ) -> DomainResult<(Id, bool)> {
        // Serialize creation as well as merge; a row lock alone cannot lock an absent key.
        let lock_key = format!("{}:{dedup_key}", tx.tenant());
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(lock_key)
            .execute(&mut **tx)
            .await
            .map_err(|e| map_sqlx_err("lock_alert_dedup", &e))?;
        let existing = sqlx::query(
            "SELECT id, asset_ids, finding_ids FROM alerts WHERE dedup_key = $1 \
             AND deleted_at IS NULL AND state IN ('open','acknowledged','escalated') ORDER BY last_seen_at DESC LIMIT 1 FOR UPDATE",
        )
        .bind(dedup_key)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|e| map_sqlx_err("find_alert_by_dedup", &e))?;

        if let Some(row) = existing {
            let id: uuid::Uuid = row.try_get("id").map_err(|e| DomainError::Internal(e.to_string()))?;
            // 合并资产/发现清单（在 Rust 侧去重，避免依赖 jsonb 聚合函数）
            let mut merged_assets: Vec<String> =
                serde_json::from_value(json_from(&row, "asset_ids")).unwrap_or_default();
            for a in asset_ids {
                let s = a.to_string();
                if !merged_assets.contains(&s) {
                    merged_assets.push(s);
                }
            }
            let mut merged_findings: Vec<String> =
                serde_json::from_value(json_from(&row, "finding_ids")).unwrap_or_default();
            for f in finding_ids {
                let s = f.to_string();
                if !merged_findings.contains(&s) {
                    merged_findings.push(s);
                }
            }
            sqlx::query(
                "UPDATE alerts SET dedup_count = dedup_count + 1, last_seen_at = now(), updated_at = now(), \
                 severity = CASE WHEN severity = 'critical' THEN 'critical' \
                                 WHEN $1 = 'critical' THEN 'critical' \
                                 WHEN severity = 'high' THEN 'high' \
                                 WHEN $1 = 'high' THEN 'high' \
                                 WHEN severity = 'medium' THEN 'medium' \
                                 WHEN $1 = 'medium' THEN 'medium' \
                                 WHEN severity = 'low' OR $1 = 'low' THEN 'low' ELSE severity END, \
                 asset_ids = $2, finding_ids = $3 WHERE id = $4",
            )
            .bind(severity.as_str())
            .bind(serde_json::to_value(&merged_assets).unwrap_or(serde_json::Value::Null))
            .bind(serde_json::to_value(&merged_findings).unwrap_or(serde_json::Value::Null))
            .bind(id)
            .execute(&mut **tx)
            .await
            .map_err(|e| map_sqlx_err("merge_alert", &e))?;
            return Ok((Id::from_uuid(id), false));
        }

        let id = Id::new();
        sqlx::query(
            r"INSERT INTO alerts (id, tenant_id, title, description, severity, domain, state, finding_ids,
                dedup_count, dedup_key, asset_ids, event_ids, affected_hosts, first_seen_at, last_seen_at,
                escalation_level, sla_due_at, sla_breached, tags, created_at, updated_at)
               VALUES ($1,$2,$3,$4,$5,$6,'open',$7,1,$8,$9,'[]'::jsonb,'[]'::jsonb,now(),now(),0,$10,false,'[]'::jsonb,now(),now())",
        )
        .bind(id.as_uuid())
        .bind(tx.tenant().as_uuid())
        .bind(title)
        .bind(description)
        .bind(severity.as_str())
        .bind(domain.map(|d| d.as_str().to_string()))
        .bind(serde_json::to_value(finding_ids.iter().map(ToString::to_string).collect::<Vec<_>>()).unwrap_or(serde_json::Value::Null))
        .bind(dedup_key)
        .bind(serde_json::to_value(asset_ids.iter().map(ToString::to_string).collect::<Vec<_>>()).unwrap_or(serde_json::Value::Null))
        .bind(sla_due_at.map(|t| t.as_datetime()))
        .execute(&mut **tx)
        .await
        .map_err(|e| map_sqlx_err("insert_alert", &e))?;
        Ok((id, true))
    }

    /// 更新状态与指派人。
    ///
    /// # Errors
    /// 记录不存在或 SQL 失败。
    pub async fn set_state(
        tx: &mut TenantTransaction<'_>,
        id: Id,
        state: AlertState,
        assignee: Option<&str>,
    ) -> DomainResult<()> {
        let affected = sqlx::query(
            "UPDATE alerts SET state = $1, assignee = COALESCE($2, assignee), updated_at = now() WHERE id = $3 AND deleted_at IS NULL",
        )
        .bind(state.as_str())
        .bind(assignee)
        .bind(id.as_uuid())
        .execute(&mut **tx)
        .await
        .map_err(|e| map_sqlx_err("set_alert_state", &e))?
        .rows_affected();
        if affected == 0 {
            return Err(DomainError::NotFound { entity: "alert", id: id.to_string() });
        }
        Ok(())
    }

    /// 列出活动告警（按等级与时间排序）。
    ///
    /// # Errors
    /// SQL 执行失败。
    pub async fn list_active(tx: &mut TenantTransaction<'_>, limit: i64) -> DomainResult<Vec<serde_json::Value>> {
        let rows = sqlx::query(
            "SELECT * FROM alerts WHERE deleted_at IS NULL AND state IN ('open','acknowledged','escalated') \
             ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, \
             last_seen_at DESC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&mut **tx)
        .await
        .map_err(|e| map_sqlx_err("list_alerts", &e))?;
        Ok(rows.iter().map(row_to_json_object).collect())
    }

    /// 刷新 SLA 超时标记（由调度器周期调用）。
    ///
    /// # Errors
    /// SQL 执行失败。
    pub async fn refresh_sla(tx: &mut TenantTransaction<'_>) -> DomainResult<u64> {
        let n = sqlx::query(
            "UPDATE alerts SET sla_breached = true \
             WHERE state IN ('open','acknowledged','escalated') AND NOT sla_breached \
             AND sla_due_at IS NOT NULL AND sla_due_at < now()",
        )
        .execute(&mut **tx)
        .await
        .map_err(|e| map_sqlx_err("refresh_sla", &e))?
        .rows_affected();
        Ok(n)
    }

    /// SLA 超时计数。
    ///
    /// # Errors
    /// SQL 执行失败。
    pub async fn sla_breached_count(tx: &mut TenantTransaction<'_>) -> DomainResult<i64> {
        sqlx::query_scalar(
            "SELECT count(*) FROM alerts WHERE state IN ('open','acknowledged','escalated') \
             AND sla_due_at IS NOT NULL AND sla_due_at < now()",
        )
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| map_sqlx_err("sla_count", &e))
    }
}
