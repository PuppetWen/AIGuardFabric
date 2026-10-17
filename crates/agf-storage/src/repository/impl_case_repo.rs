//! 由 `repository.rs` 拆分：`impl_CaseRepo`/`to_json` 等 2 项（纯搬移，逻辑不变）。
use super::*;

use crate::db::{TenantTransaction, map_sqlx_err};
use agf_core::enums::{CaseState, Severity};
use agf_core::error::{DomainError, DomainResult};
use agf_core::ids::Id;
use agf_core::time::Timestamp;

impl CaseRepo {
    /// 新建案件（自动编号）。
    ///
    /// # Errors
    /// SQL 执行失败。
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        tx: &mut TenantTransaction<'_>,
        title: &str,
        summary: &str,
        severity: Severity,
        alert_ids: &[Id],
        finding_ids: &[Id],
        asset_ids: &[Id],
        owner: Option<&str>,
    ) -> DomainResult<(Id, String)> {
        let code = Self::next_code(tx).await?;
        let id = Id::new();
        let sla = Timestamp::now().offset_secs(agf_core::alert::Alert::sla_secs(severity));
        sqlx::query(
            r"INSERT INTO cases (id, tenant_id, code, title, summary, severity, state, alert_ids, finding_ids,
                asset_ids, owner, sla_due_at, created_at, updated_at)
               VALUES ($1,$2,$3,$4,$5,$6,'new',$7,$8,$9,$10,$11,now(),now())",
        )
        .bind(id.as_uuid())
        .bind(tx.tenant().as_uuid())
        .bind(&code)
        .bind(title)
        .bind(summary)
        .bind(severity.as_str())
        .bind(
            serde_json::to_value(alert_ids.iter().map(ToString::to_string).collect::<Vec<_>>())
                .unwrap_or(serde_json::Value::Null),
        )
        .bind(
            serde_json::to_value(finding_ids.iter().map(ToString::to_string).collect::<Vec<_>>())
                .unwrap_or(serde_json::Value::Null),
        )
        .bind(
            serde_json::to_value(asset_ids.iter().map(ToString::to_string).collect::<Vec<_>>())
                .unwrap_or(serde_json::Value::Null),
        )
        .bind(owner)
        .bind(sla.as_datetime())
        .execute(&mut **tx)
        .await
        .map_err(|e| map_sqlx_err("insert_case", &e))?;
        Ok((id, code))
    }

    /// 追加案件时间线事件。
    ///
    /// # Errors
    /// SQL 执行失败。
    pub async fn add_event(
        tx: &mut TenantTransaction<'_>,
        case_id: Id,
        kind: &str,
        actor: &str,
        note: &str,
        detail: serde_json::Value,
        automated: bool,
    ) -> DomainResult<()> {
        sqlx::query(
            "INSERT INTO case_events (id, tenant_id, case_id, kind, actor, note, detail, automated, at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now())",
        )
        .bind(Id::new().as_uuid())
        .bind(tx.tenant().as_uuid())
        .bind(case_id.as_uuid())
        .bind(kind)
        .bind(actor)
        .bind(note)
        .bind(detail)
        .bind(automated)
        .execute(&mut **tx)
        .await
        .map_err(|e| map_sqlx_err("insert_case_event", &e))?;
        Ok(())
    }

    /// 状态流转。
    ///
    /// # Errors
    /// 记录不存在或 SQL 失败。
    pub async fn set_state(
        tx: &mut TenantTransaction<'_>,
        id: Id,
        state: CaseState,
        resolution: Option<&str>,
    ) -> DomainResult<()> {
        let affected = sqlx::query(
            "UPDATE cases SET state = $1, resolution = COALESCE($2, resolution), \
             closed_at = CASE WHEN $1 = 'closed' THEN COALESCE(closed_at,now()) ELSE closed_at END, updated_at = now() WHERE id = $3",
        )
        .bind(state.as_str())
        .bind(resolution)
        .bind(id.as_uuid())
        .execute(&mut **tx)
        .await
        .map_err(|e| map_sqlx_err("set_case_state", &e))?
        .rows_affected();
        if affected == 0 {
            return Err(DomainError::NotFound { entity: "case", id: id.to_string() });
        }
        Ok(())
    }

    /// 列出案件。
    ///
    /// # Errors
    /// SQL 执行失败。
    pub async fn list(tx: &mut TenantTransaction<'_>, limit: i64) -> DomainResult<Vec<serde_json::Value>> {
        let rows = sqlx::query("SELECT * FROM cases ORDER BY created_at DESC LIMIT $1")
            .bind(limit)
            .fetch_all(&mut **tx)
            .await
            .map_err(|e| map_sqlx_err("list_cases", &e))?;
        Ok(rows.iter().map(row_to_json_object).collect())
    }

    /// 案件时间线。
    ///
    /// # Errors
    /// SQL 执行失败。
    pub async fn timeline(tx: &mut TenantTransaction<'_>, case_id: Id) -> DomainResult<Vec<serde_json::Value>> {
        let rows = sqlx::query("SELECT * FROM case_events WHERE case_id = $1 ORDER BY at ASC")
            .bind(case_id.as_uuid())
            .fetch_all(&mut **tx)
            .await
            .map_err(|e| map_sqlx_err("case_timeline", &e))?;
        Ok(rows.iter().map(row_to_json_object).collect())
    }
}

/// JSON 转换助手。
#[must_use]
pub fn to_json<T: serde::Serialize>(value: &T) -> serde_json::Value {
    serde_json::to_value(value).unwrap_or(serde_json::Value::Null)
}
