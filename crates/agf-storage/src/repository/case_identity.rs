//! Stable case/event identities and serialized tenant case numbering.
use super::CaseRepo;
use crate::{TenantTransaction, map_sqlx_err};
use agf_core::{
    case::{Case, CaseEvent},
    error::{DomainError, DomainResult},
    ids::Id,
};

impl CaseRepo {
    pub(super) async fn next_code(tx: &mut TenantTransaction<'_>) -> DomainResult<String> {
        Self::lock_numbering(tx).await?;
        let year = chrono::Datelike::year(&chrono::Utc::now());
        let pattern = format!("^CASE-{year}-([0-9]+)$");
        let seq: i64 = sqlx::query_scalar(
            "SELECT COALESCE(max((substring(code from $1))::bigint),0)+1 FROM cases WHERE code ~ $1",
        )
        .bind(pattern)
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| map_sqlx_err("case_sequence", &e))?;
        let seq = u32::try_from(seq).map_err(|_| DomainError::Config("Case numbering exhausted".into()))?;
        Ok(Case::make_code(year, seq))
    }

    async fn lock_numbering(tx: &mut TenantTransaction<'_>) -> DomainResult<()> {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!("case-numbering:{}", tx.tenant()))
            .execute(&mut **tx)
            .await
            .map_err(|e| map_sqlx_err("case_number_lock", &e))?;
        Ok(())
    }

    /// Read a tenant-owned case, optionally locking it for an atomic state transition.
    pub async fn get(tx: &mut TenantTransaction<'_>, id: Id, lock: bool) -> DomainResult<Option<Case>> {
        let sql = if lock {
            "SELECT to_jsonb(c) FROM cases c WHERE id=$1 FOR UPDATE"
        } else {
            "SELECT to_jsonb(c) FROM cases c WHERE id=$1"
        };
        let value: Option<serde_json::Value> = sqlx::query_scalar(sql)
            .bind(id.as_uuid())
            .fetch_optional(&mut **tx)
            .await
            .map_err(|e| map_sqlx_err("case_get", &e))?;
        value.map(serde_json::from_value).transpose().map_err(Into::into)
    }

    /// Legacy write queues and fixture import must retain the ID already returned to the caller.
    /// Existing records are never overwritten by a replayed creation intent.
    pub async fn insert_identity(tx: &mut TenantTransaction<'_>, case: &Case) -> DomainResult<Case> {
        if case.tenant_id != tx.tenant() {
            return Err(DomainError::Forbidden("Case tenant mismatch".into()));
        }
        Self::lock_numbering(tx).await?;
        if let Some(saved) = Self::get(tx, case.id, false).await? {
            return Ok(saved);
        }
        let mut case = case.clone();
        let occupied: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM cases WHERE code=$1)")
            .bind(&case.code)
            .fetch_one(&mut **tx)
            .await
            .map_err(|e| map_sqlx_err("case_code", &e))?;
        if occupied {
            case.code = Self::next_code(tx).await?;
        }
        sqlx::query(
            "INSERT INTO cases SELECT (jsonb_populate_record(NULL::cases,$1::jsonb)).* ON CONFLICT (id) DO NOTHING",
        )
        .bind(serde_json::to_value(&case)?)
        .execute(&mut **tx)
        .await
        .map_err(|e| map_sqlx_err("case_insert_identity", &e))?;
        let saved = Self::get(tx, case.id, false)
            .await?
            .ok_or_else(|| DomainError::Conflict("Case identity already belongs to another record".into()))?;
        Self::link_alerts(tx, &saved).await?;
        Ok(saved)
    }

    /// Enforce bidirectional ownership without silently moving an alert out of another case.
    pub async fn link_alerts(tx: &mut TenantTransaction<'_>, case: &Case) -> DomainResult<()> {
        let mut ids: Vec<_> = case.alert_ids.iter().map(Id::as_uuid).collect();
        ids.sort();
        ids.dedup();
        if ids.is_empty() {
            return Ok(());
        }
        let changed = sqlx::query(
            "UPDATE alerts SET case_id=$1,updated_at=now() WHERE id=ANY($2)
            AND (case_id IS NULL OR case_id=$1)",
        )
        .bind(case.id.as_uuid())
        .bind(&ids)
        .execute(&mut **tx)
        .await
        .map_err(|e| map_sqlx_err("case_alert_link", &e))?
        .rows_affected();
        if changed != ids.len() as u64 {
            return Err(DomainError::Conflict("An alert is missing or already belongs to another case".into()));
        }
        Ok(())
    }

    /// Append exactly the supplied timeline identity, idempotently within the owning tenant.
    pub async fn insert_event(tx: &mut TenantTransaction<'_>, event: &CaseEvent) -> DomainResult<()> {
        if event.tenant_id != tx.tenant() || Self::get(tx, event.case_id, false).await?.is_none() {
            return Err(DomainError::NotFound { entity: "case", id: event.case_id.to_string() });
        }
        sqlx::query(
            "INSERT INTO case_events (id,tenant_id,case_id,kind,actor,note,detail,automated,at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (id) DO NOTHING",
        )
        .bind(event.id.as_uuid())
        .bind(event.tenant_id.as_uuid())
        .bind(event.case_id.as_uuid())
        .bind(event.kind.as_str())
        .bind(&event.actor)
        .bind(&event.note)
        .bind(&event.detail)
        .bind(event.automated)
        .bind(event.at.as_datetime())
        .execute(&mut **tx)
        .await
        .map_err(|e| map_sqlx_err("case_event_identity", &e))?;
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM case_events WHERE id=$1 AND case_id=$2)")
            .bind(event.id.as_uuid())
            .bind(event.case_id.as_uuid())
            .fetch_one(&mut **tx)
            .await
            .map_err(|e| map_sqlx_err("case_event_owner", &e))?;
        if !exists {
            return Err(DomainError::Conflict("Timeline identity belongs to another record".into()));
        }
        Ok(())
    }
}
