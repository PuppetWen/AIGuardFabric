//! SQL scan summaries and bounded state transitions. Submitted text is never stored here.
use super::*;
use agf_storage::TenantTransaction;

pub(super) const TIMEOUT_SECONDS: i64 = 120;
pub(super) const INTERRUPTED: &str = "Scan execution expired or was interrupted; submit a new task to retry.";

pub(super) fn expire(job: &mut ScanJob) {
    if !job.state.is_terminal() && Timestamp::now() >= job.created_at.offset_secs(TIMEOUT_SECONDS) {
        job.state = ScanJobState::Failed;
        job.error = Some(INTERRUPTED.into());
        job.finished_at = Some(Timestamp::now());
    }
}

pub(super) async fn read(tx: &mut TenantTransaction<'_>, id: Id) -> DomainResult<Option<ScanJob>> {
    let value: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT result FROM scan_jobs WHERE id=$1 AND deleted_at IS NULL FOR UPDATE")
            .bind(id.as_uuid())
            .fetch_optional(&mut **tx)
            .await
            .map_err(|e| agf_storage::map_sqlx_err("scan_read", &e))?;
    value.map(serde_json::from_value).transpose().map_err(Into::into)
}

pub(super) async fn save(tx: &mut TenantTransaction<'_>, job: &ScanJob, insert: bool) -> DomainResult<()> {
    let state = if job.state == ScanJobState::Succeeded { "completed" } else { job.state.as_str() };
    if insert {
        sqlx::query(
            "INSERT INTO scan_jobs(id,tenant_id,name,job_kind,state,total_targets,created_at,result)
            VALUES ($1,$2,$3,'content',$4,$5,$6,$7)",
        )
        .bind(job.id.as_uuid())
        .bind(job.tenant_id.as_uuid())
        .bind(&job.name)
        .bind(state)
        .bind(i32::try_from(job.targets).unwrap_or(i32::MAX))
        .bind(job.created_at.as_datetime())
        .bind(serde_json::to_value(job)?)
        .execute(&mut **tx)
        .await
        .map_err(|e| agf_storage::map_sqlx_err("scan_insert", &e))?;
    } else {
        sqlx::query(
            "UPDATE scan_jobs SET state=$2,progress=$3,findings_count=$4,error=$5,
            started_at=$6,finished_at=$7,updated_at=now(),result=$8,
            scanned_targets=CASE WHEN $2='completed' THEN total_targets ELSE 0 END WHERE id=$1 AND deleted_at IS NULL",
        )
        .bind(job.id.as_uuid())
        .bind(state)
        .bind(i16::from(job.progress))
        .bind(i32::try_from(job.finding_count).unwrap_or(i32::MAX))
        .bind(&job.error)
        .bind(job.started_at.map(|t| t.as_datetime()))
        .bind(job.finished_at.map(|t| t.as_datetime()))
        .bind(serde_json::to_value(job)?)
        .execute(&mut **tx)
        .await
        .map_err(|e| agf_storage::map_sqlx_err("scan_update", &e))?;
    }
    Ok(())
}

pub(super) fn missing(id: Id) -> DomainError {
    DomainError::NotFound { entity: "scan-job", id: id.to_string() }
}

pub(super) fn transition(job: &mut ScanJob, next: ScanJobState, error: Option<String>) -> DomainResult<()> {
    expire(job);
    if job.state.is_terminal() {
        return Ok(());
    }
    match (job.state, next) {
        (ScanJobState::Queued, ScanJobState::Running) => {
            job.started_at = Some(Timestamp::now());
            job.progress = 10;
        }
        (_, ScanJobState::Cancelled | ScanJobState::Failed) => {
            job.finished_at = Some(Timestamp::now());
            job.error = error;
        }
        _ => return Err(DomainError::Conflict("Invalid scan state transition".into())),
    }
    job.state = next;
    Ok(())
}
