//! SQL storage of a campaign aggregate, protected by tenant RLS and a row lock.
use super::*;
use agf_storage::TenantTransaction;

pub(super) async fn read(tx: &mut TenantTransaction<'_>, id: Id) -> DomainResult<Option<CampaignRecord>> {
    let raw: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT record FROM redteam_campaigns WHERE id=$1 AND deleted_at IS NULL FOR UPDATE")
            .bind(id.as_uuid())
            .fetch_optional(&mut **tx)
            .await
            .map_err(|e| agf_storage::map_sqlx_err("campaign_read", &e))?;
    raw.map(serde_json::from_value).transpose().map_err(Into::into)
}

pub(super) async fn save(tx: &mut TenantTransaction<'_>, record: &CampaignRecord, insert: bool) -> DomainResult<()> {
    let c = &record.campaign;
    if insert {
        sqlx::query(
            "INSERT INTO redteam_campaigns(id,tenant_id,name,state,launched_by,ci_gate,total_cases,created_at,record,
                target_agent_ids,target_mcp_ids,case_keys,categories,tags,scheduled,cron)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",
        )
        .bind(c.id.as_uuid())
        .bind(c.tenant_id.as_uuid())
        .bind(&c.name)
        .bind(c.state.as_str())
        .bind(&c.launched_by)
        .bind(c.ci_gate)
        .bind(i64::from(c.total_cases))
        .bind(c.created_at.as_datetime())
        .bind(serde_json::to_value(record)?)
        .bind(serde_json::to_value(&c.target_agent_ids)?)
        .bind(serde_json::to_value(&c.target_mcp_ids)?)
        .bind(serde_json::to_value(&c.case_keys)?)
        .bind(serde_json::to_value(&c.categories)?)
        .bind(serde_json::to_value(&c.tags)?)
        .bind(c.scheduled)
        .bind(&c.cron)
        .execute(&mut **tx)
        .await
        .map_err(|e| agf_storage::map_sqlx_err("campaign_insert", &e))?;
    } else {
        sqlx::query(
            "UPDATE redteam_campaigns SET state=$2,executed_cases=$3,succeeded_cases=$4,started_at=$5,
            finished_at=$6,updated_at=now(),record=$7 WHERE id=$1 AND deleted_at IS NULL",
        )
        .bind(c.id.as_uuid())
        .bind(c.state.as_str())
        .bind(i64::from(c.executed_cases))
        .bind(i64::from(c.succeeded_cases))
        .bind(c.started_at.map(|t| t.as_datetime()))
        .bind(c.finished_at.map(|t| t.as_datetime()))
        .bind(serde_json::to_value(record)?)
        .execute(&mut **tx)
        .await
        .map_err(|e| agf_storage::map_sqlx_err("campaign_update", &e))?;
    }
    Ok(())
}

pub(super) fn missing(id: Id) -> DomainError {
    DomainError::NotFound { entity: "redteam-campaign", id: id.to_string() }
}
