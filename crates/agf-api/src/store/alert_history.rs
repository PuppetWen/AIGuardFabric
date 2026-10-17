//! Complete alert history and atomic SLA/state updates for console, reports and workflows.
use super::*;
use agf_core::alert::Alert;
use agf_storage::AlertRepo;

impl ApiStore {
    pub async fn alert_list_durable(
        &self,
        tenant: TenantId,
        state: Option<AlertState>,
        severity: Option<Severity>,
    ) -> DomainResult<Vec<Alert>> {
        let Some(database) = &self.database else { return self.alert_list(tenant, state, severity) };
        database
            .with_tenant(tenant, move |tx| {
                Box::pin(async move {
                    let rows: Vec<serde_json::Value> = sqlx::query_scalar(
                        "SELECT to_jsonb(a) FROM alerts a WHERE deleted_at IS NULL
                 AND ($1::text IS NULL OR state=$1) AND ($2::text IS NULL OR severity=$2)
                 ORDER BY last_seen_at DESC, id ASC",
                    )
                    .bind(state.map(|s| s.as_str()))
                    .bind(severity.map(|s| s.as_str()))
                    .fetch_all(&mut **tx)
                    .await
                    .map_err(|e| agf_storage::map_sqlx_err("alert_history", &e))?;
                    rows.into_iter().map(serde_json::from_value).collect::<Result<Vec<Alert>, _>>().map_err(Into::into)
                })
            })
            .await
    }

    /// State/assignee and SLA are one transaction when an escalation changes both.
    #[allow(clippy::too_many_arguments)]
    pub async fn alert_set_sla_durable(
        &self,
        tenant: TenantId,
        id: Id,
        due_at: Option<Timestamp>,
        breached: bool,
        level: u8,
        escalation: Option<(AlertState, Option<String>)>,
    ) -> DomainResult<Alert> {
        let Some(database) = &self.database else {
            if let Some((state, assignee)) = escalation {
                self.alert_set_state(tenant, id, state, assignee)?;
            }
            return self.alert_set_sla(tenant, id, due_at, breached, level);
        };
        let alert = database
            .with_tenant(tenant, move |tx| {
                Box::pin(async move {
                    let (state, assignee) =
                        escalation.map_or((None, None), |(state, assignee)| (Some(state), assignee));
                    let affected = sqlx::query(
                        "UPDATE alerts SET sla_due_at=$2, sla_breached=$3, escalation_level=GREATEST(escalation_level,$4),
                 state=COALESCE($5,state), assignee=COALESCE($6,assignee), updated_at=now()
                 WHERE id=$1 AND deleted_at IS NULL",
                    )
                    .bind(id.as_uuid())
                    .bind(due_at.map(|t| t.as_datetime()))
                    .bind(breached)
                    .bind(i16::from(level))
                    .bind(state.map(|s| s.as_str()))
                    .bind(assignee)
                    .execute(&mut **tx)
                    .await
                    .map_err(|e| agf_storage::map_sqlx_err("alert_sla", &e))?
                    .rows_affected();
                    if affected == 0 {
                        return Err(DomainError::NotFound { entity: "alert", id: id.to_string() });
                    }
                    AlertRepo::get(tx, id)
                        .await?
                        .ok_or_else(|| DomainError::Internal("Updated alert is missing".into()))
                })
            })
            .await?;
        self.hydrate_alert(&alert)?;
        Ok(alert)
    }
}
