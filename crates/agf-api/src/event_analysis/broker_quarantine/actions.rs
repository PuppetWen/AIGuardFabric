use super::*;

/// Expired manual attempts require review. Never automatically replay an uncertain attempt.
pub async fn recover_expired(state: &AppState) -> DomainResult<()> {
    database(state)?.with_tenant(TenantId::default_tenant(), |tx| Box::pin(async move {
        sqlx::query("WITH expired AS (UPDATE broker_quarantine SET state='quarantined',version=version+1,
            lease_id=NULL,lease_until=NULL,reason_code='retry_interrupted',updated_at=now()
            WHERE state='retrying' AND lease_until<now() RETURNING tenant_id,id,version)
            INSERT INTO broker_quarantine_actions(tenant_id,id,message_id,action,actor_id,note,previous_version)
            SELECT tenant_id,gen_random_uuid(),id,'interrupted','system','Retry lease expired; inspect before retry',version-1 FROM expired")
            .execute(&mut **tx).await.map_err(|e| agf_storage::map_sqlx_err("broker_retry_recovery", &e))?;
        Ok(())
    })).await
}

pub async fn act(
    state: &AppState,
    id: Id,
    version: i64,
    action: String,
    note: String,
    actor: String,
) -> DomainResult<Value> {
    let note = note.trim().to_owned();
    if !["retry", "dismiss"].contains(&action.as_str()) || version < 1 || note.is_empty() || note.len() > 1000 {
        return Err(DomainError::Validation(
            "Retry/dismiss requires a current version and a reason (1–1000 bytes)".into(),
        ));
    }
    let retry = action == "retry";
    let tenant = TenantId::default_tenant();
    let lease = Id::new();
    let result: Value = database(state)?.with_tenant(tenant, move |tx| Box::pin(async move {
        let current: Option<(i64,String)> = sqlx::query_as("SELECT version,state FROM broker_quarantine WHERE id=$1 FOR UPDATE")
            .bind(id.as_uuid()).fetch_optional(&mut **tx).await
            .map_err(|e| agf_storage::map_sqlx_err("broker_quarantine_lock", &e))?;
        let (current_version,current_state) = current.ok_or_else(|| not_found(id))?;
        if current_version!=version || current_state!="quarantined" {
            return Err(DomainError::Conflict("Message changed or is no longer quarantined; refresh before acting".into()));
        }
        let result: Value = sqlx::query_scalar("UPDATE broker_quarantine SET state=$2,version=version+1,updated_at=now(),
            lease_id=$3,lease_until=CASE WHEN $3::uuid IS NULL THEN NULL ELSE now()+interval '120 seconds' END
            WHERE id=$1 RETURNING to_jsonb(broker_quarantine)")
            .bind(id.as_uuid()).bind(if retry {"retrying"} else {"dismissed"})
            .bind(retry.then(|| lease.as_uuid())).fetch_one(&mut **tx).await
            .map_err(|e| agf_storage::map_sqlx_err("broker_quarantine_claim", &e))?;
        sqlx::query("INSERT INTO broker_quarantine_actions(tenant_id,id,message_id,action,actor_id,note,previous_version)
            VALUES ($1,$2,$3,$4,$5,$6,$7)")
            .bind(tenant.as_uuid()).bind(Id::new().as_uuid()).bind(id.as_uuid()).bind(action).bind(actor)
            .bind(note).bind(version).execute(&mut **tx).await
            .map_err(|e| agf_storage::map_sqlx_err("broker_quarantine_action", &e))?;
        Ok(result)
    })).await?;
    if !retry {
        return Ok(serde_json::json!({"id":id,"state":"dismissed","version":version+1}));
    }
    let attempted = attempt(state, id, result["sealed_envelope"].clone()).await;
    let (next, reason) = match attempted {
        Ok(Some(_)) => ("resolved", "analysis_completed"),
        Ok(None) => ("resolved", "sql_recovery_owns_retry"),
        Err(DomainError::Parse(_)) => ("quarantined", "invalid_payload"),
        Err(DomainError::NotFound { entity: "committed-event", .. }) => ("quarantined", "missing_event"),
        Err(DomainError::NotFound { entity: "tenant", .. }) => ("quarantined", "unknown_tenant"),
        Err(DomainError::Forbidden(_)) => ("quarantined", "routing_or_authorization"),
        Err(DomainError::Crypto(_)) => ("quarantined", "encryption"),
        Err(_) => ("quarantined", "dependency_or_analysis"),
    };
    database(state)?.with_tenant(tenant, move |tx| Box::pin(async move {
        let result: Value = sqlx::query_scalar("UPDATE broker_quarantine SET state=$3,reason_code=$4,
            version=version+1,updated_at=now(),lease_id=NULL,lease_until=NULL WHERE id=$1 AND lease_id=$2 AND state='retrying'
            RETURNING jsonb_build_object('id',id,'state',state,'version',version,'reason_code',reason_code)")
            .bind(id.as_uuid()).bind(lease.as_uuid()).bind(next).bind(reason).fetch_optional(&mut **tx).await
            .map_err(|e| agf_storage::map_sqlx_err("broker_quarantine_finish", &e))?
            .ok_or_else(|| DomainError::Conflict("Retry lease changed; inspect current message state".into()))?;
        sqlx::query("INSERT INTO broker_quarantine_actions(tenant_id,id,message_id,action,actor_id,note,previous_version)
            VALUES ($1,$2,$3,'retry_result','system',$4,$5)")
            .bind(tenant.as_uuid()).bind(Id::new().as_uuid()).bind(id.as_uuid()).bind(reason).bind(version+1)
            .execute(&mut **tx).await.map_err(|e| agf_storage::map_sqlx_err("broker_quarantine_result", &e))?;
        Ok(result)
    })).await
}

async fn attempt(state: &AppState, id: Id, sealed: Value) -> DomainResult<Option<super::super::AnalysisResult>> {
    let envelope = decrypt(state, id, sealed)?;
    let payload =
        STANDARD.decode(envelope.payload_b64).map_err(|_| DomainError::Crypto("Invalid evidence encoding".into()))?;
    // Replay only the original reference through canonical SQL lookup; no editable payload or tenant override.
    tokio::time::timeout(
        std::time::Duration::from_secs(45),
        super::super::process_or_defer_delivery(state, &envelope.prefix, &envelope.subject, &payload),
    )
    .await
    .map_err(|_| DomainError::Timeout("Broker retry deadline exceeded".into()))?
}
