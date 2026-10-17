use super::*;

pub async fn list(state: &AppState, filter: String, search: String, limit: i64, offset: i64) -> DomainResult<Value> {
    if !["all", "quarantined", "retrying", "resolved", "dismissed"].contains(&filter.as_str()) || search.len() > 128 {
        return Err(DomainError::Validation("Invalid broker queue filter or search longer than 128 bytes".into()));
    }
    database(state)?.with_tenant(TenantId::default_tenant(), move |tx| Box::pin(async move {
        sqlx::query_scalar("WITH filtered AS (
            SELECT id,stream,stream_sequence,payload_hash,payload_bytes,reason_code,state,version,created_at,updated_at
            FROM broker_quarantine WHERE ($1='all' OR state=$1)
            AND ($2='' OR position(lower($2) in lower(id::text || ' ' || payload_hash || ' ' || reason_code || ' ' || stream))>0)),
            selected AS (SELECT * FROM filtered ORDER BY updated_at DESC,id LIMIT $3 OFFSET $4)
            SELECT jsonb_build_object('items',COALESCE((SELECT jsonb_agg(to_jsonb(s) ORDER BY s.updated_at DESC,s.id) FROM selected s),'[]'::jsonb),
            'total',(SELECT count(*) FROM filtered))")
            .bind(filter).bind(search).bind(limit.clamp(1,200)).bind(offset.max(0))
            .fetch_one(&mut **tx).await.map_err(|e| agf_storage::map_sqlx_err("broker_quarantine_list", &e))
    })).await
}

/// Explicit admin evidence inspection; lists never include either plaintext or ciphertext.
pub async fn detail(state: &AppState, id: Id, actor: String) -> DomainResult<Value> {
    let tenant = TenantId::default_tenant();
    let row: Value = database(state)?.with_tenant(tenant, move |tx| Box::pin(async move {
        let row: Value = sqlx::query_scalar("SELECT to_jsonb(q) FROM broker_quarantine q WHERE id=$1")
            .bind(id.as_uuid()).fetch_optional(&mut **tx).await
            .map_err(|e| agf_storage::map_sqlx_err("broker_quarantine_evidence", &e))?.ok_or_else(|| not_found(id))?;
        sqlx::query("INSERT INTO broker_quarantine_actions(tenant_id,id,message_id,action,actor_id,note,previous_version)
            VALUES ($1,$2,$3,'inspect',$4,'Evidence opened',$5)")
            .bind(tenant.as_uuid()).bind(Id::new().as_uuid()).bind(id.as_uuid()).bind(actor)
            .bind(row["version"].as_i64().unwrap_or(1)).execute(&mut **tx).await
            .map_err(|e| agf_storage::map_sqlx_err("broker_quarantine_inspect", &e))?;
        Ok(row)
    })).await?;
    let envelope = decrypt(state, id, row["sealed_envelope"].clone())?;
    Ok(serde_json::json!({"id":id,"subject":envelope.subject,"prefix":envelope.prefix,
        "payload_b64":envelope.payload_b64,"payload_hash":row["payload_hash"],"payload_bytes":row["payload_bytes"]}))
}

pub async fn history(state: &AppState, id: Id, limit: i64, offset: i64) -> DomainResult<Value> {
    database(state)?.with_tenant(TenantId::default_tenant(), move |tx| Box::pin(async move {
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM broker_quarantine WHERE id=$1)")
            .bind(id.as_uuid()).fetch_one(&mut **tx).await
            .map_err(|e| agf_storage::map_sqlx_err("broker_quarantine_exists", &e))?;
        if !exists { return Err(not_found(id)); }
        sqlx::query_scalar("WITH selected AS (SELECT id,action,actor_id,note,previous_version,created_at
            FROM broker_quarantine_actions WHERE message_id=$1 ORDER BY created_at DESC,id LIMIT $2 OFFSET $3)
            SELECT jsonb_build_object('items',COALESCE((SELECT jsonb_agg(to_jsonb(s) ORDER BY s.created_at DESC,s.id) FROM selected s),'[]'::jsonb),
            'total',(SELECT count(*) FROM broker_quarantine_actions WHERE message_id=$1))")
            .bind(id.as_uuid()).bind(limit.clamp(1,200)).bind(offset.max(0)).fetch_one(&mut **tx).await
            .map_err(|e| agf_storage::map_sqlx_err("broker_quarantine_history", &e))
    })).await
}
