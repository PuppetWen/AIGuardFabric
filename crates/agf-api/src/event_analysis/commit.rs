//! Exactly-once database effects across redelivery, restarts and competing consumers.
use super::AnalysisResult;
use agf_core::{
    alert::Alert,
    enums::AssetKind,
    error::DomainResult,
    event::{Event, EventCategory},
    ids::Id,
    risk::Finding,
    time::Timestamp,
};
use agf_storage::{AlertRepo, FindingRepo, Store, map_sqlx_err};

/// Only fully scanned events with no findings and no active correlation rules reach this path.
/// No future placeholder receipts are made visible to temporal correlation processing.
pub(super) async fn save_empty_batch(
    store: &Store,
    events: &[Event],
    fingerprint: &str,
    registry_identity: serde_json::Value,
    check_deferred: bool,
) -> DomainResult<Option<Vec<AnalysisResult>>> {
    let Some(first) = events.first() else { return Ok(Some(Vec::new())) };
    let tenant = first.tenant_id;
    let ids: Vec<_> = events.iter().map(|e| e.id.as_uuid()).collect();
    let times: Vec<_> = events.iter().map(|e| e.time.as_datetime()).collect();
    let fingerprint = fingerprint.to_owned();
    store
        .with_tenant(tenant, move |tx| {
            Box::pin(async move {
                // A publication after input preparation forces the unchanged per-event path, without writes.
                // As with single-event analysis this does not freeze concurrent configuration publishers.
                if super::context::snapshot(tx, tenant).await?.identity()? != registry_identity {
                    return Ok(None);
                }
                if check_deferred {
                    let deferred: bool = sqlx::query_scalar(
                        "SELECT EXISTS(SELECT 1 FROM event_analysis_retries WHERE event_id=ANY($1)
                 AND resolved_at IS NULL AND (available_at>now() OR paused OR attempts>=8))",
                    )
                    .bind(&ids)
                    .fetch_one(&mut **tx)
                    .await
                    .map_err(|e| map_sqlx_err("analysis_batch_deferred", &e))?;
                    if deferred {
                        return Ok(None);
                    }
                }
                let inserted: Vec<uuid::Uuid> = sqlx::query_scalar(
                    "INSERT INTO event_analysis_receipts(tenant_id,event_id,event_time,rule_fingerprint,
                finding_ids,alert_ids,notification_enqueued_at)
             SELECT $1,i.id,i.time,$4,'[]'::jsonb,'[]'::jsonb,now()
             FROM UNNEST($2::uuid[],$3::timestamptz[]) i(id,time) ORDER BY i.id
             ON CONFLICT (tenant_id,event_id) DO NOTHING RETURNING event_id",
                )
                .bind(tenant.as_uuid())
                .bind(&ids)
                .bind(times)
                .bind(fingerprint)
                .fetch_all(&mut **tx)
                .await
                .map_err(|e| map_sqlx_err("analysis_batch_complete", &e))?;
                // Existing receipts keep the original path's retry behavior; only our newly completed IDs resolve.
                if !inserted.is_empty() {
                    sqlx::query(
                        "UPDATE event_analysis_retries SET resolved_at=now(),updated_at=now(),paused=false,
                version=version+1 WHERE event_id=ANY($1) AND resolved_at IS NULL",
                    )
                    .bind(&inserted)
                    .execute(&mut **tx)
                    .await
                    .map_err(|e| map_sqlx_err("analysis_batch_retry_complete", &e))?;
                }
                let inserted: std::collections::HashSet<_> = inserted.into_iter().collect();
                let conflicts: Vec<_> = ids.iter().copied().filter(|id| !inserted.contains(id)).collect();
                let mut saved = std::collections::HashMap::new();
                if !conflicts.is_empty() {
                    // A separate READ COMMITTED statement sees the winner after ON CONFLICT waits.
                    // A CTE SELECT in the INSERT's snapshot can miss that concurrently committed receipt.
                    let rows: Vec<(uuid::Uuid, serde_json::Value)> = sqlx::query_as(
                        "SELECT event_id,jsonb_build_object('duplicate',true,'finding_ids',finding_ids,
                    'alert_ids',alert_ids) FROM event_analysis_receipts WHERE event_id=ANY($1)",
                    )
                    .bind(conflicts)
                    .fetch_all(&mut **tx)
                    .await
                    .map_err(|e| map_sqlx_err("analysis_batch_conflicts", &e))?;
                    for (id, value) in rows {
                        saved.insert(id, serde_json::from_value(value)?);
                    }
                }
                ids.into_iter()
                    .map(|id| {
                        if inserted.contains(&id) {
                            Ok(AnalysisResult::default())
                        } else {
                            saved.remove(&id).ok_or_else(|| agf_core::error::DomainError::NotFound {
                                entity: "analysis-receipt",
                                id: id.to_string(),
                            })
                        }
                    })
                    .collect::<DomainResult<Vec<_>>>()
                    .map(Some)
            })
        })
        .await
}

pub(super) async fn save(
    store: &Store,
    event: &Event,
    fingerprint: &str,
    findings: &[Finding],
    correlations: &[crate::correlation::Revision],
) -> DomainResult<AnalysisResult> {
    let event = event.clone();
    let mut findings = findings.to_vec();
    let correlations = correlations.to_vec();
    let fingerprint = fingerprint.to_owned();
    store
        .with_tenant(event.tenant_id, move |tx| {
            Box::pin(async move {
                // 关联分析共享租户历史；串行提交保证新事件可读取前一个事件的规则命中。
                if !correlations.is_empty() {
                    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
                        .bind(format!("correlation:{}", event.tenant_id)).execute(&mut **tx).await
                        .map_err(|e| map_sqlx_err("correlation_lock", &e))?;
                }
                let inserted = sqlx::query(
                    "INSERT INTO event_analysis_receipts(tenant_id,event_id,event_time,rule_fingerprint)
            VALUES ($1,$2,$3,$4) ON CONFLICT (tenant_id,event_id) DO NOTHING",
                )
                .bind(event.tenant_id.as_uuid())
                .bind(event.id.as_uuid())
                .bind(event.time.as_datetime())
                .bind(fingerprint)
                .execute(&mut **tx)
                .await
                .map_err(|e| map_sqlx_err("analysis_claim", &e))?
                .rows_affected();
                if inserted == 0 {
                    let saved: serde_json::Value = sqlx::query_scalar(
                        "SELECT jsonb_build_object('duplicate',true,'finding_ids',finding_ids,'alert_ids',alert_ids)
                 FROM event_analysis_receipts WHERE event_id=$1",
                    )
                    .bind(event.id.as_uuid())
                    .fetch_one(&mut **tx)
                    .await
                    .map_err(|e| map_sqlx_err("analysis_receipt", &e))?;
                    return serde_json::from_value(saved).map_err(Into::into);
                }
                let correlated = crate::correlation::runtime::generate(tx, &event, &findings, &correlations).await?;
                findings.extend(correlated);
                let entities = agf_correlate::entity::EntityAligner::new().extract(&event);
                let scope = entities
                    .strongest()
                    .map(agf_correlate::entity::EntityRef::local_key)
                    .unwrap_or_else(|| event.source_id.to_string());
                let asset_ids = linked_assets(tx, &event).await?;
                let primary_asset = match event.category {
                    EventCategory::AiToolCall => [event.ai.mcp_server_id, event.ai.agent_id, event.ai.model_endpoint_id],
                    EventCategory::AiModel => [event.ai.model_endpoint_id, event.ai.agent_id, event.ai.mcp_server_id],
                    _ => [event.ai.agent_id, event.ai.mcp_server_id, event.ai.model_endpoint_id],
                }
                .into_iter()
                .flatten()
                .find(|id| asset_ids.contains(id));
                let mut result = AnalysisResult::default();
                for finding in &mut findings {
                    finding.asset_id = finding.asset_id.or(primary_asset);
                    FindingRepo::insert(tx, finding).await?;
                    result.finding_ids.push(finding.id);
                    let dedup = agf_core::secret::content_hash(&format!(
                        "{}:{}:{}:{}",
                        event.tenant_id,
                        scope,
                        finding.domain.as_str(),
                        if finding.rule_keys.is_empty() { finding.title.clone() } else { finding.rule_keys.join(",") }
                    ));
                    let (id, _) = AlertRepo::upsert_dedup(
                        tx,
                        &format!("event:{dedup}"),
                        &finding.title,
                        &finding.summary,
                        finding.severity,
                        Some(finding.domain),
                        &asset_ids,
                        &[finding.id],
                        Some(Timestamp::now().offset_secs(Alert::sla_secs(finding.severity))),
                    )
                    .await?;
                    attach_event(tx, id, &event).await?;
                    if finding.source_origin == "correlation-analysis" {
                        let ids = crate::correlation::runtime::evidence_ids(finding);
                        sqlx::query("UPDATE alerts SET event_ids=(SELECT jsonb_agg(DISTINCT value) FROM jsonb_array_elements(event_ids || $2::jsonb)) WHERE id=$1")
                            .bind(id.as_uuid()).bind(serde_json::to_value(ids)?).execute(&mut **tx).await
                            .map_err(|e| map_sqlx_err("correlation_alert_evidence", &e))?;
                    }
                    result.alert_ids.push(id);
                }
                result.alert_ids.sort();
                result.alert_ids.dedup();
                // Only the completed result can prove that this receipt needs no notification work.
                sqlx::query("UPDATE event_analysis_receipts SET finding_ids=$2,alert_ids=$3,
                    notification_enqueued_at=CASE WHEN $4 THEN now() ELSE NULL END WHERE event_id=$1")
                    .bind(event.id.as_uuid())
                    .bind(serde_json::to_value(&result.finding_ids)?)
                    .bind(serde_json::to_value(&result.alert_ids)?)
                    .bind(result.alert_ids.is_empty())
                    .execute(&mut **tx)
                    .await
                    .map_err(|e| map_sqlx_err("analysis_complete", &e))?;
                sqlx::query("UPDATE event_analysis_retries SET resolved_at=now(),updated_at=now(),paused=false,version=version+1 WHERE event_id=$1 AND resolved_at IS NULL")
                    .bind(event.id.as_uuid())
                    .execute(&mut **tx)
                    .await
                    .map_err(|e| map_sqlx_err("analysis_retry_complete", &e))?;
                Ok(result)
            })
        })
        .await
}

/// Only an explicit AGF asset ID of the expected kind may link an event to an asset.
/// Host names and external host IDs are not unique enough to authorize response actions.
async fn linked_assets(tx: &mut agf_storage::TenantTransaction<'_>, event: &Event) -> DomainResult<Vec<Id>> {
    let candidates = [
        (event.ai.agent_id, AssetKind::Agent),
        (event.ai.mcp_server_id, AssetKind::McpServer),
        (event.ai.model_endpoint_id, AssetKind::ModelEndpoint),
    ];
    let mut ids = Vec::new();
    for (id, kind) in candidates {
        let Some(id) = id else { continue };
        let found: Option<uuid::Uuid> =
            sqlx::query_scalar("SELECT id FROM assets WHERE id=$1 AND tenant_id=$2 AND kind=$3 AND deleted_at IS NULL")
                .bind(id.as_uuid())
                .bind(event.tenant_id.as_uuid())
                .bind(kind.as_str())
                .fetch_optional(&mut **tx)
                .await
                .map_err(|error| map_sqlx_err("analysis_asset_link", &error))?;
        if found.is_some() {
            ids.push(id);
        }
    }
    ids.sort();
    ids.dedup();
    Ok(ids)
}

async fn attach_event(tx: &mut agf_storage::TenantTransaction<'_>, id: Id, event: &Event) -> DomainResult<()> {
    sqlx::query("UPDATE alerts SET
        event_ids=CASE WHEN event_ids @> $2::jsonb THEN event_ids ELSE event_ids || $2::jsonb END,
        affected_hosts=CASE WHEN $3::jsonb='[]'::jsonb OR affected_hosts @> $3::jsonb THEN affected_hosts ELSE affected_hosts || $3::jsonb END
        WHERE id=$1")
        .bind(id.as_uuid()).bind(serde_json::json!([event.id]))
        .bind(serde_json::to_value(event.host.name.iter().collect::<Vec<_>>())?)
        .execute(&mut **tx).await.map_err(|e| map_sqlx_err("analysis_evidence", &e))?;
    Ok(())
}
