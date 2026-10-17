//! 从租户 SQL 事件窗口重建关联状态，规则证据与自动告警共用一个数据库事务。
use super::{Definition, Event, Revision, evaluate, group};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, deterministic_id},
    risk::{Evidence, Finding},
};
use agf_storage::{FindingRepo, TenantTransaction, map_sqlx_err};

pub async fn generate(
    tx: &mut TenantTransaction<'_>,
    event: &Event,
    basic: &[Finding],
    rules: &[Revision],
) -> DomainResult<Vec<Finding>> {
    let mut current = event.clone();
    current.ai.rule_keys.extend(basic.iter().flat_map(|f| f.rule_keys.iter().cloned()));
    current.ai.rule_keys.sort();
    current.ai.rule_keys.dedup();
    let mut output = Vec::new();
    for revision in rules {
        let definition = &revision.definition;
        if !definition.event_filter.matches(&current) || group(definition, current.tenant_id, &current).is_none() {
            continue;
        }
        let mut events = history(tx, &current, definition).await?;
        events.retain(|e| e.id != current.id);
        events.push(current.clone());
        if let Some(hit) = evaluate::run(definition, current.tenant_id, &events, current.id) {
            let mut ids = hit.event_ids.clone();
            ids.sort();
            ids.dedup();
            let identity = serde_json::to_string(&(current.tenant_id, &definition.rule, revision.version, &ids))?;
            let id = deterministic_id("agf.correlation-finding", &identity);
            if FindingRepo::get(tx, id).await?.is_some() {
                continue;
            }
            let mut finding = Finding::new(
                current.tenant_id,
                definition.domain,
                definition.rule.severity(),
                format!("event:{}:{}", current.tenant_id, current.id),
                name(definition),
                &hit.summary,
                "Review the source event evidence and correlated entity path before applying a response playbook.",
            );
            finding.id = id;
            finding.source_origin = "correlation-analysis".into();
            finding.category = definition.rule.shape().into();
            finding.rule_keys = vec![definition.rule.key().into()];
            finding.confidence = hit.confidence;
            finding.first_seen_at =
                events.iter().filter(|e| ids.contains(&e.id)).map(|e| e.time).min().unwrap_or(event.time);
            finding.last_seen_at =
                events.iter().filter(|e| ids.contains(&e.id)).map(|e| e.time).max().unwrap_or(event.time);
            let details = serde_json::to_string(&hit.details)?;
            finding.chain = Some(details.clone());
            if definition.rule.shape() == "baseline" {
                finding.baseline = Some(details);
            }
            let snapshot = serde_json::to_string(&serde_json::json!({"rule":definition.rule,
                "version":revision.version,"group_by":definition.group_by,"window_secs":definition.window_secs,
                "event_filter":definition.event_filter,"slot_by_time":definition.slot_by_time}))?;
            finding.description = snapshot.clone();
            let rule_evidence =
                Evidence::new("CORRELATION-RULE", "rule", &hit.summary, agf_core::secret::content_hash(&snapshot));
            finding.evidence.push(rule_evidence);
            for (index, id) in ids.iter().enumerate() {
                if let Some(event) = events.iter().find(|e| e.id == *id) {
                    let mut evidence = Evidence::new(
                        format!("EVENT-{index}"),
                        "event",
                        "Correlated normalized event",
                        &event.raw_hash,
                    );
                    evidence.artifact_ref = Some(format!("event:{}:{}", event.tenant_id, id));
                    evidence.collected_at = event.ingested_at;
                    finding.evidence.push(evidence);
                }
            }
            finding.evidence_refs = finding.evidence.iter().map(|e| e.code.clone()).collect();
            output.push(finding);
        }
    }
    Ok(output)
}

async fn history(tx: &mut TenantTransaction<'_>, current: &Event, definition: &Definition) -> DomainResult<Vec<Event>> {
    let source =
        matches!(definition.group_by, agf_correlate::temporal::GroupBy::Source).then_some(current.source_id.as_uuid());
    let session = matches!(definition.group_by, agf_correlate::temporal::GroupBy::Session)
        .then(|| current.ai.session_id.clone())
        .flatten();
    let rows: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT jsonb_set(to_jsonb(e)-'raw'-'message'-'extra','{ai,rule_keys}',
        COALESCE(e.ai->'rule_keys','[]'::jsonb)||COALESCE((SELECT jsonb_agg(DISTINCT k.value)
        FROM event_analysis_receipts r CROSS JOIN LATERAL jsonb_array_elements_text(r.finding_ids) ids(value)
        JOIN findings f ON f.id=ids.value::uuid CROSS JOIN LATERAL jsonb_array_elements_text(f.rule_keys) k(value)
        WHERE r.event_id=e.id),'[]'::jsonb)) FROM events e
        WHERE time >= $1 AND time <= $2 AND ($3::uuid IS NULL OR source_id=$3)
        AND ($4::text IS NULL OR ai->>'session_id'=$4) ORDER BY time,ingested_at,id LIMIT 10001",
    )
    .bind(current.time.offset_secs(-definition.window_secs).as_datetime())
    .bind(current.time.offset_secs(definition.window_secs).as_datetime())
    .bind(source)
    .bind(session)
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| map_sqlx_err("correlation_window", &e))?;
    if rows.len() > 10_000 {
        return Err(DomainError::PreconditionFailed(format!(
            "Correlation rule {} exceeds 10000 events in its window; narrow its source/session scope or window before retrying",
            definition.rule.key()
        )));
    }
    rows.into_iter().map(serde_json::from_value).collect::<Result<_, _>>().map_err(Into::into)
}

fn name(definition: &Definition) -> &str {
    use agf_correlate::temporal::CorrelationRule;
    match &definition.rule {
        CorrelationRule::Match { name, .. } => name,
        CorrelationRule::Temporal(rule) => &rule.name,
        CorrelationRule::Graph(rule) => &rule.name,
        CorrelationRule::Baseline(rule) => &rule.name,
    }
}

/// 从结构化事件证据提取告警事件清单，包含链的历史事件。
pub fn evidence_ids(finding: &Finding) -> Vec<Id> {
    finding
        .evidence
        .iter()
        .filter_map(|e| e.artifact_ref.as_deref())
        .filter_map(|reference| reference.strip_prefix(&format!("event:{}:", finding.tenant_id)))
        .filter_map(|id| id.parse().ok())
        .collect()
}
