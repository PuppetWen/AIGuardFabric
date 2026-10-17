//! Due tiers are enqueued with their immutable receipt and alert state in one SQL transaction.
use super::*;
use agf_core::{alert::Alert, enums::AlertState};
use agf_storage::{TenantTransaction, map_sqlx_err};
use serde_json::{Value, json};

pub(crate) const HEALTH: &str = "alert-escalation-health";

async fn authority(state: &AppState, tenant: TenantId, config: &Configuration) -> DomainResult<()> {
    if config.mock_mode != state.config.mock_mode {
        return Err(DomainError::PreconditionFailed("运行模式已变化，请重新检查并保存升级配置".into()));
    }
    let actor = config.publisher.as_ref().ok_or_else(|| DomainError::Forbidden("升级配置缺少发布者".into()))?;
    let principal = actor.resolve_for(state, tenant, "alerts", "write").await.map_err(|error| match error {
        DomainError::Forbidden(_) | DomainError::Unauthenticated(_) => {
            DomainError::Forbidden("升级策略发布者已停用或失去权限，请有权人员重新发布".into())
        }
        other => other,
    })?;
    if !can_write(state, &principal) {
        return Err(DomainError::Forbidden("升级策略发布者不再具备管理权限".into()));
    }
    Ok(())
}

async fn lock_policy(tx: &mut TenantTransaction<'_>, version: u64) -> DomainResult<Option<Configuration>> {
    let tenant = tx.tenant();
    let key = id(tenant);
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("{tenant}:{KIND}:{key}"))
        .execute(&mut **tx)
        .await
        .map_err(|e| map_sqlx_err("lock_escalation_policy", &e))?;
    let value: Option<Value> =
        sqlx::query_scalar("SELECT payload FROM console_configurations WHERE kind=$1 AND id=$2 AND deleted_at IS NULL")
            .bind(KIND)
            .bind(key.as_uuid())
            .fetch_optional(&mut **tx)
            .await
            .map_err(|e| map_sqlx_err("read_escalation_policy", &e))?;
    let config: Option<Configuration> = value.map(serde_json::from_value).transpose()?;
    Ok(config.filter(|c| c.version == version))
}

async fn enqueue_due(
    state: &AppState,
    tenant: TenantId,
    config: &Configuration,
    policy: &Policy,
    tier: &Tier,
    alert_id: Id,
    now: Timestamp,
) -> DomainResult<bool> {
    let database =
        state.store.database().ok_or_else(|| DomainError::PreconditionFailed("自动升级需要数据库".into()))?;
    authority(state, tenant, config).await?;
    let all = channels(state, tenant).await?;
    let mut tx = database.db().begin_tenant(tenant).await?;
    sqlx::query("SET LOCAL lock_timeout = '2000ms'")
        .execute(&mut *tx)
        .await
        .map_err(|e| map_sqlx_err("escalation_lock_timeout", &e))?;
    let Some(current) = lock_policy(&mut tx, config.version).await? else { return Ok(false) };
    let row: Option<Value> =
        sqlx::query_scalar("SELECT to_jsonb(a) FROM alerts a WHERE id=$1 AND deleted_at IS NULL FOR UPDATE")
            .bind(alert_id.as_uuid())
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| map_sqlx_err("lock_escalation_alert", &e))?;
    let Some(row) = row else { return Ok(false) };
    let alert: Alert = serde_json::from_value(row)?;
    let due = alert.first_seen_at.offset_secs(i64::from(policy.route.response_minutes) * 60);
    if !matches!(alert.state, AlertState::Open | AlertState::Escalated)
        || alert.severity != policy.route.severity
        || policy.since.is_some_and(|since| alert.first_seen_at < since)
        || now < due.offset_secs(i64::from(tier.overdue_minutes) * 60)
    {
        return Ok(false);
    }
    let done: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM alert_escalation_receipts WHERE alert_id=$1 AND tier=$2)")
            .bind(alert_id.as_uuid())
            .bind(i16::from(tier.level))
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| map_sqlx_err("check_escalation_receipt", &e))?;
    if done {
        return Ok(false);
    }
    let selected: Vec<_> = all
        .into_iter()
        .filter(|row| tier.channels.contains(&row.channel) && row.enabled && alert.severity >= row.min_severity)
        .collect();
    if selected.len() != tier.channels.len() || selected.is_empty() {
        return Err(DomainError::PreconditionFailed("升级渠道已停用、删除或等级不匹配；修复渠道后系统会重试".into()));
    }
    let subject = format!("alert-escalation:{}:{}", config.version, tier.level);
    let title = format!("[L{}] {}", tier.level, alert.title);
    let body = format!(
        "Alert: {}\nResponse target: {} minutes\nEscalation role: {}\n{}",
        alert.id,
        policy.route.response_minutes,
        tier.target.as_str(),
        alert.description.chars().take(3_000).collect::<String>()
    );
    let notifications = crate::notification_outbox::enqueue_transaction(
        state,
        &mut tx,
        selected,
        crate::notification_outbox::EnqueueMessage {
            subject: &subject,
            id: alert.id,
            title: &title,
            body: &body,
            severity: alert.severity,
        },
    )
    .await?;
    sqlx::query(
        "UPDATE alerts SET state='escalated',escalation_level=GREATEST(escalation_level,$2),
        sla_due_at=$3,sla_breached=true,updated_at=now() WHERE id=$1",
    )
    .bind(alert.id.as_uuid())
    .bind(i16::from(tier.level))
    .bind(due.as_datetime())
    .execute(&mut *tx)
    .await
    .map_err(|e| map_sqlx_err("update_escalated_alert", &e))?;
    sqlx::query("INSERT INTO alert_escalation_receipts(tenant_id,alert_id,policy_version,tier,severity,enqueued_at,actor,notification_ids)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(tenant.as_uuid()).bind(alert.id.as_uuid()).bind(i64::try_from(config.version).map_err(|e|DomainError::Internal(e.to_string()))?)
        .bind(i16::from(tier.level)).bind(alert.severity.as_str()).bind(now.as_datetime())
        .bind(current.publisher.as_ref().map_or_else(String::new,Actor::display)).bind(serde_json::to_value(notifications)?)
        .execute(&mut *tx).await.map_err(|e|map_sqlx_err("save_escalation_receipt",&e))?;
    tx.commit().await?;
    Ok(true)
}

async fn refresh_due_dates(
    state: &AppState,
    tenant: TenantId,
    config: &Configuration,
    policy: &Policy,
    now: Timestamp,
) -> DomainResult<()> {
    let database =
        state.store.database().ok_or_else(|| DomainError::PreconditionFailed("自动升级需要数据库".into()))?;
    let mut tx = database.db().begin_tenant(tenant).await?;
    if lock_policy(&mut tx, config.version).await?.is_none() {
        return Ok(());
    }
    sqlx::query("UPDATE alerts SET sla_due_at=first_seen_at + $2::bigint * interval '1 second',
        sla_breached=(first_seen_at + $2::bigint * interval '1 second' <= $3)
        WHERE id IN (SELECT id FROM alerts WHERE severity=$1 AND deleted_at IS NULL AND state IN ('open','escalated')
            AND ($4::timestamptz IS NULL OR first_seen_at >= $4)
            AND (sla_due_at IS DISTINCT FROM first_seen_at + $2::bigint * interval '1 second'
                 OR sla_breached IS DISTINCT FROM (first_seen_at + $2::bigint * interval '1 second' <= $3)) ORDER BY first_seen_at,id LIMIT 200)
        AND severity=$1 AND deleted_at IS NULL AND state IN ('open','escalated')")
        .bind(policy.route.severity.as_str()).bind(i64::from(policy.route.response_minutes)*60).bind(now.as_datetime())
        .bind(policy.since.map(|since|since.as_datetime())).execute(&mut *tx).await.map_err(|e|map_sqlx_err("refresh_alert_response_sla",&e))?;
    tx.commit().await?;
    Ok(())
}

async fn tenant_tick(state: &AppState, tenant: TenantId, now: Timestamp) -> DomainResult<(usize, Vec<String>)> {
    let config = get(state, tenant).await?;
    if !config.policies.iter().any(|p| p.route.enabled) {
        return Ok((0, vec![]));
    }
    authority(state, tenant, &config).await?;
    let database =
        state.store.database().ok_or_else(|| DomainError::PreconditionFailed("自动升级需要数据库".into()))?;
    let mut enqueued = 0;
    let mut errors = Vec::new();
    for policy in config.policies.iter().filter(|p| p.route.enabled) {
        refresh_due_dates(state, tenant, &config, policy, now).await?;
        for tier in &policy.route.tiers {
            let cutoff = now.offset_secs(-i64::from(policy.route.response_minutes + tier.overdue_minutes) * 60);
            let mut tx = database.db().begin_tenant(tenant).await?;
            let ids: Vec<uuid::Uuid> = sqlx::query_scalar(
                "SELECT a.id FROM alerts a WHERE a.deleted_at IS NULL
                AND a.state IN ('open','escalated') AND a.severity=$1 AND a.first_seen_at <= $2
                AND ($3::timestamptz IS NULL OR a.first_seen_at >= $3)
                AND NOT EXISTS(SELECT 1 FROM alert_escalation_receipts r WHERE r.alert_id=a.id AND r.tier=$4)
                ORDER BY a.first_seen_at,a.id LIMIT 64",
            )
            .bind(policy.route.severity.as_str())
            .bind(cutoff.as_datetime())
            .bind(policy.since.map(|t| t.as_datetime()))
            .bind(i16::from(tier.level))
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| map_sqlx_err("due_escalations", &e))?;
            tx.commit().await?;
            for id in ids {
                match enqueue_due(state, tenant, &config, policy, tier, Id::from_uuid(id), now).await {
                    Ok(queued) => enqueued += usize::from(queued),
                    Err(error) => {
                        if errors.len() < 8 {
                            errors.push(error.to_string());
                        }
                        break;
                    }
                }
            }
        }
    }
    Ok((enqueued, errors))
}

/// Process bounded batches; one tenant's configuration failure does not block others.
pub async fn tick(state: &AppState, now: Timestamp) -> DomainResult<usize> {
    if !state.store.has_database() {
        return Ok(0);
    }
    let mut enqueued = 0;
    for tenant in crate::tenant_directory::list(state).await?.into_iter().filter(|t| t.enabled) {
        let result = tokio::time::timeout(std::time::Duration::from_secs(30), tenant_tick(state, tenant.id, now))
            .await
            .unwrap_or_else(|_| Err(DomainError::Timeout("升级检查超时，下一轮继续处理未完成层级".into())));
        let health = match result {
            Ok((count, errors)) => {
                enqueued += count;
                json!({"at":now,"enqueued":count,"error":if errors.is_empty() {None} else {Some(errors.join("; "))}})
            }
            Err(error) => json!({"at":now,"enqueued":null,"error":error.to_string()}),
        };
        if let Err(error) = state.configurations.put(tenant.id, HEALTH, id(tenant.id), &health).await {
            tracing::warn!(%error,tenant=%tenant.id,"could not persist escalation health");
        }
    }
    Ok(enqueued)
}
pub async fn run_loop(state: AppState) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        if let Err(error) = tick(&state, Timestamp::now()).await {
            tracing::warn!(%error,"alert escalation iteration failed");
        }
    }
}

/// Before delivery, stop queued escalation messages whose alert or policy was withdrawn.
pub(crate) async fn permit_delivery(
    state: &AppState,
    tenant: TenantId,
    alert_id: Id,
    level: u8,
    channel: ChannelKind,
) -> DomainResult<()> {
    let alert = state
        .store
        .alert_get_durable(tenant, alert_id)
        .await?
        .ok_or_else(|| DomainError::NotFound { entity: "alert", id: alert_id.to_string() })?;
    if !matches!(alert.state, AlertState::Open | AlertState::Escalated) {
        return Err(DomainError::PreconditionFailed("告警已确认、解决或抑制，停止未投递的自动升级通知".into()));
    }
    let config = get(state, tenant).await?;
    authority(state, tenant, &config).await?;
    let permitted = config.policies.iter().any(|p| {
        p.route.enabled
            && p.route.severity == alert.severity
            && p.route.tiers.iter().any(|t| t.level == level && t.channels.contains(&channel))
    });
    if !permitted {
        return Err(DomainError::PreconditionFailed("升级策略或渠道已停用，停止未投递的自动通知".into()));
    }
    Ok(())
}
