//! Persistent notification queue. Database mutations claim work before any network I/O.
use crate::{
    model_gateway::{cipher, encrypt},
    notification_config::StoredChannel,
    state::AppState,
};
use agf_core::{
    credential::SecretMaterial,
    enums::Severity,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId, deterministic_id},
    notify::ChannelKind,
    time::Timestamp,
};
use agf_correlate::notify::OutboundMessage;
use agf_storage::crypto::FieldCipher;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

mod transaction;
mod worker;
pub(crate) use transaction::{EnqueueMessage, enqueue_transaction};
pub use worker::{attempt, run_loop, tick};

pub const KIND: &str = "notification-outbox";
const MAX_PENDING: usize = 1024;
const MAX_COMPLETED: usize = 4096;

#[derive(Default, Serialize, Deserialize)]
struct Queue {
    jobs: BTreeMap<Id, Job>,
    #[serde(default)]
    rate: BTreeMap<Id, Vec<i64>>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Job {
    id: Id,
    channel_id: Id,
    channel: ChannelKind,
    severity: Severity,
    payload: Option<SecretMaterial>,
    mocked: bool,
    attempts: u32,
    remaining_attempts: u32,
    expires_at: Timestamp,
    created_at: Timestamp,
    next_at: Timestamp,
    lease_token: Option<Id>,
    lease_until: Option<Timestamp>,
    completed_at: Option<Timestamp>,
    status: String,
    receipt: Option<Value>,
}

fn queue_id(tenant: TenantId) -> Id {
    deterministic_id("agf.notification-outbox", &tenant.to_string())
}

fn prune(queue: &mut Queue, now: Timestamp) {
    queue.jobs.retain(|_, row| row.completed_at.is_none_or(|at| at.offset_secs(30 * 86400) > now));
    let mut completed: Vec<_> = queue.jobs.values().filter_map(|row| row.completed_at.map(|at| (at, row.id))).collect();
    completed.sort_unstable();
    for (_, id) in completed.iter().take(completed.len().saturating_sub(MAX_COMPLETED)) {
        queue.jobs.remove(id);
    }
    queue.rate.retain(|_, values| {
        values.retain(|at| *at > now.unix_secs() - 60);
        !values.is_empty()
    });
}

/// Atomically persist all selected channels. A full queue rejects the operation rather than dropping messages.
pub async fn enqueue(
    state: &AppState,
    tenant: TenantId,
    rows: Vec<StoredChannel>,
    subject: &str,
    subject_id: Id,
    title: &str,
    body: &str,
    severity: Severity,
) -> DomainResult<Vec<Id>> {
    let now = Timestamp::now();
    let jobs = prepare_jobs(state, tenant, rows, subject, subject_id, title, body, severity)?;
    let ids = jobs.iter().map(|job| job.id).collect();
    state
        .configurations
        .mutate::<Queue, _>(tenant, KIND, queue_id(tenant), |queue| {
            insert_jobs(queue, jobs, now)?;
            Ok(())
        })
        .await?;
    Ok(ids)
}

fn prepare_jobs(
    state: &AppState,
    tenant: TenantId,
    rows: Vec<StoredChannel>,
    subject: &str,
    subject_id: Id,
    title: &str,
    body: &str,
    severity: Severity,
) -> DomainResult<Vec<Job>> {
    if title.len() > 2048 || body.len() > 16384 || subject.len() > 128 {
        return Err(DomainError::Validation("通知标题、正文或对象类型过长".into()));
    }
    let now = Timestamp::now();
    let mut jobs = Vec::new();
    for row in rows.into_iter().filter(|row| row.enabled && severity >= row.min_severity) {
        let dedup = format!("{tenant}:{}:{subject}:{subject_id}:{}", row.id, severity.as_str());
        let id = deterministic_id("agf.notification-job", &dedup);
        let message = OutboundMessage {
            tenant_id: tenant,
            channel_id: row.id,
            kind: row.channel,
            subject_kind: subject.into(),
            subject_id,
            dedup_key: id.to_string(),
            title: title.into(),
            body: body.into(),
            severity,
            targets: Vec::new(),
            at: now,
            extra: BTreeMap::new(),
        };
        jobs.push(Job {
            id,
            channel_id: row.id,
            channel: row.channel,
            severity,
            payload: Some(encrypt(state, tenant, id, serde_json::to_string(&message)?)?),
            mocked: state.config.mock_mode,
            attempts: 0,
            remaining_attempts: 8,
            expires_at: now.offset_secs(86400),
            created_at: now,
            next_at: now,
            lease_token: None,
            lease_until: None,
            completed_at: None,
            status: "pending".into(),
            receipt: None,
        });
    }
    Ok(jobs)
}

fn insert_jobs(queue: &mut Queue, jobs: Vec<Job>, now: Timestamp) -> DomainResult<()> {
    prune(queue, now);
    let added = jobs.iter().filter(|job| !queue.jobs.contains_key(&job.id)).count();
    if added + queue.jobs.values().filter(|job| job.completed_at.is_none()).count() > MAX_PENDING {
        return Err(DomainError::PreconditionFailed("通知队列已满，请先处理失败渠道或等待投递后重试".into()));
    }
    for job in jobs {
        queue.jobs.entry(job.id).or_insert(job);
    }
    Ok(())
}

fn decrypt(state: &AppState, tenant: TenantId, job: &Job) -> DomainResult<OutboundMessage> {
    let payload = job.payload.as_ref().ok_or_else(|| DomainError::Internal("通知正文缺失".into()))?;
    if payload.aad.as_deref() != Some(&FieldCipher::make_aad(&tenant, &job.id)) {
        return Err(DomainError::Crypto("通知租户绑定不匹配".into()));
    }
    let value: OutboundMessage = serde_json::from_str(cipher(state)?.decrypt(payload)?.expose_secret())?;
    if value.tenant_id != tenant || value.channel_id != job.channel_id || value.dedup_key != job.id.to_string() {
        return Err(DomainError::Crypto("通知消息绑定不匹配".into()));
    }
    Ok(value)
}

fn view(job: &Job) -> Value {
    let mut value = job.receipt.clone().unwrap_or_else(|| {
        json!({
            "channel_id":job.channel_id, "kind":job.channel, "outcome":"pending",
            "attempts":job.attempts, "receipt":null, "error":null,
            "mocked":job.mocked && job.channel != ChannelKind::InApp, "at":job.created_at,
        })
    });
    value["id"] = json!(job.id);
    value["status"] = json!(job.status);
    value["next_attempt_at"] = if job.completed_at.is_none() { json!(job.next_at) } else { Value::Null };
    value
}

/// Metadata only; neither message bodies nor channel credentials are exposed.
pub async fn history(state: &AppState, tenant: TenantId) -> DomainResult<Vec<Value>> {
    let queue: Queue = state.configurations.get(tenant, KIND, queue_id(tenant)).await?.unwrap_or_default();
    let mut rows: Vec<_> = queue.jobs.values().collect();
    rows.sort_by_key(|row| std::cmp::Reverse(row.created_at));
    Ok(rows.into_iter().map(view).collect())
}

/// Explicit operator retry uses the original idempotency key and preserves attempt history.
pub async fn retry(state: &AppState, tenant: TenantId, id: Id) -> DomainResult<Value> {
    let now = Timestamp::now();
    let queue = state
        .configurations
        .mutate::<Queue, _>(tenant, KIND, queue_id(tenant), |queue| {
            if queue.jobs.values().filter(|job| job.completed_at.is_none()).count() >= MAX_PENDING {
                return Err(DomainError::PreconditionFailed("通知队列已满".into()));
            }
            let job = queue
                .jobs
                .get_mut(&id)
                .ok_or_else(|| DomainError::NotFound { entity: "notification", id: id.to_string() })?;
            if job.lease_until.is_some_and(|at| at > now) || !matches!(job.status.as_str(), "failed" | "retrying") {
                return Err(DomainError::Conflict("通知正在投递、已经成功或已取消，不能重试".into()));
            }
            if job.payload.is_none() {
                return Err(DomainError::PreconditionFailed("通知正文已过保留期，请重新发起".into()));
            }
            job.remaining_attempts = 8;
            job.expires_at = now.offset_secs(86400);
            job.completed_at = None;
            job.next_at = now;
            job.status = "pending".into();
            job.lease_token = None;
            job.lease_until = None;
            Ok(())
        })
        .await?;
    queue.jobs.get(&id).map(view).ok_or_else(|| DomainError::Internal("通知任务缺失".into()))
}
