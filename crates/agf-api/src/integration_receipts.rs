//! Durable operation claims and encrypted receipts shared by vendor and cloud adapters.
use crate::{
    model_gateway::{cipher, encrypt},
    state::AppState,
};
use agf_core::{
    audit::AuditActor,
    credential::SecretMaterial,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    time::Timestamp,
};
use agf_storage::configuration::{ConditionalMutation, MutationDecision};
use agf_storage::crypto::FieldCipher;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, future::Future};
const RUNS: &str = "integration-operation";
const OPERATION_TIMEOUT_SECS: u64 = 120;
mod apig;
mod completion;
mod scheduler;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Run {
    pub id: Id,
    pub request_id: Id,
    pub adapter: String,
    pub operation: String,
    pub configuration_version: u64,
    pub request_hash: String,
    pub actor: String,
    pub started_at: Timestamp,
    pub finished_at: Option<Timestamp>,
    pub status: String,
    pub mocked: bool,
    pub result: Option<SecretMaterial>,
}
fn public(run: &Run) -> Value {
    serde_json::json!({"id":run.id,"request_id":run.request_id,"adapter":run.adapter,
        "operation":run.operation,"configuration_version":run.configuration_version,"actor":run.actor,
        "started_at":run.started_at,"finished_at":run.finished_at,"status":run.status,"mocked":run.mocked,
        "completion_state":if run.finished_at.is_some(){"complete"}else{"running"}})
}
fn response(state: &AppState, tenant: TenantId, run: &Run) -> DomainResult<Value> {
    let mut value = public(run);
    if let Some(result) = &run.result {
        if result.aad.as_deref() != Some(&FieldCipher::make_aad(&tenant, &run.id)) {
            return Err(DomainError::Crypto("集成回执租户绑定不匹配".into()));
        }
        let text = cipher(state)?.decrypt(result)?;
        let mut receipt = serde_json::from_str(text.expose_secret())?;
        scheduler::project(&run.adapter, &run.operation, &mut receipt)?;
        apig::project(&run.adapter, &mut receipt)?;
        value["receipt"] = receipt;
    }
    Ok(value)
}
pub async fn history(state: &AppState, tenant: TenantId, name: &str) -> DomainResult<Vec<Value>> {
    let mut runs = state.configurations.list::<Run>(tenant, RUNS).await?;
    runs.retain(|run| run.adapter == name);
    runs.sort_by_key(|run| std::cmp::Reverse(run.started_at));
    let mut items = Vec::new();
    for run in runs.iter().take(50) {
        let mut item = public(run);
        if run.finished_at.is_none() {
            if let Some(pending) = completion::pending(state, tenant, run).await? {
                completion::pending_metadata(&mut item, &pending);
            }
        }
        items.push(item);
    }
    Ok(items)
}
pub async fn get(state: &AppState, tenant: TenantId, name: &str, id: Id) -> DomainResult<Value> {
    let run = state
        .configurations
        .get::<Run>(tenant, RUNS, id)
        .await?
        .filter(|run| run.adapter == name)
        .ok_or_else(|| DomainError::NotFound { entity: "integration-operation", id: id.to_string() })?;
    if run.finished_at.is_none() {
        if let Some(pending) = completion::pending(state, tenant, &run).await? {
            let mut value = response(state, tenant, &pending.run)?;
            completion::pending_metadata(&mut value, &pending);
            return Ok(value);
        }
    }
    response(state, tenant, &run)
}
/// Publish an already encrypted completion and its audit; never invoke an adapter or cloud API.
pub async fn recover(state: &AppState, tenant: TenantId, name: &str, id: Id) -> DomainResult<Value> {
    let run = state
        .configurations
        .get::<Run>(tenant, RUNS, id)
        .await?
        .filter(|run| run.adapter == name)
        .ok_or_else(|| DomainError::NotFound { entity: "integration-operation", id: id.to_string() })?;
    if run.finished_at.is_some() {
        return response(state, tenant, &run);
    }
    let Some(pending) = completion::pending(state, tenant, &run).await? else {
        // Another instance can complete and clean its staging row between these reads.
        let current = state
            .configurations
            .get::<Run>(tenant, RUNS, id)
            .await?
            .filter(|current| current.adapter == name && current.request_hash == run.request_hash);
        if let Some(current) = current.filter(|current| current.finished_at.is_some()) {
            return response(state, tenant, &current);
        }
        return Err(DomainError::PreconditionFailed(
            "没有可本地恢复的已知回执；请求可能已送达，请核对远端状态，不能重新发送".into(),
        ));
    };
    let published = completion::resume(state.clone(), tenant, pending).await?;
    response(state, tenant, &published)
}

/// Explicit service identity for internal callers without an authenticated principal.
pub(crate) fn internal_actor(name: &str) -> AuditActor {
    AuditActor {
        id: None,
        kind: "service".into(),
        name: name.into(),
        source_ip: None,
        user_agent: None,
        session_id: None,
    }
}
pub async fn execute<F>(
    state: &AppState,
    tenant: TenantId,
    run: Run,
    secrets: &BTreeMap<String, String>,
    can_write: bool,
    future: F,
) -> DomainResult<Value>
where
    F: Future<Output = DomainResult<Value>>,
{
    Box::pin(execute_audited(state, tenant, run, secrets, can_write, internal_actor("integration-runtime"), future))
        .await
}

/// Execute a claimed operation with a trusted audit identity supplied by its runtime.
pub async fn execute_audited<F>(
    state: &AppState,
    tenant: TenantId,
    mut run: Run,
    secrets: &BTreeMap<String, String>,
    can_write: bool,
    audit_actor: AuditActor,
    future: F,
) -> DomainResult<Value>
where
    F: Future<Output = DomainResult<Value>>,
{
    let id = run.id;
    let mut claimed = false;
    let (prior, _) = state
        .configurations
        .mutate_conditional_audited::<Option<Run>, _, _>(
            tenant,
            ConditionalMutation { kind: RUNS, id, guard: None },
            |_, current| {
                if let Some(prior) = current {
                    completion::matches_claim(prior, &run)?;
                    return Ok(MutationDecision::Unchanged);
                }
                *current = Some(run.clone());
                claimed = true;
                Ok(MutationDecision::Write(None))
            },
            |_| Err(DomainError::Internal("集成领取不得追加终态审计".into())),
        )
        .await?;
    if !claimed {
        let prior = prior.ok_or_else(|| DomainError::Conflict("调用记录不存在".into()))?;
        if prior.finished_at.is_none() {
            if let Some(pending) = completion::pending(state, tenant, &prior).await? {
                let published = completion::resume(state.clone(), tenant, pending).await?;
                return response(state, tenant, &published);
            }
            return Err(DomainError::Conflict("请求正在执行或曾被中断；请核对远端状态，禁止盲目重试".into()));
        }
        return response(state, tenant, &prior);
    }
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(OPERATION_TIMEOUT_SECS), future).await;
    let mut receipt = match outcome {
        Ok(Ok(value)) => {
            run.status =
                if value.get("accepted") == Some(&Value::Bool(false)) || value["failed"].as_u64().unwrap_or(0) > 0 {
                    "failed"
                } else {
                    "succeeded"
                }
                .into();
            value
        }
        Ok(Err(error)) => {
            run.status = if can_write
                && matches!(
                    error,
                    DomainError::Timeout(_) | DomainError::DependencyUnavailable { .. } | DomainError::Parse(_)
                ) {
                "uncertain"
            } else {
                "failed"
            }
            .into();
            serde_json::json!({"error":error.to_string()})
        }
        Err(_) => {
            run.status = "uncertain".into();
            serde_json::json!({"error":"调用超时，远端可能已执行；请检查远端回执后再决定是否重试"})
        }
    };
    redact(&mut receipt, secrets);
    scheduler::project(&run.adapter, &run.operation, &mut receipt)?;
    apig::project(&run.adapter, &mut receipt)?;
    let result = serde_json::to_string(&receipt)?;
    if result.len() > 2 * 1024 * 1024 {
        run.status = "uncertain".into();
        receipt = serde_json::json!({"error":"远端回执超过 2 MiB；请缩小读取范围，写操作请先核对远端状态"});
    }
    run.finished_at = Some(Timestamp::now());
    run.result = Some(encrypt(state, tenant, id, serde_json::to_string(&receipt)?)?);
    let published = completion::finish(state.clone(), tenant, run, audit_actor).await?;
    response(state, tenant, &published)
}
pub(crate) fn redact(value: &mut Value, secrets: &BTreeMap<String, String>) {
    match value {
        Value::String(text) => {
            for secret in secrets.values().filter(|secret| !secret.is_empty()) {
                *text = text.replace(secret, "[REDACTED]");
            }
        }
        Value::Array(items) => {
            for item in items {
                redact(item, secrets);
            }
        }
        Value::Object(items) => {
            for item in items.values_mut() {
                redact(item, secrets);
            }
        }
        _ => {}
    }
}
