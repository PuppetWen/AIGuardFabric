//! 绑定 Agent 的进程准入和观察；请求不接受租户，持久审计不含原始命令。
use crate::{
    AppState, Principal,
    error::ApiResult,
    policy_store::{AccessLease, AuthorizedSubmission, PublicationAuthorization, authorize_publication},
    routes::ApiJson,
};
use agf_core::{
    audit::{AuditAction, AuditOutcome, AuditTarget},
    enums::{AssetKind, DataClass, InterceptPoint},
    error::{DomainError, DomainResult},
    policy::PolicyContext,
    process_hook::{ProcessMode, ProcessReceipt, ProcessRequest, launch_action_supported},
    rbac::SubjectKind,
    time::Timestamp,
};
use agf_runtime::audit::{InterceptionRecord, InterceptionVerdict};
use axum::{Json, Router, extract::State, http::HeaderMap, routing::post};
use serde_json::json;
use std::time::Duration;
mod publication;

const KIND: &str = "runtime-process-admission";
static READ: PublicationAuthorization =
    PublicationAuthorization { resource: "policies", action: "read", additional: &[] };
/// 绑定 Agent 的进程判定路由；只提交判定与审计，不远程执行系统命令。
pub fn router() -> Router<AppState> {
    Router::new().route("/runtime/process/check", post(check))
}
struct Submission {
    principal: Principal,
    lease: Option<AccessLease>,
    at: Timestamp,
    deadline: tokio::time::Instant,
}
impl Submission {
    fn borrowed(&self) -> AuthorizedSubmission<'_> {
        AuthorizedSubmission {
            principal: &self.principal,
            lease: self.lease.as_ref(),
            submitted_at: self.at,
            authorization: &READ,
        }
    }
    async fn current(&self, state: &AppState) -> DomainResult<Principal> {
        self.budget()?;
        let current = authorize_publication(state, &self.borrowed()).await?;
        if current.subject_kind != SubjectKind::ApiKey
            || current.agent_id != self.principal.agent_id
            || current.tenant != self.principal.tenant
        {
            return Err(DomainError::Forbidden("Process admission identity changed".into()));
        }
        self.budget()?;
        Ok(current)
    }
    fn budget(&self) -> DomainResult<()> {
        if tokio::time::Instant::now() >= self.deadline {
            return Err(DomainError::Timeout("Original process admission deadline expired".into()));
        }
        Ok(())
    }
}
async fn check(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    ApiJson(body): ApiJson<ProcessRequest>,
) -> ApiResult<Json<ProcessReceipt>> {
    principal.require(&state, "policies", "read")?;
    if principal.subject_kind != SubjectKind::ApiKey || principal.agent_id != Some(body.agent_id) {
        return Err(DomainError::Forbidden("A bound Agent API Key is required for process policy".into()).into());
    }
    let submission = Submission {
        lease: AccessLease::capture(&state, &principal, &headers)?,
        principal,
        at: Timestamp::now(),
        deadline: tokio::time::Instant::now() + Duration::from_secs(3),
    };
    tokio::time::timeout_at(submission.deadline, execute(&state, &submission, body))
        .await
        .map_err(|_| DomainError::Timeout("Process policy/audit deadline expired; no launch authorized".into()))?
        .map(Json)
        .map_err(Into::into)
}
async fn execute(state: &AppState, submission: &Submission, body: ProcessRequest) -> DomainResult<ProcessReceipt> {
    let path = body.validate()?;
    let digest = body.digest()?;
    let current = submission.current(state).await?;
    let asset = state
        .store
        .asset_get_durable(current.tenant, body.agent_id)
        .await?
        .filter(|a| a.kind == AssetKind::Agent && a.deleted_at.is_none())
        .ok_or_else(|| DomainError::Forbidden("Bound Agent no longer exists".into()))?;
    let path_utf8 = std::str::from_utf8(&path).ok();
    let command = path_utf8.map(|p| format!("{p} {}", body.arguments.join(" ")));
    let engine = state.runtime_registry.get(state, current.tenant).await?;
    let decision=engine.evaluate(PolicyContext{tenant_id:current.tenant,session_id:body.request_id.to_string(),
        agent_id:Some(body.agent_id),department:asset.department.clone(),intercept_point:InterceptPoint::ProcessHook,
        tool_name:Some("process_exec".into()),path:path_utf8.map(str::to_owned),domain:None,command,
        payload:json!({"mode":body.mode,"source":body.source,"executable":path_utf8,"arguments":body.arguments,
            "arguments_available":body.mode==ProcessMode::Launch,"pid":body.pid,"truncated":body.truncated,"lost":body.lost}),
        payload_bytes:serde_json::to_vec(&body)?.len() as u64,risk_domains:Vec::new(),max_severity:None,
        data_class:std::cmp::max(asset.data_class,DataClass::Internal),now:Timestamp::now()}).await?;
    let allowed =
        body.mode == ProcessMode::Launch && launch_action_supported(decision.action, decision.dry_run, decision.redact);
    let summary = json!({"request_sha256":digest,"executable_sha256":body.executable_sha256,
        "filename_sha256":agf_core::secret::content_hash(&body.executable_b64),"argument_count":body.arguments.len(),
        "mode":body.mode,"source":body.source,"pid":body.pid,"uid":body.uid,"monotonic_ns":body.monotonic_ns,
        "truncated":body.truncated,"lost":body.lost,"path_utf8":path_utf8.is_some(),"launch_admitted":allowed,"enforced":false});
    let mut record = InterceptionRecord::new(
        current.tenant,
        &body.request_id.to_string(),
        InterceptPoint::ProcessHook,
        InterceptionVerdict::Audited,
        "Process policy decision; OS execution not asserted",
    )
    .with_tool("process_exec")
    .with_target(format!("sha256:{digest}"))
    .with_excerpt(summary.to_string());
    record.agent_id = Some(body.agent_id);
    record.action = decision.action;
    record.policy_id = decision.policy_id;
    record.enforced = false;
    record.latency_micros = decision.eval_micros.max(1);
    // 策略原因和名称可能插入原始命令或凭据，因此只保存固定说明与安全摘要。
    let record = engine.audit().append(record).map_err(DomainError::Internal)?;
    let receipt = ProcessReceipt {
        request_id: body.request_id,
        agent_id: body.agent_id,
        request_sha256: digest,
        mode: body.mode,
        launch_allowed: allowed,
        action: decision.action,
        dry_run: decision.dry_run,
        audit_committed: true,
        audit_id: record.id,
        expires_at_ms: submission.at.unix_millis() + 3000,
        enforced: false,
    };
    let mut audit = AppState::audit_entry(
        current.tenant,
        AuditAction::Execute,
        AuditOutcome::Success,
        AppState::audit_actor(&current, "process-policy"),
        AuditTarget::new("process-admission", Some(body.request_id.to_string()), None),
        "Bound Agent process decision committed; no OS execution asserted",
    );
    audit.after = Some(summary);
    publication::commit(state, submission, &receipt, &record, audit).await?;
    submission.current(state).await?;
    let latest = state.runtime_registry.get(state, current.tenant).await?;
    let bound = state
        .store
        .asset_get_durable(current.tenant, body.agent_id)
        .await?
        .filter(|a| a.kind == AssetKind::Agent && a.deleted_at.is_none());
    if !std::sync::Arc::ptr_eq(&engine, &latest)
        || bound.as_ref().is_none_or(|a| a.department != asset.department || a.data_class != asset.data_class)
    {
        return Err(DomainError::Conflict(
            "Original process policy or Agent classification changed; no launch authorized".into(),
        ));
    }
    submission.budget()?;
    Ok(receipt)
}
