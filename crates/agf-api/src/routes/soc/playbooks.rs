//! Case playbook execution, approval evidence and durable results.
use super::*;

/// 案件剧本执行 Body。
///
/// 二选一提供剧本：`yaml`（`parse_playbooks_yaml` 的三种形态都接受）或 `playbook`（JSON 对象）。
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct CasePlaybookBody {
    /// 剧本 YAML 原文（多剧本文件用 `key` 选择）。
    #[serde(default)]
    pub yaml: Option<String>,
    /// 剧本 JSON（与 YAML 等价的 `agf_core::case::Playbook` 结构）。
    #[serde(default)]
    pub playbook: Option<serde_json::Value>,
    /// 多剧本时按 key 选择（缺省取第一个）。
    #[serde(default)]
    pub key: Option<String>,
    /// 空转（演练）执行：只走轨迹，不调用执行器/通知点。
    #[serde(default)]
    pub dry_run: Option<bool>,
    /// 人工审批结论（默认 `false` = 拒绝）。含不可逆动作或审批步骤的剧本在 `false` 时**不执行**。
    #[serde(default)]
    pub approve: Option<bool>,
}

/// Run a tenant-scoped playbook with real managed actions and an explicit human approval.
pub async fn case_playbook(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
    body: Bytes,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "cases", "write")?;
    let case_id = parse_id(&id, "case")?;
    let body: CasePlaybookBody = optional_body(&body)?;
    let Some(case) = state.store.case_get_durable(principal.tenant, case_id).await? else {
        return Err(ApiError::new(DomainError::NotFound { entity: "case", id }));
    };

    let book = select_playbook(&body)?;
    let (trigger, ctx) = super::playbook_context::context(&state, principal.tenant, &case).await?;

    let approve = body.approve.unwrap_or(false);
    let dry_run = body.dry_run.unwrap_or(false);
    if approve && !dry_run {
        principal.require(&state, "cases", "admin")?;
        if principal.subject_kind != agf_core::rbac::SubjectKind::User {
            return Err(DomainError::Forbidden("审批必须由已登录且有 cases:admin 权限的用户确认".into()).into());
        }
    }
    let request_id = Id::new();
    state
        .configurations
        .put(
            principal.tenant,
            "soar-execution-request",
            request_id,
            &serde_json::json!({
                "id":request_id,"case_id":case.id,"actor":principal.display(),"approved":approve,
                "dry_run":dry_run,"playbook":book,"created_at":Timestamp::now(),"status":"started"
            }),
        )
        .await?;
    let executor =
        crate::soar_executor::Executor { state: state.clone(), principal: principal.clone(), workflow_step: None };
    let mut engine = PlaybookEngine::new()
        .with_action_executor(Box::new(executor.clone()))
        .with_notifier(Box::new(executor))
        .with_approval(Box::new(crate::soar_executor::Approval { approved: approve }));
    if body.dry_run.unwrap_or(false) {
        engine = engine.dry_run();
    }

    let now = Timestamp::now();
    let mut run = engine.run(&book, &trigger, &ctx, now).await.map_err(|e| playbook_error(e, &book.key))?;
    run.finished_at = Timestamp::now();
    let report = run.report();
    let run_id = request_id;
    let record =
        SoarRunRecord { id: run_id, tenant_id: principal.tenant, case_id: case.id, started_at: now, run: run.clone() };
    state.configurations.put(principal.tenant, "soar-run", run_id, &record).await?;
    state
        .configurations
        .put(
            principal.tenant,
            "soar-execution-request",
            request_id,
            &serde_json::json!({
                "id":request_id,"case_id":case.id,"actor":principal.display(),"approved":approve,
                "dry_run":dry_run,"playbook":book,"created_at":now,"status":"finished","outcome":run.outcome
            }),
        )
        .await?;
    state.store.soar_run_insert(record)?;
    state
        .store
        .case_add_event_durable(
            principal.tenant,
            case.id,
            CaseEventKind::PlaybookRun,
            &principal.display(),
            &format!("剧本 {} 执行：{}（{} 步）", run.playbook_key, run.outcome.as_str(), run.steps()),
        )
        .await?;
    state
        .audit(
            principal.tenant,
            AuditAction::Execute,
            if run.has_failure() { AuditOutcome::Failure } else { AuditOutcome::Success },
            AppState::audit_actor(&principal, "case-playbook"),
            AuditTarget::new("case", Some(case.id.to_string()), Some(book.key.clone())),
            &format!(
                "剧本 {} v{} 在案件 {} 上执行：{}（dry_run={}，approve={}）",
                book.key,
                book.version,
                case.code,
                run.outcome.as_str(),
                run.dry_run,
                approve
            ),
        )
        .await?;
    state.publish(crate::state::WsEvent {
        kind: "case".to_string(),
        tenant_id: principal.tenant,
        at: now,
        payload: serde_json::json!({
            "case_id": case.id,
            "playbook": book.key,
            "outcome": run.outcome.as_str(),
        }),
    });

    Ok(Json(serde_json::json!({
        "case_id": case.id,
        "case_code": case.code,
        "run_id": run_id,
        "playbook": run.playbook_key,
        "playbook_version": run.playbook_version,
        "trigger": { "severity": ctx.severity.as_str(), "domain": ctx.domain },
        "outcome": run.outcome.as_str(),
        "dry_run": run.dry_run,
        "approved": approve,
        "steps": run.trace,
        "step_count": run.steps(),
        "has_failure": run.has_failure(),
        "executed_actions": run.executed_actions(),
        "reason": run.reason,
        "report": report,
        "run": run,
        "note": "演练不产生副作用；真实处置以逐步执行结果为准。隔离/封禁适用于经过 AIGuardFabric 的 MCP/模型流量",
    })))
}
