//! Atomically attach a case, queue a run and record the trigger decision in SQL.
use super::*;
use agf_core::{
    case::{Case, CaseEvent, CaseEventKind},
    enums::CaseState,
};
use agf_correlate::playbook::RunContext;
use agf_storage::{CaseRepo, TenantTransaction, map_sqlx_err};

struct Prepared {
    status: &'static str,
    reason: String,
    context: Option<RunContext>,
}

async fn prepare(state: &AppState, template: &Automation, alert: &Alert) -> DomainResult<Prepared> {
    if state.config.mock_mode != template.mock_mode {
        return Err(DomainError::PreconditionFailed("模拟/真实模式已改变，请重新核对并保存配置".into()));
    }
    let principal = template.published_by.resolve(state, template.tenant_id).await?;
    if !can_manage(state, &principal) {
        return Err(DomainError::Forbidden("发布者已失去自动响应管理权限".into()));
    }
    let preview = inputs::preview(state, template.tenant_id, alert, &template.playbook).await?;
    if !preview.active || !preview.matches {
        return Ok(Prepared {
            status: "skipped", reason: "告警已结束、被抑制或不符合触发条件".into(), context: None
        });
    }
    Ok(Prepared {
        status: "submitted",
        reason: "已创建持久化执行任务，请到案件查看审批和逐步结果".into(),
        context: Some(preview.context),
    })
}

fn closed(case: &Case) -> bool {
    matches!(case.state, CaseState::Resolved | CaseState::Closed)
}

fn event(template: &Automation, case: Id) -> CaseEvent {
    CaseEvent {
        id: Id::new(),
        tenant_id: template.tenant_id,
        case_id: case,
        kind: CaseEventKind::Created,
        actor: template.published_by.display(),
        note: "告警自动响应创建案件".into(),
        detail: serde_json::json!({"automation_id":template.id,"version":template.version}),
        automated: true,
        at: Timestamp::now(),
    }
}

async fn case_sql(tx: &mut TenantTransaction<'_>, alert: &Alert, template: &Automation) -> DomainResult<Option<Case>> {
    // Match the manual case creator's lock order: tenant numbering before alert ownership.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("case-numbering:{}", template.tenant_id))
        .execute(&mut **tx)
        .await
        .map_err(|e| map_sqlx_err("soar_case_lock", &e))?;
    let saved: serde_json::Value = sqlx::query_scalar("SELECT to_jsonb(a) FROM alerts a WHERE id=$1 FOR UPDATE")
        .bind(alert.id.as_uuid())
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| map_sqlx_err("soar_alert_lock", &e))?;
    let saved: Alert = serde_json::from_value(saved)?;
    if !saved.is_active() {
        return Ok(None);
    }
    if let Some(id) = saved.case_id {
        return CaseRepo::get(tx, id, true).await;
    }
    let (id, _) = CaseRepo::create(
        tx,
        &alert.title,
        &alert.description,
        alert.severity,
        &[alert.id],
        &alert.finding_ids,
        &alert.asset_ids,
        alert.assignee.as_deref(),
    )
    .await?;
    let case = CaseRepo::get(tx, id, false).await?.ok_or_else(|| DomainError::Internal("自动案件创建失败".into()))?;
    CaseRepo::link_alerts(tx, &case).await?;
    CaseRepo::insert_event(tx, &event(template, id)).await?;
    Ok(Some(case))
}

fn run(template: &Automation, delivery: Id, case: &Case, context: RunContext) -> DomainResult<workflow::Run> {
    let context = context
        .with_case(case.id)
        .with_param("case_code", &case.code)
        .with_param("case_state", case.state.as_str())
        .with_param("automation_id", template.id.to_string())
        .with_param("automation_version", template.version.to_string());
    workflow::prepare(workflow::Submission {
        id: delivery,
        case_id: case.id,
        actor: template.published_by.clone(),
        book: template.playbook.clone(),
        context,
        separate_approver: template.separate_approver,
        matches: true,
        mock_mode: template.mock_mode,
    })
}

async fn commit(state: &AppState, template: &Automation, alert: &Alert, prepared: Prepared) -> DomainResult<()> {
    let tenant = template.tenant_id;
    let id = delivery_id(tenant, template.id, alert.id);
    let mut receipt = Delivery {
        id,
        automation_id: template.id,
        automation_version: template.version,
        alert_id: alert.id,
        alert_title: alert.title.clone(),
        status: prepared.status.into(),
        reason: prepared.reason,
        case_id: None,
        run_id: None,
        attempts: 1,
        at: Timestamp::now(),
        history: Vec::new(),
    };
    let _guard = state.soar_automation_lock.lock().await;
    if let Some(db) = state.store.database() {
        let (template, alert) = (template.clone(), alert.clone());
        return db
            .with_tenant(tenant, move |tx| {
                Box::pin(async move {
                    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
                        .bind(format!("{tenant}:{KIND}:{}", template.id))
                        .execute(&mut **tx)
                        .await
                        .map_err(|e| map_sqlx_err("soar_automation_lock", &e))?;
                    let current = storage::read::<Automation>(tx, KIND, template.id).await?;
                    if current.is_none_or(|row| !row.enabled || row.version != template.version) {
                        return Ok(());
                    }
                    // Retry uses the receipt lock as well; it cannot overwrite a committed submission.
                    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
                        .bind(format!("{tenant}:{DELIVERY}:{id}"))
                        .execute(&mut **tx)
                        .await
                        .map_err(|e| map_sqlx_err("soar_delivery_lock", &e))?;
                    if let Some(previous) = storage::read::<Delivery>(tx, DELIVERY, id).await? {
                        if previous.status != "pending" {
                            return Ok(());
                        }
                        receipt.attempts = previous.attempts.saturating_add(1);
                        receipt.history = previous.history;
                        if previous.automation_version != template.version {
                            receipt.status = "skipped".into();
                            receipt.reason = "配置变更，旧触发不自动执行新动作".into();
                            receipt.record("system:soar".into());
                            return storage::write(tx, DELIVERY, id, &receipt).await;
                        }
                    }
                    if let Some(context) = prepared.context {
                        if let Some(case) = case_sql(tx, &alert, &template).await?.filter(|case| !closed(case)) {
                            let run = run(&template, id, &case, context)?;
                            storage::write(tx, workflow::KIND, id, &run).await?;
                            receipt.case_id = Some(case.id);
                            receipt.run_id = Some(run.id);
                        } else {
                            receipt.status = "skipped".into();
                            receipt.reason = "告警不活跃或所属案件已解决/关闭".into();
                        }
                    }
                    receipt.record("system:soar".into());
                    storage::write(tx, DELIVERY, id, &receipt).await
                })
            })
            .await;
    }
    let current = get(state, tenant, template.id).await?;
    if !current.enabled || current.version != template.version {
        return Ok(());
    }
    if let Some(previous) = state.configurations.get::<Delivery>(tenant, DELIVERY, id).await? {
        if previous.status != "pending" {
            return Ok(());
        }
        receipt.attempts = previous.attempts.saturating_add(1);
        receipt.history = previous.history;
        if previous.automation_version != template.version {
            receipt.status = "skipped".into();
            receipt.reason = "配置变更，旧触发不自动执行新动作".into();
            receipt.record("system:soar".into());
            return state.configurations.put(tenant, DELIVERY, id, &receipt).await;
        }
    }
    if let Some(context) = prepared.context {
        let saved = state.store.alert_get(tenant, alert.id)?;
        if let Some(saved) = saved.filter(Alert::is_active) {
            let case = if let Some(id) = saved.case_id {
                state.store.case_get(tenant, id)?
            } else {
                let case = state.store.case_create(
                    tenant,
                    &alert.title,
                    &alert.description,
                    alert.severity,
                    &[alert.id],
                    &alert.finding_ids,
                    &alert.asset_ids,
                    alert.assignee.as_deref(),
                )?;
                state.store.case_insert_event_durable(&event(template, case.id)).await?;
                Some(case)
            };
            if let Some(case) = case.filter(|case| !closed(case)) {
                let run = run(template, id, &case, context)?;
                state.configurations.put(tenant, workflow::KIND, id, &run).await?;
                receipt.case_id = Some(case.id);
                receipt.run_id = Some(id);
            }
        }
        if receipt.run_id.is_none() {
            receipt.status = "skipped".into();
            receipt.reason = "告警不活跃或所属案件已解决/关闭".into();
        }
    }
    receipt.record("system:soar".into());
    state.configurations.put(tenant, DELIVERY, id, &receipt).await
}

pub async fn tick(state: &AppState) -> DomainResult<usize> {
    let mut processed = 0;
    for tenant in crate::tenant_directory::list(state).await?.into_iter().filter(|row| row.enabled) {
        let templates = storage::summaries(state, tenant.id).await?;
        for template in templates.into_iter().filter(|row| row.enabled) {
            for alert in storage::candidates(state, &template).await? {
                let prepared = prepare(state, &template, &alert).await.unwrap_or_else(|error| Prepared {
                    status: "failed",
                    reason: error.to_string().chars().take(2000).collect(),
                    context: None,
                });
                match commit(state, &template, &alert, prepared).await {
                    Ok(()) => processed += 1,
                    Err(error) => {
                        tracing::warn!(%error, automation=%template.id, alert=%alert.id, "Automatic response not committed; will retry");
                    }
                }
            }
        }
    }
    Ok(processed)
}
