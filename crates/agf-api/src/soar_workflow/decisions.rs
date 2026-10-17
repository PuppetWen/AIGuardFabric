//! Optimistic revisions prevent a stale approval from authorizing a different step.
use super::*;

#[derive(Debug, Clone, Deserialize)]
pub struct Decision {
    pub expected_version: u64,
    /// approve / reject / cancel / abort / confirm-completed / retry
    pub action: String,
    pub reason: String,
}

pub async fn decide(state: &AppState, principal: &Principal, id: Id, body: Decision) -> DomainResult<Run> {
    if body.reason.trim().is_empty() || body.reason.len() > 2000 {
        return Err(DomainError::Validation("请填写 1–2000 字节的处理原因".into()));
    }
    if body.action == "cancel" {
        principal.require(state, "cases", "write").map_err(|e| e.error)?;
    } else if !can_approve(state, principal) {
        return Err(DomainError::Forbidden("需要已登录用户及 cases:admin 权限".into()));
    }
    let actor = Actor::from_principal(principal)?;
    change(state, principal.tenant, id, |run| {
        let now = Timestamp::now();
        if run.version != body.expected_version {
            return Err(DomainError::Conflict("执行记录已更新，请刷新后重新核对步骤与目标".into()));
        }
        if run.status.terminal() || run.history.len() >= 900 {
            return Err(DomainError::Conflict("该执行记录已结束或处理次数达到上限".into()));
        }
        match body.action.as_str() {
            "abort" if run.status == Status::Review => {
                run.finish(
                    Status::Aborted,
                    now,
                    &format!("停止后续步骤；中断步骤的实际影响须另行核对：{}", body.reason),
                );
            }
            "cancel" => {
                if matches!(run.status, Status::Running | Status::Review) {
                    return Err(DomainError::Conflict("当前步骤结果尚未确认，请等待完成或先核对处置记录".into()));
                }
                if actor.id != run.requested_by.id && !can_approve(state, principal) {
                    return Err(DomainError::Forbidden("只能取消本人发起的任务；管理员可取消其他任务".into()));
                }
                run.finish(Status::Cancelled, now, &body.reason);
            }
            "approve" | "reject" => {
                if run.status != Status::Approval || run.wake_at.is_some_and(|at| at <= now) {
                    return Err(DomainError::Conflict("该步骤当前不在有效审批期内".into()));
                }
                if run.separate_approver
                    && actor.id == run.requested_by.id
                    && actor.identity_tenant == run.requested_by.identity_tenant
                {
                    return Err(DomainError::Forbidden("该任务要求由另一位管理员审批".into()));
                }
                if body.action == "reject" {
                    run.finish(Status::Aborted, now, &body.reason);
                } else {
                    // The approver supplies current action permissions; the submitting service key cannot self-approve.
                    run.execute_as = actor.clone();
                    if run.initial_approval {
                        run.initial_approval = false;
                        run.deadline_at = Some(now.offset_secs(run.playbook.timeout_secs));
                        run.status = Status::Queued;
                        run.wake_at = None;
                    } else {
                        run.complete_step(now, &format!("审批通过：{}；{}", actor.display(), body.reason));
                    }
                }
            }
            "confirm-completed" | "retry" => {
                if run.status != Status::Review {
                    return Err(DomainError::Conflict("只能处理结果待核对的步骤".into()));
                }
                run.execute_as = actor.clone();
                if body.action == "confirm-completed" {
                    run.complete_step(now, &format!("人工核实已完成：{}；{}", actor.display(), body.reason));
                } else {
                    if run.deadline_at.is_some_and(|at| at <= now) {
                        return Err(DomainError::Conflict("任务已超过总时限；请确认已有处置后另建任务".into()));
                    }
                    run.status = Status::Queued;
                }
                run.lease_token = None;
                run.lease_until = None;
                run.reason = None;
            }
            _ => return Err(DomainError::Validation("未知处理动作".into())),
        }
        run.record(now, &actor.display(), &body.action, &body.reason);
        Ok(())
    })
    .await
}
