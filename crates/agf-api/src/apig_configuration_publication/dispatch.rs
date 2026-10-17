//! The network future remains borrowed; only a static encrypted completion may outlive cancellation.
use super::{
    audit,
    authority::Submission,
    completion,
    content::Content,
    operations,
    provider::{self, Guard},
    records::*,
    sql::key,
    store::{self, Decision, Mutation},
    util,
};
use crate::state::AppState;
use agf_alicloud::apig::config_driver::{ReadbackState, WriteOutcome};
use agf_core::{
    audit::AuditAction,
    error::{DomainError, DomainResult},
    time::Timestamp,
};
use serde_json::json;
use std::sync::{Arc, Mutex};

pub(super) async fn run(
    state: AppState,
    submission: Arc<Submission>,
    fact: Fact,
    prepared: Prepared,
    content: Content,
) -> DomainResult<()> {
    let progress = Arc::new(Mutex::new(operations::receipt(&fact)?.clone()));
    let mut on_cancel =
        LocalCompletion { state: state.clone(), fact: fact.clone(), receipt: progress.clone(), armed: true };
    let guard = Arc::new(Guard {
        state: state.clone(),
        submission: submission.clone(),
        scope: fact.scope.clone(),
        operation: Some(fact.request_id),
    });
    let result = tokio::time::timeout_at(
        submission.deadline,
        Box::pin(flow(&state, &submission, &fact, &content, guard, &progress)),
    )
    .await;
    let mut receipt = locked(&progress)?;
    if !matches!(result, Ok(Ok(()))) {
        fail(&mut receipt, "执行预算、基线或当前权限/来源守卫未满足；云结果按已知阶段保留");
    }
    receipt.finished_at = Some(Timestamp::now());
    receipt.local_publication = PublicationStatus::PendingAudit;
    update(&progress, &receipt)?;
    // The known result is encrypted and staged even if original authority or dependencies changed after delivery.
    let result = completion::finish(state, submission, fact, receipt, prepared).await;
    if result.is_ok() {
        on_cancel.armed = false;
    }
    result
}

async fn flow(
    state: &AppState,
    submission: &Submission,
    fact: &Fact,
    content: &Content,
    guard: Arc<Guard>,
    progress: &Arc<Mutex<Operation>>,
) -> DomainResult<()> {
    mark_dispatch(state, submission, fact).await?;
    let mut receipt = locked(progress)?;
    receipt.cloud_write = WriteStatus::Attempting;
    update(progress, &receipt)?;
    match provider::publish(guard.clone(), &content.update).await {
        Ok(WriteOutcome::Accepted { request_id }) => {
            receipt.cloud_write = WriteStatus::Accepted;
            receipt.provider_request_id = Some(request_id);
        }
        Ok(WriteOutcome::Unknown) => {
            receipt.cloud_write = WriteStatus::Unknown;
            receipt.status = Status::Uncertain;
            receipt.safe_reason =
                Some("已进入唯一写传输但缺少可信ACK；原编号永久不重发，旧请求可能迟到且影响共享配置".into());
        }
        Err(error) => {
            // Both typed drivers return Err only before the unique configuration PUT transport/Mock execution.
            receipt.cloud_write = WriteStatus::NotAttempted;
            receipt.status = if matches!(error, DomainError::Conflict(_)) { Status::Conflict } else { Status::Failed };
            receipt.safe_reason = Some("完整资源基线、当前授权、依赖或原预算在写传输前拒绝；请重新观察并预览".into());
        }
    }
    update(progress, &receipt)?;
    if receipt.cloud_write == WriteStatus::Accepted {
        match provider::query(guard, false).await {
            Ok(after) => {
                receipt.readback_observed_at = Some(Timestamp::now());
                receipt.readback_hash = Some(after.fingerprint().to_owned());
                if content.update.compare_readback(&after) == ReadbackState::Matched {
                    receipt.readback = ReadStatus::Matched;
                    receipt.status = Status::Verified;
                } else {
                    receipt.readback = ReadStatus::Different;
                    receipt.status = Status::Uncertain;
                    receipt.safe_reason = Some("已保留APIG接受ACK，独立回读不同；不证明当前配置或流量生效".into());
                }
            }
            Err(_) => {
                receipt.readback = ReadStatus::Unavailable;
                receipt.status = Status::Uncertain;
                receipt.safe_reason = Some("已保留APIG接受ACK，当前权限、来源或回读不可用；仅恢复本地事实".into());
            }
        }
        update(progress, &receipt)?;
    }
    Ok(())
}

async fn mark_dispatch(state: &AppState, submission: &Submission, fact: &Fact) -> DomainResult<()> {
    let related = [key(FACT, util::fact_id(fact.tenant, fact.request_id))];
    store::mutate(state, Mutation { submission, scope: Some(&fact.scope), related: &related }, |main, snapshot| {
        let mut stored: Fact = util::read(&snapshot.related, FACT, util::fact_id(fact.tenant, fact.request_id))?
            .ok_or_else(util::corrupt)?;
        let receipt = operations::receipt_mut(&mut stored)?;
        if receipt.status != Status::Started
            || receipt.lease_expires_at <= Timestamp::now()
            || !main.active.as_ref().is_some_and(|active| {
                let same_owner = active.request_id == fact.request_id;
                let same_lease = active.expires_at == receipt.lease_expires_at;
                same_owner && same_lease
            })
        {
            return Err(util::stale());
        }
        receipt.cloud_write = WriteStatus::Attempting;
        let mut writes = Values::new();
        util::put(&mut writes, FACT, util::fact_id(fact.tenant, fact.request_id), &stored)?;
        util::bump(main)?;
        let audit = audit::entry(
            submission,
            fact.request_id,
            "apig-configuration-publication-dispatch",
            AuditAction::Configure,
            json!({"phase":"write_intent","targetScopeId":fact.scope.target.target_scope_id}),
        );
        Ok(Decision::Write { related: writes, audit: Box::new(audit) })
    })
    .await?;
    Ok(())
}

fn fail(receipt: &mut Operation, reason: &str) {
    if receipt.status != Status::Started {
        return;
    }
    receipt.status = if receipt.cloud_write == WriteStatus::NotAttempted { Status::Failed } else { Status::Uncertain };
    if receipt.cloud_write == WriteStatus::Attempting {
        receipt.cloud_write = WriteStatus::Unknown;
    }
    if receipt.cloud_write == WriteStatus::Accepted {
        receipt.readback = ReadStatus::Unavailable;
    }
    receipt.safe_reason = Some(reason.into());
}
fn locked(progress: &Mutex<Operation>) -> DomainResult<Operation> {
    progress.lock().map(|receipt| receipt.clone()).map_err(|_| DomainError::Internal("本地回执阶段锁已损坏".into()))
}
fn update(progress: &Mutex<Operation>, receipt: &Operation) -> DomainResult<()> {
    progress.lock().map_err(|_| DomainError::Internal("本地回执阶段锁已损坏".into()))?.clone_from(receipt);
    Ok(())
}

struct LocalCompletion {
    state: AppState,
    fact: Fact,
    receipt: Arc<Mutex<Operation>>,
    armed: bool,
}
impl Drop for LocalCompletion {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let Ok(mut receipt) = locked(&self.receipt) else {
            return;
        };
        fail(&mut receipt, "父请求取消或断线；已知云阶段保留，未确认的写结果永久未知，禁止原编号重发");
        receipt.finished_at = Some(Timestamp::now());
        receipt.local_publication = PublicationStatus::PendingAudit;
        let state = self.state.clone();
        let fact = self.fact.clone();
        tokio::spawn(async move {
            if let Err(error) = completion::stage(&state, &fact, &receipt).await {
                tracing::warn!(%error, "取消后的本地APIG回执暂存失败；永久claim保留，禁止远端重派");
            }
        });
    }
}
