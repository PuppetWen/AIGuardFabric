//! The network future remains borrowed; only a static encrypted completion may outlive cancellation.
use super::{
    audit,
    authority::Submission,
    bundle::BundleContent,
    completion, dependencies, operations,
    provider::{self, Guard},
    records::*,
    sql::key,
    store::{self, Decision, Mutation},
    util,
};
use crate::state::AppState;
use agf_alicloud::mse::config_cas::PublishOutcome;
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
    content: BundleContent,
) -> DomainResult<()> {
    let progress = Arc::new(Mutex::new(operations::receipt(&fact)?.clone()));
    let mut on_cancel =
        LocalCompletion { state: state.clone(), fact: fact.clone(), receipt: progress.clone(), armed: true };
    let guard = Arc::new(Guard {
        state: state.clone(),
        submission: submission.clone(),
        scope: fact.scope.clone(),
        fence: Some(prepared.fence.clone()),
        source: content.source_policies.clone(),
        operation: Some(fact.request_id),
    });
    let result = tokio::time::timeout_at(
        submission.deadline,
        Box::pin(flow(&state, &submission, &fact, &prepared, &content, guard, &progress)),
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
    let result = completion::finish(state, submission, fact, receipt, prepared, content.source_policies).await;
    if result.is_ok() {
        on_cancel.armed = false;
    }
    result
}

async fn flow(
    state: &AppState,
    submission: &Submission,
    fact: &Fact,
    prepared: &Prepared,
    content: &BundleContent,
    guard: Arc<Guard>,
    progress: &Arc<Mutex<Operation>>,
) -> DomainResult<()> {
    let before = provider::query(guard.clone()).await?;
    if before.md5 != prepared.baseline_md5 || util::hash(before.content.as_bytes()) != prepared.baseline_hash {
        let mut receipt = locked(progress)?;
        receipt.status = Status::Conflict;
        receipt.safe_reason = Some("发送前基线已改变；没有进入写传输，请新观察和新预览".into());
        receipt.readback = ReadStatus::Different;
        receipt.readback_observed_at = Some(before.observed_at);
        receipt.readback_hash = Some(util::hash(before.content.as_bytes()));
        update(progress, &receipt)?;
        return Ok(());
    }
    mark_dispatch(state, submission, fact, prepared, &content.source_policies).await?;
    let mut receipt = locked(progress)?;
    receipt.cloud_write = WriteStatus::Attempting;
    update(progress, &receipt)?;
    match provider::publish(guard.clone(), &prepared.baseline_md5, &content.plaintext).await {
        Ok(PublishOutcome::Accepted) => {
            receipt.cloud_write = WriteStatus::Accepted;
        }
        Ok(PublishOutcome::Conflict) => {
            receipt.cloud_write = WriteStatus::Conflict;
            receipt.status = Status::Conflict;
            receipt.safe_reason = Some("供应商明确拒绝内容MD5 CAS；请新观察，不会自动重发".into());
        }
        Ok(PublishOutcome::Rejected { .. }) => {
            receipt.cloud_write = WriteStatus::Rejected;
            receipt.status = Status::Failed;
            receipt.safe_reason = Some("供应商按已验证协议明确拒绝此写入；不会自动重发".into());
        }
        Ok(PublishOutcome::Uncertain(_)) => {
            receipt.cloud_write = WriteStatus::Unknown;
            receipt.status = Status::Uncertain;
            receipt.safe_reason = Some("云写入送达或结果未知；原编号/预览永久不重派，旧远端请求仍可能迟到".into());
        }
        Err(_) => {
            // The pinned driver returns Err only before transport starts.
            receipt.cloud_write = WriteStatus::NotAttempted;
            receipt.status = Status::Failed;
            receipt.safe_reason = Some("凭据、当前守卫或本地校验在写传输开始前拒绝".into());
        }
    }
    update(progress, &receipt)?;
    if receipt.cloud_write == WriteStatus::Accepted {
        match provider::query(guard).await {
            Ok(after) => {
                let hash = util::hash(after.content.as_bytes());
                receipt.readback_observed_at = Some(after.observed_at);
                receipt.readback_hash = Some(hash.clone());
                if hash == content.content_hash && after.content == content.plaintext {
                    receipt.readback = ReadStatus::Matched;
                    receipt.status = Status::Verified;
                } else {
                    receipt.readback = ReadStatus::Different;
                    receipt.status = Status::Uncertain;
                    receipt.safe_reason = Some("云端已接受，随后回读与原期望正文不同；不能宣称当前或消费者生效".into());
                }
            }
            Err(_) => {
                receipt.readback = ReadStatus::Unavailable;
                receipt.status = Status::Uncertain;
                receipt.safe_reason = Some("已保留云端接受证据，但回读不可用或原权限/来源改变；仅恢复本地事实".into());
            }
        }
        update(progress, &receipt)?;
    }
    Ok(())
}

async fn mark_dispatch(
    state: &AppState,
    submission: &Submission,
    fact: &Fact,
    prepared: &Prepared,
    source: &[agf_core::policy::Policy],
) -> DomainResult<()> {
    let (selection, _) = dependencies::prepare(state, &fact.scope, &prepared.fence.policies, source).await?;
    let related = [key(FACT, util::fact_id(fact.tenant, fact.request_id))];
    store::mutate(
        state,
        Mutation {
            submission,
            scope: Some(&fact.scope),
            selection: Some(&selection),
            fence: Some(&prepared.fence),
            source,
            related: &related,
        },
        |main, snapshot| {
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
                "mse-config-publication-dispatch",
                AuditAction::Configure,
                json!({"phase":"write_intent","targetScopeId":fact.scope.target.target_scope_id}),
            );
            Ok(Decision::Write { related: writes, audit: Box::new(audit) })
        },
    )
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
                tracing::warn!(%error, "取消后的本地MSE回执暂存失败；永久claim保留，禁止远端重派");
            }
        });
    }
}
