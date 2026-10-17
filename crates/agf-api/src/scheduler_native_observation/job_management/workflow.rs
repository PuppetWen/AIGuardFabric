use super::super::authority::Submission;
use super::{claim, completion, current, model::Operation, staging};
use crate::state::AppState;
use agf_alicloud::schedulerx3::managed_jobs::{Readback, WriteEvidence, WriteStatus};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
};
use std::sync::Arc;

pub(super) async fn apply(
    state: &AppState,
    submission: Arc<Submission>,
    id: Id,
    input: super::input::ApplyInput,
) -> DomainResult<Operation> {
    let (row, created) = claim::take(state, &submission, id, input).await?;
    if !created || row.target.mocked {
        return Ok(row);
    }
    let mut cancellation = Cancellation { state: state.clone(), row: row.clone(), armed: true };
    let preview = row.preview.as_ref().ok_or_else(super::super::util::corrupt)?;
    let selected = preview.input.selection.as_ref().ok_or_else(super::super::util::corrupt)?;
    let guard = current::Guard { state, submission: &submission, row: &row };
    let native = row.target.native();
    let write = match Box::pin(crate::cloud_runtime::execute_scheduler_management(
        state,
        crate::cloud_runtime::SchedulerManagementInvocation {
            tenant: row.tenant,
            configuration_version: row.target.configuration_version,
            payload_fingerprint: &row.target.fingerprint,
            scope: &native,
            selection: selected,
            change: &preview.input.change,
            guard: &guard,
            deadline: submission.deadline,
        },
    ))
    .await
    {
        Ok(write) => write,
        // The typed driver converts post-dispatch failures to Unknown. An Err means it never entered its single write.
        Err(_) => WriteEvidence {
            attempted: false,
            status: WriteStatus::Rejected,
            provider_request_id: None,
            authority_current: false,
            original_deadline_current: submission.budget().is_ok(),
        },
    };
    cancellation.armed = false;
    // The owned local task retains the exact known ACK if its HTTP waiter disappears.
    let owned_state = state.clone();
    let owned_submission = submission.clone();
    let original = row.clone();
    let task = tokio::spawn(async move {
        if staging::persist(&owned_state, &original, write, Readback::Unknown).await?.is_none() {
            return super::views::load_operation(&owned_state, original.tenant, original.request_id).await;
        }
        completion::finish(&owned_state, &owned_submission, &original).await
    });
    match task.await {
        Ok(Ok(row)) => Ok(row),
        _ => Err(DomainError::DependencyUnavailable {
            dependency: "scheduler-local-publication".into(),
            cause: "本地结果或审计未能完成；读取原编号核查封存状态，禁止重派".into(),
        }),
    }
}
struct Cancellation {
    state: AppState,
    row: Operation,
    armed: bool,
}
impl Drop for Cancellation {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let state = self.state.clone();
        let row = self.row.clone();
        tokio::spawn(async move {
            let outcome = staging::persist(
                &state,
                &row,
                WriteEvidence {
                    attempted: true,
                    status: WriteStatus::Unknown,
                    provider_request_id: None,
                    authority_current: false,
                    original_deadline_current: false,
                },
                Readback::Unknown,
            )
            .await;
            if outcome.is_err() {
                tracing::warn!("Scheduler 取消结果未能封存；旧领取保留，过期后只能本地恢复");
            }
        });
    }
}
