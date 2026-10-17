use super::{
    BODY,
    authority::Submission,
    completion,
    model::{Attempt, Body, Delivery, Outcome},
    provider, records, send, staging, store, util,
};
use crate::state::AppState;
use agf_alicloud::cms::queue_delivery::Outcome as VendorOutcome;
use agf_core::{error::DomainResult, time::Timestamp};

pub(super) async fn one(state: &AppState, submission: &Submission, original: &Attempt) -> DomainResult<()> {
    let item =
        super::authority::bounded(submission.deadline, records::load_item(state, original.tenant, original.item_id))
            .await?;
    let body: Body =
        super::authority::bounded(submission.deadline, store::get(state, item.tenant, &util::key(BODY, item.id)))
            .await?
            .ok_or_else(util::corrupt)?;
    provider::body(&body, &item)?;
    let request = provider::prepare(&body.payload, &original.source)?;
    let started = send::start(state, submission, original).await?;
    let mut cancellation = Cancellation { state: state.clone(), attempt: started.clone(), armed: true };
    let guard = provider::Guard { state, submission, attempt: &started };
    let result = Box::pin(crate::cloud_runtime::execute_cms_queue(
        state,
        crate::cloud_runtime::CmsQueueInvocation {
            tenant: started.tenant,
            configuration_version: started.source.version,
            payload_fingerprint: &started.source.fingerprint,
            guard: &guard,
            deadline: submission.deadline,
            request: &request,
        },
    ))
    .await;
    let (delivery, id) = match result {
        Ok(VendorOutcome::Accepted(id)) => (Delivery::Accepted, Some(id)),
        Ok(VendorOutcome::Rejected(id)) => (Delivery::Rejected, Some(id)),
        Ok(VendorOutcome::Unknown) => (Delivery::Unknown, None),
        // The typed driver returns Err only before the unique transport call.
        Err(_) => (Delivery::NotSent, None),
    };
    let outcome = Outcome { delivery, provider_request_id: id, finished_at: Timestamp::now() };
    cancellation.armed = false;
    let state = state.clone();
    let submission = submission.clone();
    let task = tokio::spawn(async move {
        staging::persist(&state, &started, outcome.clone()).await?;
        completion::finish(&state, &submission, &started, outcome).await.map(|_| ())
    });
    task.await.map_err(|_| util::conflict())?
}
struct Cancellation {
    state: AppState,
    attempt: Attempt,
    armed: bool,
}
impl Drop for Cancellation {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let state = self.state.clone();
        let attempt = self.attempt.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = staging::persist(
                    &state,
                    &attempt,
                    Outcome { delivery: Delivery::Unknown, provider_request_id: None, finished_at: Timestamp::now() },
                )
                .await;
            });
        }
    }
}
