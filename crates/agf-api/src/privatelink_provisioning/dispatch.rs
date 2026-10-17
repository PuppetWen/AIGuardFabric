use super::{
    authority::Submission,
    claim, completion,
    model::{Delivery, Fact, Phase, ResultData, Write},
    records, source, staging, util,
};
use crate::state::AppState;
use agf_alicloud::privatelink::provisioning::{CurrentGuard, WriteStatus};
use agf_core::{error::DomainResult, time::Timestamp};
use async_trait::async_trait;
pub(super) struct Guard<'a> {
    pub state: &'a AppState,
    pub submission: &'a Submission,
    pub fact: &'a Fact,
}
#[async_trait]
impl CurrentGuard for Guard<'_> {
    async fn validate(&self) -> DomainResult<()> {
        source::check(self.state, self.submission, self.fact.source.as_ref().ok_or_else(util::corrupt)?).await?;
        let current = records::load(self.state, self.fact.tenant, self.fact.id).await?;
        self.submission.own(&current.owner)?;
        if records::claim_hash(&current)? != records::claim_hash(self.fact)?
            || current.phase != Phase::Started
            || current.archived_at.is_some()
            || current.lease_expires_at <= Timestamp::now()
        {
            return Err(util::conflict());
        }
        self.submission.budget()
    }
}
pub(super) async fn write(state: &AppState, submission: &Submission, original: &Fact) -> DomainResult<()> {
    let started = claim::start(state, submission, original).await?;
    let source = started.source.as_ref().ok_or_else(util::corrupt)?;
    let request = started.intent.as_ref().ok_or_else(util::corrupt)?.prepare(started.id)?;
    let mut cancel = Cancellation { state: state.clone(), fact: started.clone(), armed: true };
    let guard = Guard { state, submission, fact: &started };
    let result = Box::pin(crate::cloud_runtime::execute_privatelink_provisioning(
        state,
        crate::cloud_runtime::PrivateLinkProvisioningInvocation {
            tenant: started.tenant,
            configuration_version: source.version,
            payload_fingerprint: &source.fingerprint,
            guard: &guard,
            deadline: submission.deadline,
            call: crate::cloud_runtime::PrivateLinkProvisioningCall::Write(&request),
        },
    ))
    .await;
    let outcome = match result {
        Ok(crate::cloud_runtime::PrivateLinkProvisioningOutcome::Written(e)) => Write {
            delivery: match e.status {
                WriteStatus::Acknowledged => Delivery::Acknowledged,
                WriteStatus::Rejected => Delivery::Rejected,
                WriteStatus::Unknown => Delivery::Unknown,
            },
            provider_request_id: e.provider_request_id,
            endpoint_id: e.endpoint_id,
            finished_at: Timestamp::now(),
        },
        Err(_) => Write {
            delivery: Delivery::NotSent,
            provider_request_id: None,
            endpoint_id: started.intent.as_ref().and_then(|i| i.endpoint()).map(str::to_owned),
            finished_at: Timestamp::now(),
        },
        _ => return Err(util::corrupt()),
    };
    cancel.armed = false;
    retain(state, submission, started, ResultData::Write { outcome }).await
}
pub(super) async fn retain(
    state: &AppState,
    submission: &Submission,
    started: Fact,
    outcome: ResultData,
) -> DomainResult<()> {
    let state = state.clone();
    let submission = submission.clone();
    tokio::spawn(async move {
        staging::persist(&state, &started, outcome.clone()).await?;
        completion::finish(&state, &submission, &started, outcome).await.map(|_| ())
    })
    .await
    .map_err(|_| util::conflict())?
}
pub(super) struct Cancellation {
    pub state: AppState,
    pub fact: Fact,
    pub armed: bool,
}
impl Drop for Cancellation {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let state = self.state.clone();
        let fact = self.fact.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let outcome = if fact.purpose == super::model::Purpose::Apply {
                    ResultData::Write {
                        outcome: Write {
                            delivery: Delivery::Unknown,
                            provider_request_id: None,
                            endpoint_id: fact.intent.as_ref().and_then(|i| i.endpoint()).map(str::to_owned),
                            finished_at: Timestamp::now(),
                        },
                    }
                } else {
                    ResultData::FailedRead
                };
                let _ = staging::persist(&state, &fact, outcome).await;
            });
        }
    }
}
