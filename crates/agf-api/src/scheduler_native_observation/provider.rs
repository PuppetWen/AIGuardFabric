//! Live calls require a dedicated same-entry hook; Mock initialization is an explicit guarded POST action.
use super::{
    authority::Submission,
    claim,
    records::{Journal, MOCK, MockRecord, Values},
    safe::SafeSnapshot,
    scope::{self, SourceTarget},
    store::{self, Mutation, Plan},
    util,
};
use crate::state::AppState;
use agf_alicloud::schedulerx3::native_observation::{self as driver, CurrentGuard};
use agf_core::{
    audit::{AuditAction, AuditOutcome},
    error::{DomainError, DomainResult},
    ids::Id,
};

pub(super) struct Guard<'a> {
    pub state: &'a AppState,
    pub submission: &'a Submission,
    pub target: &'a SourceTarget,
    pub row: &'a super::records::Fact,
}
#[async_trait::async_trait]
impl CurrentGuard for Guard<'_> {
    async fn validate(&self) -> DomainResult<()> {
        self.submission.authorize(self.state).await?;
        if scope::current(self.state, self.target.tenant).await?.as_ref() != Some(self.target) {
            return Err(util::stale());
        }
        let journal = store::journal(self.state, self.target.tenant).await?;
        if !claim::owns(&journal, self.row) {
            return Err(util::stale());
        }
        self.submission.budget()
    }
}
fn mock_key(target: &SourceTarget) -> (String, Id) {
    (MOCK.into(), util::key_id(target.tenant, target.scope_id, MOCK))
}
pub(super) async fn seed(state: &AppState, submission: &Submission, target: &SourceTarget) -> DomainResult<()> {
    if !submission.write || !target.mocked || target.region != "cn-hangzhou" {
        return Err(DomainError::PreconditionFailed("示例初始化仅限明确授权的 Mock 来源和 cn-hangzhou".into()));
    }
    let mut fixture = driver::MockState::default();
    fixture.seed_owned_fixture(&target.native())?;
    let data = SafeSnapshot::parse(target, serde_json::to_value(fixture.observe(&target.native())?)?)?;
    let key = mock_key(target);
    let state_key = util::state_key(target.tenant);
    let (secret, hash) = util::encrypt_json(state, target.tenant, key.1, data.value())?;
    let mock = MockRecord { tenant: target.tenant, scope_id: target.scope_id, hash, secret };
    store::mutate(
        state,
        Mutation {
            submission,
            source: Some(target),
            main: state_key.clone(),
            declared: vec![state_key.clone(), key.clone()],
        },
        |snapshot| {
            if let Some(old) = util::read::<MockRecord>(snapshot, &key)? {
                decode_mock(state, target, &old)?;
                return Ok(((), None));
            }
            let mut journal: Journal = util::read(snapshot, &state_key)?.unwrap_or_default();
            store::bump(&mut journal, target.tenant)?;
            let mut writes = Values::new();
            util::put(&mut writes, state_key, &journal)?;
            util::put(&mut writes, key, &mock)?;
            Ok((
                (),
                Some(Plan {
                    writes,
                    audit: Box::new(claim::audit(
                        submission,
                        target.scope_id,
                        "scheduler-native-mock",
                        AuditAction::Configure,
                        AuditOutcome::Success,
                        "明确初始化固定示例；不创建真实云任务或配置回调",
                    )),
                }),
            ))
        },
    )
    .await
}
fn decode_mock(state: &AppState, target: &SourceTarget, row: &MockRecord) -> DomainResult<SafeSnapshot> {
    if (row.tenant, row.scope_id) != (target.tenant, target.scope_id) {
        return Err(util::corrupt());
    }
    SafeSnapshot::parse(target, util::decrypt_json(state, target.tenant, mock_key(target).1, &row.secret, &row.hash)?)
}
pub(super) async fn read(state: &AppState, guard: &Guard<'_>) -> DomainResult<SafeSnapshot> {
    guard.validate().await?;
    let target = guard.target;
    let data = if target.mocked {
        let row = store::get::<MockRecord>(state, target.tenant, &mock_key(target))
            .await?
            .ok_or_else(|| DomainError::PreconditionFailed("此 Mock 来源尚未明确初始化固定示例".into()))?;
        decode_mock(state, target, &row)?
    } else {
        // Parent-owned admission hook must resolve the same serialized source entry and return only typed safe evidence.
        let observed = Box::pin(crate::cloud_runtime::execute_scheduler_observation(
            state,
            crate::cloud_runtime::SchedulerObservationInvocation {
                tenant: target.tenant,
                configuration_version: target.configuration_version,
                payload_fingerprint: &target.fingerprint,
                guard,
                deadline: guard.submission.deadline,
                scope: &target.native(),
            },
        ))
        .await?;
        SafeSnapshot::parse(target, serde_json::to_value(observed)?)?
    };
    guard.validate().await?;
    Ok(data)
}
