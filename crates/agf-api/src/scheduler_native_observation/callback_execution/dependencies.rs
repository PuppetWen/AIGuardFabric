use super::super::{
    records::{BindingRecord, Values},
    scope::SourceTarget,
    util,
};
use super::{
    current, identity,
    model::{Batch, Progress},
};
use crate::state::AppState;
use agf_alicloud::schedulerx3::SchedulerX3Job;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::TenantId,
    time::Timestamp,
};

pub(super) fn kinds(tenant: TenantId, kind: &str) -> DomainResult<Vec<String>> {
    let defaults = SchedulerX3Job::platform_defaults(tenant);
    let job = defaults.iter().find(|job| job.job_kind == kind).ok_or_else(current::unqualified)?;
    job.depends_on
        .iter()
        .map(|id| defaults.iter().find(|job| job.id == *id).map(|job| job.job_kind.clone()).ok_or_else(util::corrupt))
        .collect()
}
pub(super) fn check(
    state: &AppState,
    snapshot: &Values,
    binding: &BindingRecord,
    target: &SourceTarget,
    kind: &str,
) -> DomainResult<()> {
    for upstream in kinds(target.tenant, kind)? {
        let assignment = binding.items.iter().find(|item| item.kind == upstream).ok_or_else(incomplete)?;
        let app = binding.app_id.as_deref().ok_or_else(incomplete)?;
        let adoption = current::mapping(state, binding, target.tenant, target, &upstream, app, &assignment.job_id)?;
        let progress: Progress =
            util::read(snapshot, &identity::progress_key(target.tenant, &upstream))?.ok_or_else(incomplete)?;
        validate_progress(state, &progress, target.tenant, &upstream)?;
        let context = &progress.batch.context;
        if context.target != *target
            || (context.app_id.as_str(), context.job_id.as_str(), context.adoption_version)
                != (app, assignment.job_id.as_str(), adoption)
            || !complete(&progress.batch, Timestamp::now())
        {
            return Err(incomplete());
        }
    }
    Ok(())
}
pub(super) fn validate_progress(state: &AppState, row: &Progress, tenant: TenantId, kind: &str) -> DomainResult<()> {
    row.batch.validate(tenant)?;
    if row.tenant != tenant || row.kind != kind || row.batch.context.kind != kind {
        return Err(util::corrupt());
    }
    super::evidence::verify(state, row)?;
    Ok(())
}
pub(super) fn complete(row: &Batch, now: Timestamp) -> bool {
    row.partitions.len() == usize::from(row.context.partition_total)
        && (0..row.context.partition_total).all(|index| {
            row.partitions.get(&index).is_some_and(|partition| {
                partition.terminal.as_ref().is_some_and(|result| {
                    result.ok
                        && !result.skipped
                        && result.finished_at <= now
                        && result.finished_at >= now.offset_secs(-86_400)
                })
            })
        })
}
fn incomplete() -> DomainError {
    DomainError::PreconditionFailed("上游最新批次必须来自当前可信映射，并在24小时内全部分片明确成功且未跳过".into())
}
