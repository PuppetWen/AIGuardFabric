use super::super::util;
use super::{
    input::{AdmissionInput, Outcome},
    model,
};
use agf_core::{
    error::DomainResult,
    ids::{Id, TenantId, deterministic_id},
};
use serde_json::json;

pub(super) type Key = (String, Id);
pub(super) fn batch(tenant: TenantId, input: &AdmissionInput) -> DomainResult<Id> {
    Ok(deterministic_id(
        "agf.scheduler.callback.batch.v1",
        &util::canonical_hash(&json!([tenant, input.app_id, input.job_id, input.job_execution_id]))?,
    ))
}
pub(super) fn fact(tenant: TenantId, input: &AdmissionInput) -> DomainResult<Id> {
    Ok(deterministic_id(
        "agf.scheduler.callback.fact.v1",
        &util::canonical_hash(&json!([
            tenant,
            input.app_id,
            input.job_id,
            input.job_execution_id,
            input.partition_index
        ]))?,
    ))
}
pub(super) fn input_hash(input: &AdmissionInput) -> DomainResult<String> {
    // Request UUID is an index; another UUID cannot mint another global execution.
    util::canonical_hash(&json!({"purpose":"callback-admission","kind":input.kind,
        "app":input.app_id,"job":input.job_id,"execution":input.job_execution_id,
        "index":input.partition_index,"total":input.partition_total,
        "binding":input.binding_version,"configuration":input.configuration_version,
        "source":input.source_fingerprint}))
}
pub(super) fn outcome_hash(outcome: &Outcome) -> DomainResult<String> {
    util::canonical_hash(&serde_json::to_value(outcome)?)
}
pub(super) fn fact_key(id: Id) -> Key {
    (model::EXECUTION.into(), id)
}
pub(super) fn batch_key(id: Id) -> Key {
    (model::BATCH.into(), id)
}
pub(super) fn pending_key(id: Id) -> Key {
    (model::PENDING.into(), deterministic_id("agf.scheduler.callback.pending.v1", &id.to_string()))
}
pub(super) fn request_key(tenant: TenantId, id: Id) -> Key {
    (model::REQUEST.into(), deterministic_id("agf.scheduler.callback.request.v1", &format!("{tenant}:{id}")))
}
pub(super) fn progress_key(tenant: TenantId, kind: &str) -> Key {
    (model::PROGRESS.into(), deterministic_id("agf.scheduler.callback.progress.v1", &format!("{tenant}:{kind}")))
}
