use super::super::{
    records::{MOCK, MockRecord, Values},
    safe::SafeSnapshot,
    scope::SourceTarget,
    store, util,
};
use super::model::Preview;
use crate::state::AppState;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
};
use serde_json::json;

pub(super) fn key(target: &SourceTarget) -> (String, Id) {
    (MOCK.into(), util::key_id(target.tenant, target.scope_id, MOCK))
}
fn decode(state: &AppState, target: &SourceTarget, row: &MockRecord) -> DomainResult<SafeSnapshot> {
    if !target.mocked || (row.tenant, row.scope_id) != (target.tenant, target.scope_id) {
        return Err(util::corrupt());
    }
    SafeSnapshot::parse(target, util::decrypt_json(state, target.tenant, key(target).1, &row.secret, &row.hash)?)
}
pub(super) async fn load(state: &AppState, target: &SourceTarget) -> DomainResult<SafeSnapshot> {
    let row = store::get(state, target.tenant, &key(target)).await?.ok_or_else(uninitialized)?;
    decode(state, target, &row)
}
pub(super) fn snapshot(state: &AppState, target: &SourceTarget, values: &Values) -> DomainResult<SafeSnapshot> {
    let row = util::read(values, &key(target))?.ok_or_else(uninitialized)?;
    decode(state, target, &row)
}
pub(super) fn change(
    state: &AppState,
    preview: &Preview,
    current: &SafeSnapshot,
) -> DomainResult<(MockRecord, SafeSnapshot)> {
    if !preview.target.mocked || current.app_id() != preview.app_id {
        return Err(util::stale());
    }
    if preview.baseline_fingerprint != current.fingerprint() {
        return Err(util::stale());
    }
    let mut value = current.value().clone();
    let jobs = value["jobs"].as_array_mut().ok_or_else(util::corrupt)?;
    let found = jobs.iter().position(|job| job["id"] == preview.desired["id"]);
    match (&preview.before, found) {
        (None, None) => jobs.push(preview.desired.clone()),
        (Some(before), Some(index)) if &jobs[index] == before => jobs[index] = preview.desired.clone(),
        _ => return Err(util::stale()),
    }
    jobs.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    let total = jobs.len();
    value["pagination"] = json!({"total":total,"listingComplete":true,"strongSnapshot":false,
        "pages":(0..total.div_ceil(100).max(1)).map(|page|json!({"number":page+1,"size":100,
            "records":(total-page*100).min(100),"requestId":format!("mock-managed-page-{}",page+1)})).collect::<Vec<_>>()});
    value["fingerprint"] = json!(util::canonical_hash(&json!({"scope":value["scope"],"app":value["app"],
        "jobs":value["jobs"],"total":total}))?);
    let data = SafeSnapshot::parse(&preview.target, value)?;
    let (secret, hash) = util::encrypt_json(state, preview.tenant, key(&preview.target).1, data.value())?;
    Ok((MockRecord { tenant: preview.tenant, scope_id: preview.target.scope_id, hash, secret }, data))
}
fn uninitialized() -> DomainError {
    DomainError::PreconditionFailed("先在原生观察页明确初始化此固定 Mock 来源；GET 不初始化".into())
}
