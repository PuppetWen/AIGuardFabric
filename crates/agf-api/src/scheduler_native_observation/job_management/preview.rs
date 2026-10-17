use super::super::{authority::Submission, scope, util};
use super::{
    baseline, codec,
    input::PreviewInput,
    model::{Index, Preview, PreviewRecord, Purpose},
    mutation, plan,
};
use crate::state::AppState;
use agf_core::{
    audit::{AuditAction, AuditOutcome},
    error::DomainResult,
    time::Timestamp,
};
use serde_json::json;

pub(super) async fn create(
    state: &AppState,
    submission: &Submission,
    input: PreviewInput,
) -> DomainResult<PreviewRecord> {
    input.validate()?;
    submission.authorize(state).await?;
    let tenant = submission.principal.tenant;
    let actor = baseline::actor(submission)?;
    let hash = codec::hash(Purpose::Preview, &input)?;
    let key = codec::key(tenant, input.request_id, super::model::PREVIEW);
    if let Some(index) = codec::load::<Index>(state, tenant, &codec::request_key(tenant, input.request_id)).await? {
        codec::index(&index, tenant, input.request_id, Purpose::Preview, actor, &hash)?;
        return super::views::load_preview(state, tenant, input.request_id).await;
    }
    baseline::vacancy_external(state, tenant, input.request_id).await?;
    let target = scope::current(state, tenant).await?.ok_or_else(util::stale)?;
    if input.configuration_version != target.configuration_version {
        return Err(util::stale());
    }
    let mut keys = baseline::native_keys(tenant, input.request_id);
    keys.extend([
        key.clone(),
        util::binding_key(tenant),
        util::fact_key(tenant, input.observation_id),
        util::body_key(tenant, input.observation_id),
    ]);
    if target.mocked {
        keys.push(super::mock::key(&target));
    }
    mutation::apply(state, mutation::options(submission, Some(&target), keys), |values| {
        if baseline::prior(state, values, tenant, input.request_id, Purpose::Preview, actor, &hash)? {
            let record = codec::snapshot(state, tenant, values, &key)?.ok_or_else(util::corrupt)?;
            codec::preview_record(&record, tenant, input.request_id)?;
            return Ok((record, None));
        }
        let mut journal = mutation::journal(state, tenant, values)?;
        mutation::can_add(&journal, true)?;
        let (data, _) = baseline::observed(state, values, &target, &input)?;
        if target.mocked && super::mock::snapshot(state, &target, values)?.fingerprint() != data.fingerprint() {
            return Err(util::stale());
        }
        let (before, desired) = plan::desired(&input, &data, &journal, target.scope_id, target.mocked)?;
        let now = Timestamp::now();
        let mut row = Preview {
            tenant,
            id: input.request_id,
            actor,
            input_hash: hash.clone(),
            input: input.clone(),
            target: target.clone(),
            created_at: now,
            expires_at: now.offset_secs(120),
            app_id: data.app_id().into(),
            baseline_fingerprint: data.fingerprint().into(),
            before,
            desired,
            fingerprint: String::new(),
            operation_id: None,
            archived_at: None,
        };
        row.fingerprint = util::canonical_hash(&json!({"domain":"agf.scheduler.managed.preview.v1","tenant":tenant,
            "id":row.id,"actor":actor,"inputHash":hash,"target":target,"before":row.before,"desired":row.desired,
            "baselineFingerprint":row.baseline_fingerprint,"expiresAt":row.expires_at}))?;
        codec::preview(&row, tenant, row.id)?;
        let record = PreviewRecord::Content(Box::new(row));
        let mut writes = super::super::records::Values::new();
        let bytes = mutation::put(state, tenant, &mut writes, key, &record)?;
        mutation::put(
            state,
            tenant,
            &mut writes,
            codec::request_key(tenant, input.request_id),
            &Index { tenant, request_id: input.request_id, purpose: Purpose::Preview, actor, hash },
        )?;
        journal.previews.push(input.request_id);
        mutation::account(&mut journal, 0, bytes)?;
        let plan = mutation::finish(
            state,
            submission,
            &mut journal,
            writes,
            input.request_id,
            AuditAction::Read,
            AuditOutcome::Success,
            "创建有时限的受管任务差异预览；没有 provider 写入、注册或 Callback 授权",
        )?;
        Ok((record, Some(plan)))
    })
    .await
}
