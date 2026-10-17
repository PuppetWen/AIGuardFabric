use super::super::{authority::Submission, scope, util};
use super::{
    baseline, codec,
    input::ApplyInput,
    model::{Active, Index, Operation, PreviewRecord, Purpose, State},
    mutation,
};
use crate::state::AppState;
use agf_alicloud::schedulerx3::managed_jobs::Readback;
use agf_core::{
    audit::{AuditAction, AuditOutcome},
    error::{DomainError, DomainResult},
    ids::Id,
    time::Timestamp,
};

pub(super) async fn take(
    state: &AppState,
    submission: &Submission,
    id: Id,
    input: ApplyInput,
) -> DomainResult<(Operation, bool)> {
    input.validate()?;
    if id.is_nil() {
        return Err(super::input::invalid());
    }
    submission.authorize(state).await?;
    let tenant = submission.principal.tenant;
    let actor = baseline::actor(submission)?;
    let hash = codec::hash(Purpose::Apply, &input)?;
    if let Some(index) = codec::load::<Index>(state, tenant, &codec::request_key(tenant, id)).await? {
        codec::index(&index, tenant, id, Purpose::Apply, actor, &hash)?;
        return Ok((super::views::load_operation(state, tenant, id).await?, false));
    }
    baseline::vacancy_external(state, tenant, id).await?;
    let target = scope::current(state, tenant).await?.ok_or_else(util::stale)?;
    if !target.mocked && state.store.database().is_none() {
        return Err(DomainError::PreconditionFailed("Live 受管修改必须使用持久数据库领取与加密结果恢复".into()));
    }
    if target.transport_mode == "live" && !input.confirm_live {
        return Err(super::input::invalid());
    }
    let preview_key = codec::key(tenant, input.preview_id, super::model::PREVIEW);
    let loaded = super::views::load_preview(state, tenant, input.preview_id).await?;
    let PreviewRecord::Content(loaded) = loaded else {
        return Err(util::stale());
    };
    let mut keys = baseline::native_keys(tenant, id);
    keys.extend([
        preview_key.clone(),
        codec::key(tenant, id, super::model::OPERATION),
        util::binding_key(tenant),
        util::fact_key(tenant, loaded.input.observation_id),
        util::body_key(tenant, loaded.input.observation_id),
    ]);
    if target.mocked {
        keys.push(super::mock::key(&target));
    }
    mutation::apply(state, mutation::options(submission, Some(&target), keys), |values| {
        if baseline::prior(state, values, tenant, id, Purpose::Apply, actor, &hash)? {
            let prior = codec::snapshot(state, tenant, values, &codec::key(tenant, id, super::model::OPERATION))?
                .ok_or_else(util::corrupt)?;
            codec::operation(&prior, tenant, id)?;
            return Ok(((prior, false), None));
        }
        let mut journal = mutation::journal(state, tenant, values)?;
        mutation::can_add(&journal, false)?;
        if journal.active.is_some() {
            return Err(DomainError::Conflict("原受管修改尚未本地结束；请读取并显式恢复原编号".into()));
        }
        let record: PreviewRecord = codec::snapshot(state, tenant, values, &preview_key)?.ok_or_else(util::stale)?;
        codec::preview_record(&record, tenant, input.preview_id)?;
        let PreviewRecord::Content(mut preview) = record else {
            return Err(util::stale());
        };
        let now = Timestamp::now();
        if preview.actor != actor
            || preview.target != target
            || preview.fingerprint != input.preview_fingerprint
            || preview.expires_at <= now
            || preview.operation_id.is_some()
        {
            return Err(util::stale());
        }
        if preview.input.observation_id != loaded.input.observation_id {
            return Err(util::corrupt());
        }
        let (baseline, _) = baseline::observed(state, values, &target, &preview.input)?;
        if baseline.fingerprint() != preview.baseline_fingerprint {
            return Err(util::stale());
        }
        if let Some(unknown) =
            journal.unknown.iter().find(|unknown| unknown.resource == super::model::RiskIdentity::of(&target))
        {
            let fact: super::super::records::Fact =
                util::read(values, &util::fact_key(tenant, preview.input.observation_id))?.ok_or_else(util::stale)?;
            if !input.confirm_unknown_overlap
                || now <= unknown.expires_at
                || fact.started_at <= unknown.expires_at
                || fact.finished_at.is_none_or(|at| at <= unknown.expires_at)
            {
                return Err(DomainError::PreconditionFailed(
                    "未知旧写入已本地恢复仍不证明远端停止；须租约后新观察与独立重叠风险确认".into(),
                ));
            }
        }
        let bindings: super::super::records::BindingRecord =
            util::read(values, &util::binding_key(tenant))?.unwrap_or_default();
        super::super::binding::validate(&bindings, tenant)?;
        super::super::proof::restore(state, &bindings, tenant)?;
        if bindings.version != preview.input.expected_binding_version {
            return Err(util::stale());
        }
        if target.mocked {
            let current = super::mock::snapshot(state, &target, values)?;
            if current.fingerprint() != preview.baseline_fingerprint {
                return Err(util::stale());
            }
        }
        let (action, kind) =
            super::plan::summary(&preview.input.change, preview.input.selection.as_ref().map(|s| s.kind))?;
        preview.operation_id = Some(id);
        let mut row = Operation {
            tenant,
            request_id: id,
            actor,
            claim_id: Id::new(),
            input_hash: hash.clone(),
            input: input.clone(),
            target: target.clone(),
            preview: Some(preview.clone()),
            started_at: now,
            submitted_at: submission.submitted_at,
            expires_at: now.offset_secs(120),
            finished_at: None,
            state: State::Started,
            write: None,
            readback: Readback::Unknown,
            job_id: preview.desired["id"].as_str().map(str::to_owned),
            action: action.into(),
            kind,
            readback_at: None,
            readback_fingerprint: None,
            archived_at: None,
            detail_bytes: 0,
        };
        let mut writes = super::super::records::Values::new();
        if target.mocked {
            return super::mock_commit::apply(
                state,
                submission,
                values,
                journal,
                preview_key,
                preview,
                row,
                &mut writes,
            );
        }
        journal.active = Some(Active {
            request_id: id,
            claim_id: row.claim_id,
            scope_id: target.scope_id,
            expires_at: row.expires_at,
        });
        journal.operations.push(id);
        let old = mutation::encoded_bytes(values, &preview_key)?;
        let bytes = mutation::put(state, tenant, &mut writes, preview_key, &PreviewRecord::Content(preview))?;
        mutation::account(&mut journal, old, bytes)?;
        mutation::operation(state, &mut writes, &mut row)?;
        mutation::account(&mut journal, 0, row.detail_bytes)?;
        mutation::put(
            state,
            tenant,
            &mut writes,
            codec::request_key(tenant, id),
            &Index { tenant, request_id: id, purpose: Purpose::Apply, actor, hash },
        )?;
        codec::operation(&row, tenant, id)?;
        let plan = mutation::finish(
            state,
            submission,
            &mut journal,
            writes,
            id,
            AuditAction::Create,
            AuditOutcome::Success,
            "永久领取单次受管修改；尚未发送，不代表云接受、云注册或回调启用",
        )?;
        Ok(((row, true), Some(plan)))
    })
    .await
}
