use super::super::{authority::Submission, records::Values, util};
use super::{
    codec,
    input::ArchiveInput,
    model::{ArchivedPreview, Index, Operation, PreviewRecord, Purpose, State},
    mutation,
};
use crate::state::AppState;
use agf_core::{
    audit::{AuditAction, AuditOutcome},
    error::{DomainError, DomainResult},
    ids::TenantId,
    time::Timestamp,
};
use std::collections::BTreeMap;

pub(super) async fn archive(
    state: &AppState,
    submission: &Submission,
    input: ArchiveInput,
) -> DomainResult<super::model::Journal> {
    input.validate()?;
    submission.authorize(state).await?;
    let tenant = submission.principal.tenant;
    let prepared = codec::journal(state, tenant).await?;
    if prepared.generation != input.expected_generation {
        return Err(util::stale());
    }
    let mut entries = BTreeMap::new();
    let mut keys = Vec::new();
    for id in &input.request_ids {
        let index: Index =
            codec::load(state, tenant, &codec::request_key(tenant, *id)).await?.ok_or_else(|| util::missing(*id))?;
        if index.tenant != tenant || index.request_id != *id || index.actor.is_nil() || !util::digest(&index.hash) {
            return Err(util::corrupt());
        }
        match index.purpose {
            Purpose::Preview => {
                keys.push(codec::key(tenant, *id, super::model::PREVIEW));
                entries.insert(*id, (Purpose::Preview, None));
            }
            Purpose::Apply => {
                let row = super::views::load_operation(state, tenant, *id).await?;
                keys.push(codec::key(tenant, *id, super::model::OPERATION));
                let preview = row.input.preview_id;
                keys.push(codec::key(tenant, preview, super::model::PREVIEW));
                entries.insert(*id, (Purpose::Apply, Some(preview)));
            }
        }
    }
    mutation::apply(state, mutation::options(submission, None, keys), |values| {
        let mut journal = mutation::journal(state, tenant, values)?;
        if (journal.generation, journal.version) != (input.expected_generation, prepared.version) {
            return Err(util::stale());
        }
        let mut writes = Values::new();
        let now = Timestamp::now();
        let mut count = 0_u64;
        for (id, (purpose, preview_id)) in entries {
            match purpose {
                Purpose::Preview => {
                    let key = codec::key(tenant, id, super::model::PREVIEW);
                    let record: PreviewRecord =
                        codec::snapshot(state, tenant, values, &key)?.ok_or_else(util::corrupt)?;
                    codec::preview_record(&record, tenant, id)?;
                    if let PreviewRecord::Content(row) = record {
                        if row.operation_id.is_some() || row.expires_at > now {
                            return Err(unavailable());
                        }
                        retire_preview(state, tenant, values, &mut writes, &mut journal, *row, now)?;
                        count = count.checked_add(1).ok_or_else(util::capacity)?;
                    }
                }
                Purpose::Apply => {
                    let key = codec::key(tenant, id, super::model::OPERATION);
                    let mut row: Operation = codec::snapshot(state, tenant, values, &key)?.ok_or_else(util::corrupt)?;
                    codec::operation(&row, tenant, id)?;
                    if row.archived_at.is_some() {
                        continue;
                    }
                    if row.state != State::Complete || journal.active.as_ref().is_some_and(|a| a.request_id == id) {
                        return Err(unavailable());
                    }
                    let preview_id = preview_id.ok_or_else(util::corrupt)?;
                    let preview_key = codec::key(tenant, preview_id, super::model::PREVIEW);
                    let record: PreviewRecord =
                        codec::snapshot(state, tenant, values, &preview_key)?.ok_or_else(util::corrupt)?;
                    codec::preview_record(&record, tenant, preview_id)?;
                    if let PreviewRecord::Content(preview) = record {
                        if preview.operation_id != Some(id) {
                            return Err(util::corrupt());
                        }
                        retire_preview(state, tenant, values, &mut writes, &mut journal, *preview, now)?;
                    }
                    let old = row.detail_bytes;
                    row.preview = None;
                    row.archived_at = Some(now);
                    mutation::operation(state, &mut writes, &mut row)?;
                    mutation::account(&mut journal, old, 0)?;
                    journal.operations.retain(|item| *item != id);
                    codec::operation(&row, tenant, id)?;
                    count = count.checked_add(1).ok_or_else(util::capacity)?;
                }
            }
        }
        if count == 0 {
            return Ok((journal, None));
        }
        journal.archived_count = journal.archived_count.checked_add(count).ok_or_else(util::capacity)?;
        let plan = mutation::finish(
            state,
            submission,
            &mut journal,
            writes,
            util::main_id(tenant),
            AuditAction::Configure,
            AuditOutcome::Success,
            "明确释放受管预览详细正文；永久 UUID/原结果/Unknown 围栏保留，不删除任务或启用回调",
        )?;
        Ok((journal, Some(plan)))
    })
    .await
}
fn retire_preview(
    state: &AppState,
    tenant: TenantId,
    values: &Values,
    writes: &mut Values,
    journal: &mut super::model::Journal,
    row: super::model::Preview,
    at: Timestamp,
) -> DomainResult<()> {
    let key = codec::key(tenant, row.id, super::model::PREVIEW);
    let old = mutation::encoded_bytes(values, &key)?;
    mutation::put(
        state,
        tenant,
        writes,
        key,
        &PreviewRecord::Archived(Box::new(ArchivedPreview {
            tenant,
            id: row.id,
            actor: row.actor,
            input_hash: row.input_hash,
            target: row.target,
            fingerprint: row.fingerprint,
            created_at: row.created_at,
            archived_at: at,
            operation_id: row.operation_id,
        })),
    )?;
    mutation::account(journal, old, 0)?;
    journal.previews.retain(|id| *id != row.id);
    Ok(())
}
fn unavailable() -> DomainError {
    DomainError::PreconditionFailed("只可归档已终态非 active 操作，或过期且未使用的预览".into())
}
