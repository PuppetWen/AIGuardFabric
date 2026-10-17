//! One declared detail key per requested UUID permits an atomic 100-record archive without deleting claims.
use super::{
    audit,
    authority::Submission,
    input::ArchiveInput,
    operations,
    records::{ArchiveMarker, DETAIL, DetailRecord, PublicationStatus, Status, Values},
    sql::key,
    store::{self, Decision, Mutation},
    util,
};
use crate::state::AppState;
use agf_core::{
    audit::AuditAction,
    error::{DomainError, DomainResult},
    time::Timestamp,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub(super) async fn archive(state: &AppState, submission: &Submission, input: ArchiveInput) -> DomainResult<Value> {
    let input = input.normalize()?;
    submission.authorize(state).await?;
    let tenant = submission.principal.tenant;
    let mut facts = BTreeMap::new();
    for id in &input.request_ids {
        let fact = operations::load(state, tenant, *id)
            .await?
            .ok_or_else(|| DomainError::NotFound { entity: "apig-publication-operation", id: id.to_string() })?;
        let receipt = operations::receipt(&fact)?;
        if receipt.local_publication != PublicationStatus::Published
            || receipt.finished_at.is_none()
            || matches!(receipt.status, Status::Started | Status::Archived)
        {
            return Err(DomainError::PreconditionFailed(
                "归档仅接受已原子发布终态的操作；过期租约不能冒充终态，先显式恢复本地事实".into(),
            ));
        }
        facts.insert(*id, fact);
    }
    let related =
        input.request_ids.iter().map(|id| key(DETAIL, operations::record_id(tenant, *id))).collect::<Vec<_>>();
    let mut archived = Vec::new();
    let main = store::mutate(
        state,
        Mutation { submission, scope: None, selection: None, fence: None, source: &[], related: &related },
        |main, snapshot| {
            if main.generation != input.expected_generation {
                return Err(util::stale());
            }
            let mut writes = Values::new();
            for id in &input.request_ids {
                if main.active.as_ref().is_some_and(|active| active.request_id == *id) {
                    return Err(util::stale());
                }
                let record: DetailRecord = util::read(&snapshot.related, DETAIL, operations::record_id(tenant, *id))?
                    .ok_or_else(util::corrupt)?;
                match record {
                    DetailRecord::Archived { marker } => {
                        let receipt = operations::receipt(facts.get(id).ok_or_else(util::corrupt)?)?;
                        let finished_at = receipt.finished_at.ok_or_else(util::corrupt)?;
                        if (marker.tenant, marker.request_id) != (tenant, *id)
                            || marker.original_status != receipt.status
                            || marker.archived_at < finished_at
                            || marker.archived_at > Timestamp::now().offset_secs(5)
                        {
                            return Err(util::corrupt());
                        }
                    }
                    DetailRecord::Content { data } => {
                        if (data.tenant, data.request_id) != (tenant, *id) {
                            return Err(util::corrupt());
                        }
                        super::preview::validate_content(state, tenant, &data.prepared)?;
                        let receipt = operations::receipt(facts.get(id).ok_or_else(util::corrupt)?)?;
                        let marker = ArchiveMarker {
                            tenant,
                            request_id: *id,
                            archived_at: Timestamp::now(),
                            original_status: receipt.status,
                        };
                        util::put(
                            &mut writes,
                            DETAIL,
                            operations::record_id(tenant, *id),
                            &DetailRecord::Archived { marker },
                        )?;
                        main.operations.retain(|known| known != id);
                        archived.push(*id);
                    }
                }
            }
            if archived.is_empty() {
                return Ok(Decision::Unchanged);
            }
            main.archived_count = main
                .archived_count
                .checked_add(u64::try_from(archived.len()).map_err(|_| util::capacity())?)
                .ok_or_else(util::capacity)?;
            util::bump(main)?;
            let audit = audit::entry(
                submission,
                util::main_id(tenant),
                "apig-policy-publication-archive",
                AuditAction::Update,
                json!({"archivedRequestIds":archived,"generation":main.generation,"rollbackBodiesRemoved":true}),
            );
            Ok(Decision::Write { related: writes, audit: Box::new(audit) })
        },
    )
    .await?;
    Ok(
        json!({"generation":main.generation,"archivedCount":main.archived_count,"archivedRequestIds":archived,"unchanged":archived.is_empty()}),
    )
}
