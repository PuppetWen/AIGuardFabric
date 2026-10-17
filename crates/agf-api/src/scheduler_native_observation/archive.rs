use super::{
    authority::Submission,
    claim,
    input::ArchiveInput,
    records::{BodyRecord, Journal, Purpose, Values},
    store::{self, Mutation, Plan},
    util,
};
use crate::state::AppState;
use agf_core::{
    audit::{AuditAction, AuditOutcome},
    error::{DomainError, DomainResult},
    time::Timestamp,
};

pub(super) async fn archive(state: &AppState, submission: &Submission, input: ArchiveInput) -> DomainResult<Journal> {
    super::authority::bounded(submission.deadline, Box::pin(archive_inner(state, submission, input))).await
}
async fn archive_inner(state: &AppState, submission: &Submission, input: ArchiveInput) -> DomainResult<Journal> {
    input.validate()?;
    submission.authorize(state).await?;
    let tenant = submission.principal.tenant;
    let state_key = util::state_key(tenant);
    let prepared = store::journal(state, tenant).await?;
    if prepared.generation != input.expected_generation {
        return Err(util::stale());
    }
    // Immutable facts are read before the write transaction. Their identity and body summaries are never deleted.
    let mut facts = Vec::new();
    for id in &input.request_ids {
        let fact = claim::fact(state, tenant, *id).await?.ok_or_else(|| util::missing(*id))?;
        if fact.purpose != Purpose::Observe {
            return Err(DomainError::Validation("只能归档观察编号，不能归档本地关联动作".into()));
        }
        facts.push(fact);
    }
    let mut declared = vec![state_key.clone()];
    declared.extend(input.request_ids.iter().map(|id| util::body_key(tenant, *id)));
    store::mutate(state,Mutation {submission,source:None,main:state_key.clone(),declared},|snapshot| {
        let mut journal:Journal=util::read(snapshot,&state_key)?.unwrap_or_default();
        if (journal.generation,journal.version)!=(input.expected_generation,prepared.version) {return Err(util::stale());}
        let mut writes=Values::new(); let now=Timestamp::now(); let mut count=0_u64;
        for fact in &facts {
            let key=util::body_key(tenant,fact.request_id);
            let prior:Option<BodyRecord>=util::read(snapshot,&key)?;
            if let Some(BodyRecord::Archived {tenant:owner,request_id,archived_at,original_status})=&prior {
                if (*owner,*request_id)!=(tenant,fact.request_id) || *archived_at<fact.started_at
                    || !["observed","failed","interrupted"].contains(&original_status.as_str()) {return Err(util::corrupt());}
                continue;
            }
            // A permanent reading fact can be fenced only after its original lease has expired.
            // This does not prove a sent provider read stopped and never records Read success.
            if fact.status=="reading" && (fact.expires_at>now
                || journal.active.as_ref().is_some_and(|active|active.request_id==fact.request_id && active.expires_at>now)) {
                return Err(DomainError::Conflict("仍持有有效观察租约，不能归档或重新派发".into()));
            }
            if !journal.observations.contains(&fact.request_id) {return Err(util::corrupt());}
            match &prior {
                Some(BodyRecord::Content(_))=>{
                    if fact.status!="observed" || fact.body_bytes!=util::bound(prior.as_ref().ok_or_else(util::corrupt)?,4 * 1024 * 1024)? {return Err(util::corrupt());}
                    journal.stored_bytes=journal.stored_bytes.checked_sub(fact.body_bytes).ok_or_else(util::corrupt)?;
                }
                None if fact.body_bytes==0=>{},
                _=>return Err(util::corrupt()),
            }
            let original_status=if fact.status=="reading" {"interrupted"} else {fact.status.as_str()};
            if !["observed","failed","interrupted"].contains(&original_status) {return Err(util::corrupt());}
            util::put(&mut writes,key,&BodyRecord::Archived {tenant,request_id:fact.request_id,archived_at:now,original_status:original_status.into()})?;
            journal.observations.retain(|id|*id!=fact.request_id);
            if journal.active.as_ref().is_some_and(|active|active.request_id==fact.request_id) {journal.active=None;}
            count=count.checked_add(1).ok_or_else(util::capacity)?;
        }
        if count==0 {return Ok((journal,None));}
        journal.archived_count=journal.archived_count.checked_add(count).ok_or_else(util::capacity)?;
        store::bump(&mut journal,tenant)?; util::put(&mut writes,state_key,&journal)?;
        let mut audit=claim::audit(submission,util::main_id(tenant),"scheduler-native-archive",AuditAction::Configure,AuditOutcome::Success,"显式归档正文；保留永久编号，过期读取仅被本地隔离");
        audit.after=Some(serde_json::json!({"count":count,"requestIdsHash":util::canonical_hash(&serde_json::to_value(&input.request_ids)?)?}));
        Ok((journal,Some(Plan {writes,audit:Box::new(audit)})))
    }).await
}
