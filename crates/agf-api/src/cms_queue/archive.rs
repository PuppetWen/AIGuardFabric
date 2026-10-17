use super::{
    ATTEMPT, BODY, ITEM, REQUEST, audit,
    authority::Submission,
    codec,
    input::Archive,
    model::{Body, Item, Journal, Phase, Purpose, Request, Values},
    provider, records,
    store::{self, Mutation, Plan},
    util,
};
use crate::state::AppState;
use agf_core::{
    audit::AuditAction,
    error::{DomainError, DomainResult},
    time::Timestamp,
};

pub(super) async fn archive(state: &AppState, submission: &Submission, input: Archive) -> DomainResult<Request> {
    super::input::ids(input.request_id, &input.item_ids, 32)?;
    submission.authorize(state).await?;
    let tenant = submission.principal.tenant;
    let hash = util::fingerprint(&input)?;
    let request_key = util::key(REQUEST, input.request_id);
    if let Some(old) =
        super::authority::bounded(submission.deadline, store::get::<Request>(state, tenant, &request_key)).await?
    {
        records::request_identity(submission, &old, input.request_id, Purpose::Archive, &hash)?;
        return Ok(old);
    }
    let mut items = Vec::new();
    let mut keys = vec![util::state_key(tenant), request_key.clone()];
    for id in &input.item_ids {
        let item = super::authority::bounded(submission.deadline, records::load_item(state, tenant, *id)).await?;
        keys.extend([util::key(ITEM, *id), util::key(BODY, *id)]);
        if let Some(attempt) = item.attempts.last() {
            keys.push(util::key(ATTEMPT, *attempt));
        }
        items.push(item);
    }
    Box::pin(store::mutate(state,Mutation { submission,source:None,keys },|values| {
        if let Some(old)=records::replay(state,submission,values,input.request_id,Purpose::Archive,&hash)? { return Ok((old,None)); }
        let mut journal:Journal=codec::read(state,tenant,values,&util::state_key(tenant))?.unwrap_or_default();
        util::validate_journal(&journal,tenant)?;
        if journal.generation!=input.expected_generation { return Err(util::conflict()); }
        let mut changed=0; let mut writes=Values::new();
        for loaded in &items {
            let key=util::key(ITEM,loaded.id); let mut item:Item=codec::read(state,tenant,values,&key)?.ok_or_else(util::corrupt)?;
            records::item(&item,tenant,loaded.id)?; submission.own(&item.owner)?;
            if util::fingerprint(&item)?!=util::fingerprint(loaded)? { return Err(util::conflict()); }
            if item.archived_at.is_some() { continue; }
            let last=records::latest(state,tenant,values,&item)?;
            if last.as_ref().is_some_and(|attempt|attempt.phase!=Phase::Complete) {
                return Err(DomainError::PreconditionFailed("Locally settle the original active/expired delivery before archiving its body".into()));
            }
            let body:Body=codec::read(state,tenant,values,&util::key(BODY,item.id))?.ok_or_else(util::corrupt)?;
            provider::body(&body,&item)?;
            journal.stored_bytes=journal.stored_bytes.checked_sub(item.payload_bytes).ok_or_else(util::corrupt)?;
            journal.items.retain(|id|*id!=item.id); item.archived_at=Some(Timestamp::now());
            codec::put(state,tenant,&mut writes,key,&item)?; writes.insert(util::key(BODY,item.id),None); changed+=1;
        }
        // A new request UUID is a real local receipt write even when every selected item is already archived.
        util::bump(&mut journal,tenant,1)?;
        let row=Request { tenant,id:input.request_id,purpose:Purpose::Archive,input_hash:hash.clone(),owner:submission.owner(),
            item_ids:input.item_ids.clone(),attempt_ids:Vec::new(),submitted_at:submission.submitted_at,changed_count:changed,generation:journal.generation };
        codec::put(state,tenant,&mut writes,request_key,&row)?; codec::put(state,tenant,&mut writes,util::state_key(tenant),&journal)?;
        let audit=audit::change(submission,input.request_id,AuditAction::Create,"cms-queue-archive-request",
            serde_json::json!({"changedCount":changed,"generation":journal.generation,"providerContacted":false,"permanentDeliveryIdentitiesRetained":true}));
        Ok((row,Some(Plan { writes,audit:Box::new(audit) })))
    })).await
}
