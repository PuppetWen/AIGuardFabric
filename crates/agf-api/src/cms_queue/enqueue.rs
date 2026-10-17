use super::{
    BODY, ITEM, REQUEST, audit,
    authority::Submission,
    codec,
    input::Enqueue,
    model::{Body, Item, Journal, MockRecord, Purpose, Request, Values},
    records, source,
    store::{self, Mutation, Plan},
    util,
};
use crate::state::AppState;
use agf_core::{
    audit::AuditAction,
    error::{DomainError, DomainResult},
};

pub(super) async fn enqueue(state: &AppState, submission: &Submission, input: Enqueue) -> DomainResult<Request> {
    if input.request_id.is_nil() || input.items.is_empty() || input.items.len() > 20 {
        return Err(util::invalid());
    }
    for payload in &input.items {
        payload.validate()?;
    }
    let tenant = submission.principal.tenant;
    let hash = util::fingerprint(&input)?;
    let request_key = util::key(REQUEST, input.request_id);
    // Replay is independent of current source availability and never initializes a provider fixture.
    submission.authorize(state).await?;
    if let Some(row) =
        super::authority::bounded(submission.deadline, store::get::<Request>(state, tenant, &request_key)).await?
    {
        records::request_identity(submission, &row, input.request_id, Purpose::Enqueue, &hash)?;
        return Ok(row);
    }
    let source = source::current(state, submission, input.configuration_version).await?;
    if input.initialize_mock_fixture
        && (source.mode != "mock" || source.region != "cn-hangzhou" || source.group != "agf-cms-demo")
    {
        return Err(DomainError::PreconditionFailed(
            "CMS fixture initialization requires the explicit owned Mock group agf-cms-demo in cn-hangzhou".into(),
        ));
    }
    let ids = (0..input.items.len())
        .map(|i| util::derived(tenant, input.request_id, i, "agf.cms.queue.item.v1"))
        .collect::<Vec<_>>();
    let mock_key = super::provider::mock_key(&source);
    let mut keys = vec![util::state_key(tenant), request_key.clone()];
    for id in &ids {
        keys.push(util::key(ITEM, *id));
        keys.push(util::key(BODY, *id));
    }
    if input.initialize_mock_fixture {
        keys.push(mock_key.clone());
    }
    Box::pin(store::mutate(state,Mutation { submission,source:Some(&source),keys },|snapshot| {
        if let Some(row) = records::replay(state,submission,snapshot,input.request_id,Purpose::Enqueue,&hash)? { return Ok((row,None)); }
        let mut journal: Journal = codec::read(state,tenant,snapshot,&util::state_key(tenant))?.unwrap_or_default();
        util::validate_journal(&journal,tenant)?;
        if journal.generation != input.expected_generation { return Err(util::conflict()); }
        if journal.items.len()+ids.len() > super::MAX_ITEMS { return Err(util::capacity()); }
        let mut writes = Values::new();
        for (id,payload) in ids.iter().zip(&input.items) {
            if snapshot.get(&util::key(ITEM,*id)).and_then(Option::as_ref).is_some() { return Err(util::corrupt()); }
            let bytes = util::bound(payload,super::MAX_BODY)? as u64;
            journal.stored_bytes = journal.stored_bytes.checked_add(bytes).ok_or_else(util::capacity)?;
            let item = Item { tenant,id:*id,enqueue_id:input.request_id,owner:submission.owner(),source:source.clone(),
                name:payload.name().into(),action:payload.action().into(),payload_hash:util::fingerprint(payload)?,payload_bytes:bytes,
                queued_at:submission.submitted_at,attempts:Vec::new(),archived_at:None };
            records::item(&item,tenant,*id)?;
            codec::put(state,tenant,&mut writes,util::key(ITEM,*id),&item)?;
            codec::put(state,tenant,&mut writes,util::key(BODY,*id),&Body { tenant,item_id:*id,payload:payload.clone() })?;
            journal.items.push(*id);
        }
        if input.initialize_mock_fixture {
            if let Some(existing) = codec::read::<MockRecord>(state,tenant,snapshot,&mock_key)? { super::provider::validate_mock(&source,&existing)?; }
            else { codec::put(state,tenant,&mut writes,mock_key.clone(),&MockRecord { tenant:Some(tenant),source_id:Some(source.id),source_hash:source.fingerprint.clone(),accepted:std::collections::BTreeMap::new() })?; }
        }
        util::bump(&mut journal,tenant,1+ids.len() as u64)?;
        let row = Request { tenant,id:input.request_id,purpose:Purpose::Enqueue,input_hash:hash.clone(),owner:submission.owner(),
            item_ids:ids.clone(),attempt_ids:Vec::new(),submitted_at:submission.submitted_at,generation:journal.generation,changed_count:ids.len() as u64 };
        codec::put(state,tenant,&mut writes,request_key.clone(),&row)?;
        codec::put(state,tenant,&mut writes,util::state_key(tenant),&journal)?;
        let audit = audit::change(submission,input.request_id,AuditAction::Create,REQUEST,serde_json::json!({"purpose":"enqueue","items":ids.len(),"mockFixtureInitialized":input.initialize_mock_fixture,"providerContacted":false}));
        Ok((row,Some(Plan { writes,audit:Box::new(audit) })))
    })).await
}
