//! A real delayed HTTP read cannot resurrect content after the bounded observation index evicts it.
use crate::{common::*, transport::*};
use agf_core::{
    audit::{AuditAction, AuditOutcome},
    error::{DomainError, DomainResult},
    ids::{Id, deterministic_id},
};
use std::collections::BTreeSet;

async fn main_record(h: &Harness) -> DomainResult<Value> {
    let rows = h.state.configurations.list::<Value>(h.tenant, MAIN).await?;
    assert_eq!(rows.len(), 1);
    rows.into_iter().next().ok_or_else(|| DomainError::Internal("owned observation main missing".into()))
}

#[tokio::test]
async fn delayed_observation_evicted_by_nine_new_reads_keeps_no_orphan_content_or_budget() -> DomainResult<()> {
    let f = Fixture::attach(setup().await).await?;
    let old = Id::new();
    let input = json!({"request_id":old,"configuration_version":1,"confirm_live":false});
    let path = format!("{BASE}/observe");
    f.engine.hold("GET", 1).await;
    let pending = Pending::start(f.h.clone(), path.clone(), f.h.admin.clone(), input.clone());
    f.engine.waiting("GET", 1).await?;
    let mut new_ids = Vec::new();
    for _ in 0..9 {
        let observed = post(&f.h, &path, observe_input()).await?;
        new_ids.push(id(&observed, "id")?);
        assert_eq!(observed["usable"], true);
        assert_eq!(observed["contentBytes"], INITIAL.len());
    }
    assert_eq!(f.engine.counts().await, (10, 0));
    let before = main_record(&f.h).await?;
    let indexed: Vec<Id> = serde_json::from_value(before["observations"].clone())?;
    assert_eq!(indexed, new_ids[1..]);
    assert_eq!(indexed.len(), 8);
    assert!(!indexed.contains(&old));
    assert_eq!(before["latest_observation"], json!(new_ids[8]));
    let details_before = f.h.state.configurations.list::<Value>(f.h.tenant, DETAIL).await?;
    assert_eq!(details_before.len(), 8);
    assert!(audits(&f.h, old, "mse-config-observation").await?.is_empty());

    f.engine.release();
    let failed = pending.finish().await?;
    assert_eq!(failed.status, StatusCode::CONFLICT);
    let after = main_record(&f.h).await?;
    for field in ["observations", "latest_observation", "stored_content_bytes", "previews", "operations"] {
        assert_eq!(after[field], before[field], "a delayed read changed {field}");
    }
    let mut details = f.h.state.configurations.list::<Value>(f.h.tenant, DETAIL).await?;
    let detail_ids: BTreeSet<Id> = details.iter().map(|row| id(row, "request_id")).collect::<DomainResult<_>>()?;
    assert_eq!(detail_ids, indexed.iter().copied().collect());
    assert_eq!(details.len(), 8);
    let mut originals = details_before;
    originals.sort_by_key(Value::to_string);
    details.sort_by_key(Value::to_string);
    assert_eq!(details, originals, "late completion must not replace any indexed ciphertext");
    let orphan_id =
        deterministic_id("agf.mse.config-publication.content", &format!("{}:{old}:observation", f.h.tenant));
    assert!(f.h.state.configurations.get::<Value>(f.h.tenant, DETAIL, orphan_id).await?.is_none());
    let previews = f.h.state.configurations.list::<Value>(f.h.tenant, "mse-config-publication-preview").await?;
    assert!(previews.is_empty());
    let indexed_bytes = details
        .iter()
        .chain(&previews)
        .try_fold(0_u64, |sum, row| Ok::<_, serde_json::Error>(sum + serde_json::to_vec(row)?.len() as u64))?;
    assert_eq!(number(&after, "stored_content_bytes")?, indexed_bytes);

    let facts = f.h.state.configurations.list::<Value>(f.h.tenant, FACT).await?;
    assert_eq!(facts.len(), 10, "bounded content must not evict permanent request claims");
    for row in &facts {
        let request = id(row, "request_id")?;
        assert_eq!(row["purpose"], "observation");
        assert_eq!(row["outcome"]["type"], "reading");
        assert!(row["outcome"]["finished_at"].is_string());
        assert_eq!(row["outcome"]["failed"], request == old);
        assert!(request == old || new_ids.contains(&request));
    }
    let failure_audit = audits(&f.h, old, "mse-config-observation").await?;
    assert_eq!(failure_audit.len(), 1);
    assert_eq!(failure_audit[0].action, AuditAction::Read);
    assert_eq!(failure_audit[0].outcome, AuditOutcome::Failure);
    let evidence = failure_audit[0]
        .after
        .as_ref()
        .ok_or_else(|| DomainError::Internal("missing safe eviction evidence".into()))?;
    assert_eq!(evidence["observed"], false);
    assert_eq!(evidence["evicted"], true);
    let committed = snapshot(&f.h).await?;
    let state = read(&f.h, BASE).await?;
    assert_eq!(state["observation"]["id"], json!(new_ids[8]));
    assert_eq!(state["observation"]["usable"], true);
    assert_eq!(f.h.post(&path, input).await.status, StatusCode::CONFLICT);
    assert_eq!(snapshot(&f.h).await?, committed);
    assert_eq!(f.engine.counts().await, (10, 0));
    assert!(f.h.state.store.audit_verify_durable(f.h.tenant).await?.passed);
    Ok(())
}
