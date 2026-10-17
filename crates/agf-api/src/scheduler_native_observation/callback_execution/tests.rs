use super::tests_support as support;
use super::{
    dependencies, identity,
    input::{AdmissionInput, CompleteInput, Outcome},
    model::State,
    views,
};
use agf_core::{
    error::DomainResult,
    ids::{Id, TenantId},
    time::Timestamp,
};
use serde_json::json;

#[test]
fn global_identity_excludes_revision_kind_and_request_but_checks_their_hash() -> DomainResult<()> {
    let tenant = TenantId::default_tenant();
    let original = support::input()?;
    let mut changed = original.clone();
    changed.request_id = Id::new();
    assert_eq!(identity::input_hash(&changed)?, identity::input_hash(&original)?);
    changed.kind = "report".into();
    changed.binding_version += 1;
    changed.configuration_version += 1;
    changed.source_fingerprint = "1".repeat(64);
    assert_eq!(identity::fact(tenant, &changed)?, identity::fact(tenant, &original)?);
    assert_eq!(identity::batch(tenant, &changed)?, identity::batch(tenant, &original)?);
    assert_ne!(identity::input_hash(&changed)?, identity::input_hash(&original)?);
    changed.partition_index = 1;
    assert_ne!(identity::fact(tenant, &changed)?, identity::fact(tenant, &original)?);
    assert_eq!(identity::batch(tenant, &changed)?, identity::batch(tenant, &original)?);
    assert_ne!(identity::fact(support::other_tenant(), &original)?, identity::fact(tenant, &original)?);
    changed.job_execution_id = "another:run".into();
    assert_ne!(identity::batch(tenant, &changed)?, identity::batch(tenant, &original)?);
    Ok(())
}

#[test]
fn canonical_integer_ids_and_partition_bounds_are_not_lossy() -> DomainResult<()> {
    let input = support::input()?;
    input.validate()?;
    for bad in ["0", "01", "+1", "-1", "9223372036854775808", "1.0"] {
        let mut changed = input.clone();
        changed.app_id = bad.into();
        assert!(changed.validate().is_err());
    }
    let mut edge = input.clone();
    edge.job_id = i64::MAX.to_string();
    edge.partition_total = 256;
    edge.partition_index = 255;
    edge.validate()?;
    edge.partition_index = 256;
    assert!(edge.validate().is_err());
    edge.partition_index = 0;
    edge.partition_total = 0;
    assert!(edge.validate().is_err());
    for bad in [" leading", "trailing ", "with\nnewline", "路径", "query?x", "slash/value"] {
        let mut changed = input.clone();
        changed.job_execution_id = bad.into();
        assert!(changed.validate().is_err());
    }
    Ok(())
}

#[test]
fn strict_bodies_do_not_accept_raw_secrets_paths_or_negative_artifact_bytes() -> DomainResult<()> {
    let mut claim = serde_json::to_value(support::input()?)?;
    claim["callback_bearer"] = json!("never accepted");
    assert!(serde_json::from_value::<AdmissionInput>(claim).is_err());
    let mut value = serde_json::to_value(support::outcome())?;
    value["artifacts"][0]["path"] = json!("not a digest");
    assert!(serde_json::from_value::<Outcome>(value).is_err());
    let value = json!({"claim_id":Id::new(),"outcome":{"ok":true,"skipped":false,"degraded":false,
        "artifacts":[{"sha256":"0".repeat(64),"bytes":-1}]}});
    assert!(serde_json::from_value::<CompleteInput>(value).is_err());
    Ok(())
}

#[test]
fn skipped_and_large_outcomes_are_bounded_before_staging() {
    let mut value = support::outcome();
    value.skipped = true;
    assert!(value.validate().is_err());
    value.skipped = false;
    value.artifacts = vec![value.artifacts[0].clone(); 65];
    assert!(value.validate().is_err());
    value.artifacts.truncate(64);
    assert!(value.validate().is_ok());
    value.artifacts[0].sha256 = "A".repeat(64);
    assert!(value.validate().is_err());
}

#[test]
fn dependency_graph_uses_the_actual_six_platform_jobs() -> DomainResult<()> {
    let tenant = TenantId::default_tenant();
    for root in ["asset-inventory", "rule-hot-reload"] {
        assert!(dependencies::kinds(tenant, root)?.is_empty());
    }
    assert_eq!(dependencies::kinds(tenant, "log-pull")?, vec!["asset-inventory"]);
    assert_eq!(dependencies::kinds(tenant, "redteam-cruise")?, vec!["asset-inventory"]);
    assert_eq!(dependencies::kinds(tenant, "report")?, vec!["asset-inventory", "log-pull"]);
    assert_eq!(dependencies::kinds(tenant, "archive")?, vec!["report"]);
    assert!(dependencies::kinds(tenant, "report-generate").is_err());
    Ok(())
}

#[test]
fn latest_dependencies_require_every_partition_recent_ok_and_not_skipped() -> DomainResult<()> {
    let now = Timestamp::now();
    let batch = support::batch(3, now.offset_secs(-1))?;
    batch.validate(batch.context.tenant)?;
    assert!(dependencies::complete(&batch, now));
    let mut partial = batch.clone();
    partial.partitions.remove(&1);
    assert!(!dependencies::complete(&partial, now));
    for (ok, skipped) in [(false, false), (true, true)] {
        let mut changed = batch.clone();
        let item = changed.partitions.get_mut(&1).ok_or_else(super::super::util::corrupt)?;
        let result = item.terminal.as_mut().ok_or_else(super::super::util::corrupt)?;
        result.ok = ok;
        result.skipped = skipped;
        assert!(!dependencies::complete(&changed, now));
    }
    assert!(!dependencies::complete(&support::batch(3, now.offset_secs(-86_401))?, now));
    assert!(!dependencies::complete(&support::batch(3, now.offset_secs(1))?, now));
    Ok(())
}

#[test]
fn expiry_is_a_read_projection_and_never_renews_or_changes_the_fact() -> DomainResult<()> {
    let mut fact = support::running()?;
    let before = serde_json::to_value(&fact)?;
    let expiry = fact.execution_expires_at.ok_or_else(super::super::util::corrupt)?;
    assert_eq!(views::state(&fact, expiry), "uncertain");
    assert_eq!(serde_json::to_value(&fact)?, before);
    fact.state = State::Admitted;
    fact.started_at = None;
    fact.execution_expires_at = None;
    fact.validate(fact.context.tenant, fact.id)?;
    let before = serde_json::to_value(&fact)?;
    assert_eq!(views::state(&fact, fact.start_expires_at), "uncertain");
    assert_eq!(serde_json::to_value(&fact)?, before);
    assert!(fact.start_expires_at > fact.submitted_at.offset_secs(110));
    Ok(())
}
