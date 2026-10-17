//! Compare real files, SQL records and safe terminal receipts; never infer effects from ok alone.
use super::{business, database::Owned, fixtures, ownership, platform::Platform};
use agf_core::{
    audit::{AuditAction, AuditOutcome},
    ids::Id,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

pub(super) fn complete(reply: &Value, ok: bool, artifacts: usize) {
    assert_eq!(reply["ok"], ok);
    assert_eq!(reply["result"], reply["receipt"]["outcome"]);
    assert_eq!(reply["result"]["ok"], ok);
    assert_eq!(reply["result"]["skipped"], false);
    assert_eq!(reply["result"]["degraded"], false);
    assert_eq!(reply["result"]["artifacts"].as_array().map(Vec::len), Some(artifacts));
    assert_eq!(reply["receipt"]["state"], if ok { "succeeded" } else { "failed" });
    assert_eq!(reply["receipt"]["originalTarget"]["mocked"], false);
    assert_eq!(reply["receipt"]["originalTarget"]["transportMode"], "loopback_test");
}
fn digest(path: &Path) -> anyhow::Result<Value> {
    ownership::plain(path)?;
    let bytes = std::fs::read(path)?;
    anyhow::ensure!(!bytes.is_empty(), "business artifact unexpectedly empty");
    Ok(json!({"sha256":format!("{:x}",Sha256::digest(&bytes)),"bytes":bytes.len()}))
}
pub(super) fn artifacts(reply: &Value, paths: &[PathBuf]) -> anyhow::Result<()> {
    let expected: Vec<_> = paths.iter().map(|path| digest(path)).collect::<Result<_, _>>()?;
    assert_eq!(reply["result"]["artifacts"], json!(expected));
    Ok(())
}
pub(super) fn file(owned: &Owned, prefix: &str, suffix: &str) -> anyhow::Result<PathBuf> {
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(owned.scratch.path("reports"))? {
        let path = entry?.path();
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(prefix) && name.ends_with(suffix))
        {
            paths.push(path);
        }
    }
    anyhow::ensure!(paths.len() == 1, "exactly one actual business artifact required");
    Ok(paths.remove(0))
}
pub(super) fn outputs(owned: &Owned) -> anyhow::Result<Value> {
    fn walk(path: &Path, root: &Path, out: &mut BTreeMap<String, Value>) -> anyhow::Result<()> {
        ownership::plain(path)?;
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                walk(&entry.path(), root, out)?;
            } else {
                out.insert(entry.path().strip_prefix(root)?.to_string_lossy().into_owned(), digest(&entry.path())?);
            }
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    for name in ["reports", "archive", "objects"] {
        walk(&owned.scratch.path(name), &owned.scratch.root, &mut out)?;
    }
    Ok(json!(out))
}
pub(super) async fn snapshot(platform: &Platform, owned: &Owned) -> anyhow::Result<Value> {
    Ok(json!({"platform":platform.snapshot().await?,"rows":owned.rows(platform.tenant).await?,
        "campaigns":platform.state.store.campaign_list_durable(platform.tenant).await?,"outputs":outputs(owned)?}))
}
pub(super) async fn log(platform: &Platform, owned: &Owned, id: Id) -> anyhow::Result<()> {
    assert_eq!(owned.count(platform.tenant, "raw_logs").await?, 1);
    assert_eq!(owned.count(platform.tenant, "events").await?, 1);
    let row = agf_api::source_store::load(&platform.state, platform.tenant, id).await?;
    assert_eq!((row.received, row.matched, row.failed), (1, 1, 0));
    assert_eq!((row.lease_until, row.lease_id), (0, None));
    assert_eq!(row.cursor.as_deref(), Some("owned-next-1"));
    assert!(row.next_poll_at > agf_core::time::Timestamp::now().unix_secs());
    let source = row.source.ok_or_else(|| anyhow::anyhow!("source missing after pull"))?;
    assert_eq!(source.total_events, 1);
    assert_eq!(source.health, agf_core::enums::HealthState::Healthy);
    let rows = owned.rows(platform.tenant).await?;
    assert_eq!(rows["raw"][0]["source_id"], id.to_string());
    assert_eq!(rows["events"][0]["source_id"], id.to_string());
    assert_eq!(rows["events"][0]["parser_id"], json!(source.parser_id));
    assert_eq!(rows["events"][0]["action_raw"], "pulled");
    assert_eq!(rows["events"][0]["tenant_id"], platform.tenant.to_string());
    Ok(())
}
pub(super) async fn redteam(platform: &Platform, owned: &Owned, reply: &Value) -> anyhow::Result<()> {
    complete(reply, true, 2);
    let campaigns = platform.state.store.campaign_list_durable(platform.tenant).await?;
    assert_eq!(campaigns.len(), 1);
    let record = platform
        .state
        .store
        .campaign_get_durable(platform.tenant, campaigns[0].id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("real campaign missing"))?;
    assert_eq!(record.campaign.state.as_str(), "completed");
    assert!(record.campaign.scheduled);
    assert!(!record.campaign.ci_gate);
    assert_eq!(record.execution_mode.as_deref(), Some("simulator"));
    assert_eq!((record.cases.len(), record.results.len()), (1, 1));
    assert_eq!(record.cases[0].key, fixtures::case().key);
    let json_path = file(owned, "redteam-cruise-", ".json")?;
    let md_path = file(owned, "redteam-cruise-", ".md")?;
    let evidence: Value = serde_json::from_slice(&std::fs::read(&json_path)?)?;
    assert_eq!(evidence["format"], "agf-redteam-evidence-v1");
    assert_eq!(evidence["record"], serde_json::to_value(&record)?);
    assert_eq!(
        std::fs::read_to_string(&md_path)?,
        record.report.ok_or_else(|| anyhow::anyhow!("report absent"))?.markdown
    );
    artifacts(reply, &[json_path, md_path])?;
    Ok(())
}
pub(super) async fn runtime(platform: &Platform) -> anyhow::Result<()> {
    let policies = agf_api::policy_store::list(&platform.state, platform.tenant).await?;
    assert_eq!(policies.len(), 1);
    let policy = &policies[0];
    assert_eq!(policy.content_hash, policy.compute_hash());
    agf_api::policy_store::signer(&platform.state)?.verify(policy)?;
    let runtime = platform.state.runtime_registry.get(&platform.state, platform.tenant).await?;
    assert_eq!(runtime.policy_count().await, 1);
    // This endpoint uses the complete tenant registry, unlike /policies/{id}/dry-run.
    let decision = platform
        .admin(
            "POST",
            "/api/v1/policies/dry-run",
            Some(json!({"intercept_point":"ai-gateway","payload":{"message":"owned ordinary request"}})),
            200,
        )
        .await?;
    assert_eq!(decision["blocking"], true);
    assert_eq!(decision["decision"]["policy_id"], policy.id.to_string());
    Ok(())
}
pub(super) async fn archive(owned: &Owned, reply: &Value) -> anyhow::Result<()> {
    complete(reply, true, 1);
    let path = file(owned, "archive-", ".json")?;
    let manifest: crate::tasks::ArchiveManifest = serde_json::from_slice(&std::fs::read(&path)?)?;
    let report = business::report_file(owned)?;
    let bytes = std::fs::read(&report)?;
    assert_eq!(manifest.backend, "local");
    assert!(!manifest.degraded_local);
    assert_eq!(manifest.degrade_reason, None);
    assert_eq!((manifest.files, manifest.bytes), (1, bytes.len() as u64));
    assert_eq!(manifest.entries.len(), 1);
    assert_eq!(manifest.entries[0].sha256, format!("{:x}", Sha256::digest(&bytes)));
    let name =
        report.file_name().and_then(|name| name.to_str()).ok_or_else(|| anyhow::anyhow!("report name invalid"))?;
    assert_eq!(manifest.entries[0].name, name);
    assert_eq!(manifest.uploaded, vec![format!("{name}.gz")]);
    assert!(manifest.local_archives.is_empty() && manifest.errors.is_empty() && manifest.deleted_locals.is_empty());
    assert_eq!(
        crate::tasks::manifest_totals(&manifest.entries),
        (manifest.files, manifest.bytes, manifest.manifest_sha256.clone())
    );
    let compressed = owned.store.objects().get(&manifest.uploaded[0]).await?;
    assert_eq!(crate::tasks::gunzip_payload(&compressed)?, bytes);
    assert!(report.is_file());
    artifacts(reply, &[path])?;
    Ok(())
}
pub(super) async fn audits(platform: &Platform, expected: &[(Value, bool)], reloads: usize) -> anyhow::Result<()> {
    let logs = platform.state.store.audit_chain_durable(platform.tenant, 0, i64::MAX).await?;
    let terminal: Vec<_> = logs
        .iter()
        .filter(|row| row.target.kind == "scheduler-native-callback-execution" && row.action == AuditAction::Execute)
        .collect();
    assert_eq!(terminal.len(), expected.len());
    for (reply, ok) in expected {
        let id: Id = serde_json::from_value(reply["receipt"]["factId"].clone())?;
        let id_text = id.to_string();
        for (kind, action) in [
            ("scheduler-native-callback-claim", AuditAction::Create),
            ("scheduler-native-callback-start", AuditAction::Execute),
        ] {
            assert_eq!(
                logs.iter()
                    .filter(|row| row.target.kind == kind
                        && row.target.id.as_deref() == Some(id_text.as_str())
                        && row.action == action
                        && row.outcome == AuditOutcome::Success)
                    .count(),
                1
            );
        }
        let outcome = if *ok { AuditOutcome::Success } else { AuditOutcome::Failure };
        assert_eq!(
            terminal
                .iter()
                .filter(|row| row.target.id.as_deref() == Some(id_text.as_str()) && row.outcome == outcome)
                .count(),
            1
        );
    }
    assert_eq!(
        logs.iter()
            .filter(|row| row.target.kind == "runtime-engine"
                && row.action == AuditAction::Configure
                && row.outcome == AuditOutcome::Success)
            .count(),
        reloads
    );
    assert!(platform.state.store.audit_verify_durable(platform.tenant).await?.passed);
    Ok(())
}
