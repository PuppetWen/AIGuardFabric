//! Ignored owned-PG acceptance executes registered business functions through the actual v4 API.
//! No server business route or TaskOutcome is replaced; only cloud RPC/log upstreams are synthetic.
mod assertions;
mod business;
mod database;
mod fixtures;
mod ownership;
mod platform;
mod provider;
mod signature;

use crate::Partition;
use assertions as check;
use business::Consumer;
use database::Owned;
use platform::Platform;
use provider::{Provider, Pull};
use serde_json::Value;

const ONE: Partition = Partition { index: 0, total: 1 };

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires exact owned callback-business PostgreSQL and fixed validation root"]
async fn six_registered_handlers_have_real_effects_and_restart_redelivery_is_readonly() -> anyhow::Result<()> {
    let owned = Owned::open().await?;
    let provider = Provider::new().await?;
    let platform = Platform::new(&owned, provider.address()?).await?;
    let pull = Pull::new().await?;
    let source = business::source(&platform, &pull).await?;
    let consumer = Consumer::new(&platform, &owned).await?;
    let policies = serde_json::to_value(agf_api::policy_store::list(&platform.state, platform.tenant).await?)?;

    let asset = consumer.invoke("asset-inventory", "six-asset", ONE, 200).await?;
    check::complete(&asset, true, 1);
    let inventory = check::file(&owned, "asset-inventory-", ".json")?;
    let stats: Value = serde_json::from_slice(&std::fs::read(&inventory)?)?;
    assert_eq!(stats["inventory"]["total"], 1);
    check::artifacts(&asset, &[inventory])?;
    assert_eq!(platform.calls("GET", "/api/v1/assets/stats")?, 1);

    let log = consumer.invoke("log-pull", "six-log", ONE, 200).await?;
    check::complete(&log, true, 0);
    check::log(&platform, &owned, source).await?;
    assert_eq!(pull.count(), 1);
    assert_eq!(platform.calls("POST", &format!("/api/v1/ingest/sources/{source}/poll"))?, 1);

    let redteam = consumer.invoke("redteam-cruise", "six-redteam", ONE, 200).await?;
    check::redteam(&platform, &owned, &redteam).await?;
    assert_eq!(platform.calls("POST", "/api/v1/redteam/campaigns")?, 1);

    let reload = consumer.invoke("rule-hot-reload", "six-reload", ONE, 200).await?;
    check::complete(&reload, true, 0);
    assert_eq!(platform.calls("POST", "/api/v1/policies/reload")?, 1);
    assert_eq!(serde_json::to_value(agf_api::policy_store::list(&platform.state, platform.tenant).await?)?, policies);
    check::runtime(&platform).await?;

    let report = consumer.invoke("report-generate", "six-report", ONE, 200).await?;
    check::complete(&report, true, 1);
    let report_path = business::report_file(&owned)?;
    let markdown = std::fs::read_to_string(&report_path)?;
    assert!(
        markdown.contains("规则包条数：1") && markdown.contains("用例数：1") && markdown.contains("资产台账：总量 1")
    );
    assert!(
        markdown.contains("redteam-cruise-") && markdown.contains("log-pull") && markdown.contains("rule-hot-reload")
    );
    // Configured ingestion writes SQL, so its absent local log statistics stay honestly unavailable.
    assert!(
        markdown
            .split("## 日志拉取")
            .nth(1)
            .and_then(|section| section.split("## 冷归档").next())
            .is_some_and(|section| section.contains(crate::tasks::NO_DATA))
    );
    check::artifacts(&report, &[report_path])?;

    business::age_report(&owned)?;
    let archive = consumer.invoke("cold-archive", "six-archive", ONE, 200).await?;
    check::archive(&owned, &archive).await?;
    let originals = [
        ("asset-inventory", "six-asset", asset),
        ("log-pull", "six-log", log),
        ("redteam-cruise", "six-redteam", redteam),
        ("rule-hot-reload", "six-reload", reload),
        ("report-generate", "six-report", report),
        ("cold-archive", "six-archive", archive),
    ];
    let expected: Vec<_> = originals.iter().map(|(_, _, reply)| (reply.clone(), true)).collect();
    check::audits(&platform, &expected, 1).await?;
    provider.assert_initial_reads_only()?;
    let before = check::snapshot(&platform, &owned).await?;
    consumer.close().await;
    let second = platform.restart(&owned, provider.address()?).await?;
    let consumer = Consumer::new(&second, &owned).await?;
    for (kind, execution, original) in &originals {
        assert_eq!(consumer.invoke(kind, execution, ONE, 200).await?, *original);
    }
    for (method, path) in
        [("GET", "/api/v1/assets/stats"), ("POST", "/api/v1/redteam/campaigns"), ("POST", "/api/v1/policies/reload")]
    {
        assert_eq!(second.calls(method, path)?, 0);
    }
    assert_eq!(second.calls("POST", &format!("/api/v1/ingest/sources/{source}/poll"))?, 0);
    assert_eq!(pull.count(), 1);
    assert_eq!(check::snapshot(&second, &owned).await?, before);
    assert!(consumer.registry.snapshot().iter().all(|row| row.runs == 0));
    provider.assert_initial_reads_only()?;
    check::audits(&second, &expected, 1).await?;
    consumer.close().await;
    second.close().await;
    platform.close().await;
    pull.close().await;
    provider.close().await;
    owned.finish().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires exact owned callback-business PostgreSQL and fixed validation root"]
async fn report_requires_real_asset_and_log_completions_without_legacy_fill() -> anyhow::Result<()> {
    let owned = Owned::open().await?;
    let provider = Provider::new().await?;
    let platform = Platform::new(&owned, provider.address()?).await?;
    let pull = Pull::new().await?;
    let source = business::source(&platform, &pull).await?;
    let consumer = Consumer::new(&platform, &owned).await?;
    let before = check::snapshot(&platform, &owned).await?;
    consumer.invoke("report", "report-no-upstreams", ONE, 412).await?;
    assert_eq!(check::snapshot(&platform, &owned).await?, before);
    assert_eq!(platform.calls("GET", "/api/v1/assets/stats")?, 0);
    assert_eq!(pull.count(), 0);
    let asset = consumer.invoke("asset-inventory", "dependency-asset", ONE, 200).await?;
    check::complete(&asset, true, 1);
    let after_asset = check::snapshot(&platform, &owned).await?;
    consumer.invoke("report", "report-no-log", ONE, 412).await?;
    assert_eq!(check::snapshot(&platform, &owned).await?, after_asset);
    assert_eq!(pull.count(), 0);
    let log = consumer.invoke("log-pull", "dependency-log", ONE, 200).await?;
    check::complete(&log, true, 0);
    check::log(&platform, &owned, source).await?;
    let report = consumer.invoke("report", "report-ready", ONE, 200).await?;
    check::complete(&report, true, 1);
    check::artifacts(&report, &[business::report_file(&owned)?])?;
    assert_eq!(platform.calls("GET", "/api/v1/assets/stats")?, 1);
    assert_eq!(pull.count(), 1);
    check::audits(&platform, &[(asset, true), (log, true), (report, true)], 0).await?;
    provider.assert_initial_reads_only()?;
    consumer.close().await;
    platform.close().await;
    pull.close().await;
    provider.close().await;
    owned.finish().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires exact owned callback-business PostgreSQL and fixed validation root"]
async fn real_invalid_rule_pack_failure_is_permanent_for_the_original_identity() -> anyhow::Result<()> {
    let owned = Owned::open().await?;
    let provider = Provider::new().await?;
    let platform = Platform::new(&owned, provider.address()?).await?;
    let consumer = Consumer::new(&platform, &owned).await?;
    let rule = owned.scratch.path("rules").join("owned.yaml");
    ownership::plain(&rule)?;
    std::fs::write(&rule, "key: [invalid YAML")?;
    let failed = consumer.invoke("rule-hot-reload", "reload-failed", ONE, 502).await?;
    check::complete(&failed, false, 0);
    assert_eq!(platform.calls("POST", "/api/v1/policies/reload")?, 0);
    let before = check::snapshot(&platform, &owned).await?;
    std::fs::write(&rule, fixtures::RULE)?;
    assert_eq!(consumer.invoke("rule-hot-reload", "reload-failed", ONE, 502).await?, failed);
    assert_eq!(check::snapshot(&platform, &owned).await?, before);
    assert_eq!(platform.calls("POST", "/api/v1/policies/reload")?, 0);
    let recovered = consumer.invoke("rule-hot-reload", "reload-new-intent", ONE, 200).await?;
    check::complete(&recovered, true, 0);
    assert_ne!(recovered["receipt"]["factId"], failed["receipt"]["factId"]);
    assert_eq!(platform.calls("POST", "/api/v1/policies/reload")?, 1);
    check::runtime(&platform).await?;
    let row = consumer
        .registry
        .snapshot()
        .into_iter()
        .find(|row| row.name == "rule-hot-reload")
        .ok_or_else(|| anyhow::anyhow!("registered task missing"))?;
    assert_eq!((row.runs, row.failures), (2, 1));
    check::audits(&platform, &[(failed, false), (recovered, true)], 1).await?;
    provider.assert_initial_reads_only()?;
    consumer.close().await;
    platform.close().await;
    provider.close().await;
    owned.finish().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires exact owned callback-business PostgreSQL and fixed validation root"]
async fn empty_configured_log_shard_is_success_but_report_waits_for_all_real_partitions() -> anyhow::Result<()> {
    let owned = Owned::open().await?;
    let provider = Provider::new().await?;
    let platform = Platform::new(&owned, provider.address()?).await?;
    let pull = Pull::new().await?;
    let source = business::source(&platform, &pull).await?;
    let consumer = Consumer::new(&platform, &owned).await?;
    let asset = consumer.invoke("asset-inventory", "shards-asset", ONE, 200).await?;
    let owner = (0..2)
        .find(|index| Partition { index: *index, total: 2 }.owns(&source.to_string()))
        .ok_or_else(|| anyhow::anyhow!("resource partition owner missing"))?;
    let empty = Partition { index: 1 - owner, total: 2 };
    let first = consumer.invoke("log-pull", "shards-log", empty, 200).await?;
    check::complete(&first, true, 0);
    assert_eq!(pull.count(), 0);
    assert_eq!(platform.calls("GET", "/api/v1/ingest/sources")?, 1);
    assert_eq!(owned.count(platform.tenant, "raw_logs").await?, 0);
    let before = check::snapshot(&platform, &owned).await?;
    consumer.invoke("report", "report-missing-partition", ONE, 412).await?;
    assert_eq!(check::snapshot(&platform, &owned).await?, before);
    let second = consumer.invoke("log-pull", "shards-log", Partition { index: owner, total: 2 }, 200).await?;
    check::complete(&second, true, 0);
    check::log(&platform, &owned, source).await?;
    assert_eq!(pull.count(), 1);
    assert_eq!(platform.calls("GET", "/api/v1/ingest/sources")?, 2);
    assert_eq!(platform.calls("POST", &format!("/api/v1/ingest/sources/{source}/poll"))?, 1);
    let report = consumer.invoke("report", "report-complete-partitions", ONE, 200).await?;
    check::complete(&report, true, 1);
    check::artifacts(&report, &[business::report_file(&owned)?])?;
    let published = check::snapshot(&platform, &owned).await?;
    assert_eq!(consumer.invoke("log-pull", "shards-log", empty, 200).await?, first);
    assert_eq!(check::snapshot(&platform, &owned).await?, published);
    assert_eq!(pull.count(), 1);
    check::audits(&platform, &[(asset, true), (first, true), (second, true), (report, true)], 0).await?;
    provider.assert_initial_reads_only()?;
    consumer.close().await;
    platform.close().await;
    pull.close().await;
    provider.close().await;
    owned.finish().await?;
    Ok(())
}
