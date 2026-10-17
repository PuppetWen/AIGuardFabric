//! Register the six existing functions; never substitute a TaskOutcome or business response.
use super::{
    database::Owned,
    fixtures,
    platform::{Platform, Server},
    provider::Pull,
};
use crate::{
    ArchiveTaskConfig, HttpTaskConfig, Partition, Registry, ReportTaskConfig, callback, callback_binding::Client, tasks,
};
use agf_core::ids::Id;
use axum::{Router, extract::Path, http::HeaderMap, routing::post};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};

const TOKEN: &str = "callback-owned-delivery-token-at-least32bytes";
pub(super) struct Consumer {
    pub(super) registry: Arc<Registry>,
    server: Server,
    http: reqwest::Client,
}
impl Consumer {
    pub(super) async fn close(mut self) {
        self.server.stop().await;
    }
    pub(super) async fn new(platform: &Platform, owned: &Owned) -> anyhow::Result<Self> {
        let auth = tasks::ApiAuth::ApiKey(platform.key.clone());
        let binding = Client::literal_loopback(&platform.server.origin, &auth, platform.tenant)?;
        binding.ready(tokio::time::Instant::now() + Duration::from_secs(110)).await?;
        let mut registry = Registry::new();
        registry.execution.cloud = true;
        registry.execution.persistent = true;
        registry.execution.tenant = platform.tenant;
        registry.execution.store = platform.state.configurations.clone();
        registry.execution.token = TOKEN.into();
        registry.execution.app_id = fixtures::APP.into();
        registry.execution.binding = Some(Arc::new(binding));
        registry.execution.artifact_roots = vec![owned.scratch.path("reports"), owned.scratch.path("archive")];
        let registry = Arc::new(registry);
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .timeout(Duration::from_secs(100))
            .build()?;
        crate::spawn_http_tasks(
            registry.clone(),
            &http,
            HttpTaskConfig {
                server_url: platform.server.origin.clone(),
                auth: Some(auth.clone()),
                report_dir: owned.scratch.path("reports"),
                rules_dir: owned.scratch.path("rules"),
                pull_urls: String::new(),
                agentteams_sync: false,
                agentteams_confirm_live: false,
            },
            3600,
        );
        crate::spawn_redteam_task(
            registry.clone(),
            &http,
            tasks::CruiseConfig {
                server: platform.server.origin.clone(),
                auth: Some(auth),
                tenant: platform.tenant,
                output: owned.scratch.path("reports"),
                guard: 30,
            },
            3600,
        );
        crate::spawn_report_task(
            registry.clone(),
            ReportTaskConfig {
                rules: owned.scratch.path("rules"),
                redteam: owned.scratch.path("cases"),
                output: owned.scratch.path("reports"),
            },
            3600,
        );
        crate::spawn_archive_task(
            registry.clone(),
            ArchiveTaskConfig {
                job: tasks::ArchiveJob {
                    report_dir: owned.scratch.path("reports"),
                    archive_dir: owned.scratch.path("archive"),
                    after_days: 0,
                    delete_local: false,
                    store: owned.store.objects().clone(),
                    store_note: None,
                },
            },
            3600,
        );
        assert_eq!(registry.handlers.lock().map_err(|_| anyhow::anyhow!("registry poisoned"))?.len(), 6);
        let route = registry.clone();
        let app = Router::new().route(
            "/schedulerx3/{kind}",
            post(move |kind: Path<String>, headers: HeaderMap| {
                let registry = route.clone();
                async move { callback::invoke(registry, kind, headers).await }
            }),
        );
        Ok(Self { registry, server: Server::start(app).await?, http })
    }
    pub(super) async fn invoke(
        &self,
        kind: &str,
        execution: &str,
        partition: Partition,
        expected: u16,
    ) -> anyhow::Result<Value> {
        let canonical = match kind {
            "report-generate" => "report",
            "cold-archive" => "archive",
            kind => kind,
        };
        let job = fixtures::JOBS
            .iter()
            .find(|(name, _)| *name == canonical)
            .ok_or_else(|| anyhow::anyhow!("undeclared task kind"))?
            .1;
        let reply = self
            .http
            .post(format!("{}/schedulerx3/{kind}", self.server.origin))
            .bearer_auth(TOKEN)
            .header("schedulerx-appId", fixtures::APP)
            .header("schedulerx-jobId", job)
            .header("schedulerx-jobExecutionId", execution)
            .header("schedulerx-shardingindex", partition.index.to_string())
            .header("schedulerx-shardingtotal", partition.total.to_string())
            .send()
            .await?;
        anyhow::ensure!(
            reply.status().as_u16() == expected,
            "actual callback {canonical} HTTP {} differs",
            reply.status().as_u16()
        );
        let bytes = reply.bytes().await?;
        let text = std::str::from_utf8(&bytes)?;
        for forbidden in [TOKEN, "SYNTHETIC-NOT-EXPOSED", "x-agf-key", "artifact_roots"] {
            anyhow::ensure!(!text.contains(forbidden), "receipt exposed private material");
        }
        let result: Value = serde_json::from_slice(&bytes)?;
        if expected == 200 || expected == 502 {
            assert_eq!(result["receipt"]["completionState"], "complete");
            assert_eq!(result["receipt"]["mayExecute"], false);
            assert_eq!(result["receipt"]["mayConfirmStart"], false);
        }
        Ok(result)
    }
}
pub(super) async fn source(platform: &Platform, pull: &Pull) -> anyhow::Result<Id> {
    let parser = platform.admin("POST", "/api/v1/parsers", Some(fixtures::parser()), 201).await?;
    let source = platform
        .admin(
            "POST",
            "/api/v1/ingest/sources",
            Some(json!({"name":"owned pull source","protocol":"http-pull","enabled":true,
        "endpoint":format!("{}/logs",pull.server.origin),"parserId":parser["id"],"pollIntervalSecs":60})),
            201,
        )
        .await?;
    Ok(serde_json::from_value(source["id"].clone())?)
}
pub(super) fn report_file(owned: &Owned) -> anyhow::Result<std::path::PathBuf> {
    let files: Vec<_> = std::fs::read_dir(owned.scratch.path("reports"))?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("report-") && name.ends_with(".md"))
        })
        .collect();
    anyhow::ensure!(files.len() == 1, "exact actual report file required");
    Ok(files[0].clone())
}
pub(super) fn age_report(owned: &Owned) -> anyhow::Result<()> {
    let path = report_file(owned)?;
    super::ownership::plain(&path)?;
    let modified = std::time::SystemTime::now()
        .checked_sub(Duration::from_hours(48))
        .ok_or_else(|| anyhow::anyhow!("owned retention time invalid"))?;
    std::fs::OpenOptions::new().write(true).open(path)?.set_times(std::fs::FileTimes::new().set_modified(modified))?;
    Ok(())
}
