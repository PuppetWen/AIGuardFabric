//! Optional AgentTeams inventory before the ordinary asset statistics snapshot.
use super::*;
use agf_core::ids::deterministic_id;
use serde_json::{Value, json};
use std::time::Duration;

pub(crate) async fn run_agentteams_sync(
    client: &reqwest::Client,
    server_url: &str,
    auth: Option<&ApiAuth>,
    confirm_live: bool,
) -> TaskOutcome {
    let Some(auth) = auth else {
        return TaskOutcome::failed("AgentTeams 定时盘点已启用，但未配置平台服务 API Key");
    };
    let config_url = api_url(server_url, "/api/v1/alicloud/connections/alicloud-agentteams");
    let response = match http_get(client, &config_url, Some(auth)).await {
        Ok(response) => response,
        Err(error) => return TaskOutcome::failed(format!("读取 AgentTeams 连接失败：{error}")),
    };
    if !response.status().is_success() {
        return TaskOutcome::failed(format!(
            "读取 AgentTeams 连接返回 HTTP {}；需 alicloud:write",
            response.status().as_u16()
        ));
    }
    let config: Value = match response.json().await {
        Ok(value) => value,
        Err(_) => return TaskOutcome::failed("AgentTeams 连接响应不是合法 JSON"),
    };
    let Some(version) = config["version"].as_u64().filter(|version| *version > 0) else {
        return TaskOutcome::failed("AgentTeams 连接缺少有效配置版本");
    };
    if config["enabled"] != true {
        return TaskOutcome::failed("AgentTeams 定时盘点已启用，但云连接尚未启用");
    }
    let mocked = config["mock"] == true || config["environment_mock"] == true;
    if !mocked && !confirm_live {
        return TaskOutcome::failed("真实 AgentTeams 连接需要显式设置 AGF_SCHEDULER_AGENTTEAMS_CONFIRM_LIVE=1");
    }
    let request_id = crate::dispatch::EXECUTION_ID
        .try_with(|execution| deterministic_id("agf.scheduler.agentteams.sync", execution))
        .unwrap_or_else(|_| Id::new());
    let url = api_url(server_url, "/api/v1/alicloud/agentteams/sync");
    let request = auth.apply(client.post(&url).timeout(Duration::from_secs(130)).json(&json!({
        "request_id": request_id,
        "configuration_version": version,
        "confirm_live": !mocked && confirm_live,
    })));
    let response = match request.send().await {
        Ok(response) => response,
        Err(error) => return TaskOutcome::failed(format!("AgentTeams 同步请求失败：{error}")),
    };
    if !response.status().is_success() {
        return TaskOutcome::failed(format!(
            "AgentTeams 同步返回 HTTP {}；原快照保持不变，请核对云操作回执",
            response.status().as_u16()
        ));
    }
    let result: Value = match response.json().await {
        Ok(value) => value,
        Err(_) => return TaskOutcome::failed("AgentTeams 同步响应不是合法 JSON"),
    };
    let (Some(teams), Some(workers), Some(assets)) =
        (result["teams"].as_u64(), result["workers"].as_u64(), result["assets"].as_u64())
    else {
        return TaskOutcome::failed("AgentTeams 同步响应缺少团队、Worker 或资产数量");
    };
    let mode = if result["mocked"] == true { "Mock" } else { "Live" };
    TaskOutcome::ok(format!("AgentTeams {mode} 盘点已发布：{teams} 个团队、{workers} 个 Worker、{assets} 个资产"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Json, Router,
        extract::State,
        http::HeaderMap,
        routing::{get, post},
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    async fn server(mocked: bool) -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let posts = Arc::new(AtomicUsize::new(0));
        let config = json!({"enabled":true,"mock":mocked,"environment_mock":false,"version":7});
        let app = Router::new()
            .route("/api/v1/alicloud/connections/alicloud-agentteams", get(move || {
                let config = config.clone();
                async move { Json(config) }
            }))
            .route("/api/v1/alicloud/agentteams/sync", post(move |State(posts): State<Arc<AtomicUsize>>, headers: HeaderMap, Json(body): Json<Value>| async move {
                assert_eq!(headers.get("X-AGF-Key").and_then(|value| value.to_str().ok()), Some("test-key"));
                assert_eq!(body["configuration_version"], 7);
                assert!(body["request_id"].as_str().is_some());
                posts.fetch_add(1, Ordering::SeqCst);
                Json(json!({"mocked":mocked,"teams":2,"workers":3,"assets":3}))
            }))
            .with_state(Arc::clone(&posts));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (url, posts, handle)
    }

    #[tokio::test]
    async fn mock_inventory_sends_versioned_sync_with_service_identity() {
        let (url, posts, handle) = server(true).await;
        let outcome =
            run_agentteams_sync(&reqwest::Client::new(), &url, Some(&ApiAuth::ApiKey("test-key".into())), false).await;
        assert!(outcome.ok, "{}", outcome.note);
        assert!(outcome.note.contains("Mock") && outcome.note.contains("3 个资产"));
        assert_eq!(posts.load(Ordering::SeqCst), 1);
        handle.abort();
    }

    #[tokio::test]
    async fn live_inventory_requires_separate_confirmation_before_post() {
        let (url, posts, handle) = server(false).await;
        let auth = ApiAuth::ApiKey("test-key".into());
        let rejected = run_agentteams_sync(&reqwest::Client::new(), &url, Some(&auth), false).await;
        assert!(!rejected.ok && rejected.note.contains("CONFIRM_LIVE"));
        assert_eq!(posts.load(Ordering::SeqCst), 0);
        let accepted = run_agentteams_sync(&reqwest::Client::new(), &url, Some(&auth), true).await;
        assert!(accepted.ok, "{}", accepted.note);
        assert_eq!(posts.load(Ordering::SeqCst), 1);
        handle.abort();
    }
}
