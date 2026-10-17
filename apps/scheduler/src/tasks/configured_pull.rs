//! 驱动控制台日志源，沿用加密凭据、持久游标、解析器与事件入库链路。
use super::*;
use serde_json::Value;

async fn json_response(mut response: reqwest::Response) -> anyhow::Result<Value> {
    anyhow::ensure!(response.status().is_success(), "平台接口返回 HTTP {}", response.status().as_u16());
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| anyhow::anyhow!("响应读取失败"))? {
        anyhow::ensure!(bytes.len() + chunk.len() <= 2 * 1024 * 1024, "平台响应超过 2 MiB");
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("平台响应不是有效 JSON"))
}
async fn run(
    client: &reqwest::Client,
    server: &str,
    auth: Option<&ApiAuth>,
    partition: crate::Partition,
) -> anyhow::Result<TaskOutcome> {
    anyhow::ensure!(auth.is_some(), "请配置具有 sources:read 和 sources:write 的服务 API Key");
    let mut ids = std::collections::BTreeSet::new();
    let mut complete = false;
    for page in 1..=20 {
        let url = api_url(
            server,
            &format!("/api/v1/ingest/sources?page={page}&page_size=100&protocol=http-pull&enabled=true"),
        );
        let response = http_get(client, &url, auth).await.map_err(|_| anyhow::anyhow!("日志源列表连接失败"))?;
        let body = json_response(response).await?;
        let rows = body["items"].as_array().ok_or_else(|| anyhow::anyhow!("日志源列表缺少 items"))?;
        for row in rows {
            let id = row["id"]
                .as_str()
                .and_then(|id| id.parse::<agf_core::ids::Id>().ok())
                .ok_or_else(|| anyhow::anyhow!("日志源 ID 无效"))?;
            anyhow::ensure!(ids.insert(id), "分页返回重复日志源，请重新拉取");
        }
        let more = body["has_more"].as_bool().ok_or_else(|| anyhow::anyhow!("日志源列表缺少分页状态"))?;
        if !more {
            complete = true;
            break;
        }
        anyhow::ensure!(!rows.is_empty(), "日志源分页提前结束");
    }
    anyhow::ensure!(complete, "日志源超过 20 页，请按租户拆分");
    if ids.is_empty() {
        return Ok(TaskOutcome::skipped("当前租户没有启用的 HTTP Pull 日志源，请在接入管理添加"));
    }
    let (mut accepted, mut skipped, mut failed) = (0, 0, 0);
    for id in ids.iter().filter(|id| partition.owns(&id.to_string())) {
        let url = api_url(server, &format!("/api/v1/ingest/sources/{id}/poll?manual=false"));
        let response = http_post_json(client, &url, auth, serde_json::json!({})).await;
        match response {
            Ok(response) => match json_response(response).await {
                Ok(body) if body["skipped"] == true => skipped += 1,
                Ok(body) => {
                    accepted += body["accepted"].as_u64().ok_or_else(|| anyhow::anyhow!("拉取回执缺少 accepted"))?;
                    if body["errors"].as_array().is_some_and(|errors| !errors.is_empty()) {
                        failed += 1;
                    }
                }
                Err(_) => failed += 1,
            },
            Err(_) => failed += 1,
        }
    }
    let note = format!(
        "配置日志源 {} 个，实际入库 {accepted} 条，未到期/执行中 {skipped} 个，失败 {failed} 个；凭据和游标由平台保存",
        ids.len()
    );
    Ok(if failed == 0 { TaskOutcome::ok(note) } else { TaskOutcome::failed(note) })
}
pub(crate) async fn run_configured_pull(
    client: &reqwest::Client,
    server: &str,
    auth: Option<&ApiAuth>,
    partition: crate::Partition,
) -> TaskOutcome {
    match run(client, server, auth, partition).await {
        Ok(result) => result,
        Err(error) => TaskOutcome::failed(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Json, Router,
        extract::{Query, State},
        http::HeaderMap,
        routing::{get, post},
    };
    use std::sync::atomic::{AtomicU64, Ordering};
    #[tokio::test]
    async fn pages_then_polls_due_sources_with_service_key_only_at_platform() {
        let count = Arc::new(AtomicU64::new(0));
        let first = agf_core::ids::Id::new().to_string();
        let second = agf_core::ids::Id::new().to_string();
        let app = Router::new()
            .route(
                "/api/v1/ingest/sources",
                get(move |headers: HeaderMap, Query(query): Query<BTreeMap<String, String>>| {
                    let ids = [first.clone(), second.clone()];
                    async move {
                        assert_eq!(headers["x-agf-key"], "test-service-key");
                        assert_eq!(query["protocol"], "http-pull");
                        let page: usize = query["page"].parse().unwrap();
                        Json(serde_json::json!({"items":[{"id":ids[page-1]}],"has_more":page==1,"total":2}))
                    }
                }),
            )
            .route(
                "/api/v1/ingest/sources/{id}/poll",
                post(
                    |State(count): State<Arc<AtomicU64>>,
                     headers: HeaderMap,
                     Query(query): Query<BTreeMap<String, String>>| async move {
                        assert_eq!(headers["x-agf-key"], "test-service-key");
                        assert_eq!(query["manual"], "false");
                        let call = count.fetch_add(1, Ordering::SeqCst);
                        Json(if call == 0 {
                            serde_json::json!({"accepted":7,"errors":[]})
                        } else {
                            serde_json::json!({"skipped":true})
                        })
                    },
                ),
            )
            .with_state(Arc::clone(&count));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut notes = Vec::new();
        for index in 0..2 {
            let outcome = run_configured_pull(
                &reqwest::Client::new(),
                &base,
                Some(&ApiAuth::ApiKey("test-service-key".into())),
                crate::Partition { index, total: 2 },
            )
            .await;
            assert!(outcome.ok, "{}", outcome.note);
            notes.push(outcome.note);
        }
        task.abort();
        assert!(notes.iter().any(|note| note.contains("入库 7 条")));
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }
}
