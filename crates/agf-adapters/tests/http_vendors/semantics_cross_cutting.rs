//! 横切断言：`push`/`pull`/`sync` 的错误分类、能力登记与方向语义（wiremock，零外网）。
//!
//! 1. **超时 / 5xx / 4xx**：`push` 与 `send` 走同一套混切链路（熔断 + 重试 + 错误分类）；
//! 2. **Unsupported 矩阵**：12 个内置适配器 × 3 条语义逐条核对——不适用的必须给出
//!    `Validation` + **具体原因**（不是 `NotImplemented` 占位），已实现的不得被能力判定拦住；
//! 3. **方向语义**：`SyncDirection::Push` 只回写（不得发拉取请求）、`Pull` 只拉取（不得回写）。
use super::*;

use agf_adapters::contract::{Semantic, SemanticSupport};
use agf_core::adapter::Adapter as CoreAdapter;
use agf_core::adapter::SyncDirection;

/// Jira 适配器（指向本地假服务端）。
async fn jira_at(server: &MockServer, timeout_secs: u64, retry_cfg: RetryConfig) -> VendorAdapterImpl<Jira> {
    adapter::<Jira>(
        &[("base_url", json!(server.uri())), ("project_key", json!("SEC"))],
        &[("api_token", "jira-token-abcdef"), ("user_email", "soc@example.invalid")],
        timeout_secs,
        retry_cfg,
        circuit(5, 30),
        false,
    )
    .await
}

/// 单条评论回写载荷（一次请求，便于精确计数重试次数）。
fn comment_payload() -> PushPayload {
    PushPayload {
        entity: "ticket.comment".to_string(),
        entity_id: "SEC-7".to_string(),
        body: json!({"comment": "重试语义验证"}),
        idempotency_key: Some("idem-retry-1".to_string()),
    }
}

#[tokio::test]
pub(crate) async fn push_5xx_is_retried_according_to_retry_config() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rest/api/2/issue/SEC-7/comment"))
        .respond_with(ResponseTemplate::new(503).set_body_string("upstream down"))
        .expect(3)
        .mount(&server)
        .await;

    let jira = jira_at(&server, 5, retry(3)).await;
    let error = VendorAdapter::push(&jira, &comment_payload()).await.expect_err("5xx 必须如实报错");
    assert!(matches!(error, DomainError::DependencyUnavailable { .. }), "{error}");
    assert!(error.is_degradable(), "5xx 必须可重试");
    server.verify().await;
    assert_eq!(requests(&server).await.len(), 3, "max_attempts=3 ⇒ 实际尝试 3 次");
    let record = jira.build_record();
    assert_eq!(record.last_attempts, 3);
    assert_eq!(record.consecutive_failures, 1, "一次 push 只累计一次连续失败");
}

#[tokio::test]
pub(crate) async fn push_4xx_is_not_retried() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rest/api/2/issue/SEC-7/comment"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"errors": {"body": "required"}})))
        .expect(1)
        .mount(&server)
        .await;

    let jira = jira_at(&server, 5, retry(3)).await;
    let error = VendorAdapter::push(&jira, &comment_payload()).await.expect_err("4xx 必须如实报错");
    assert!(matches!(error, DomainError::Validation(_)), "{error}");
    assert!(!error.is_degradable(), "4xx 属业务错误，重试不会变好");
    server.verify().await;
    assert_eq!(requests(&server).await.len(), 1);
}

#[tokio::test]
pub(crate) async fn push_timeout_is_reported_as_timeout() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rest/api/2/issue/SEC-7/comment"))
        .respond_with(ResponseTemplate::new(201).set_delay(Duration::from_millis(1500)))
        .mount(&server)
        .await;

    let jira = jira_at(&server, 1, retry_once()).await;
    let error = VendorAdapter::push(&jira, &comment_payload()).await.expect_err("超时必须如实报错");
    assert!(matches!(error, DomainError::Timeout(_)), "{error}");
}

#[tokio::test]
pub(crate) async fn unsupported_semantics_return_validation_with_reason_for_every_builtin() {
    let mut unsupported = 0_usize;
    let mut implemented = 0_usize;
    for adapter in agf_adapters::vendors::builtin() {
        let name = adapter.name().to_string();
        let semantics = adapter.semantics();
        let request = PullRequest { resource: "issues".to_string(), ..PullRequest::default() };
        let payload = comment_payload();
        let sync_request = SyncRequest::new("issues");

        for semantic in Semantic::ALL {
            let (outcome, message) = match semantic {
                Semantic::Push => match adapter.push(&payload).await {
                    Ok(_) => (true, String::new()),
                    Err(error) => (false, error.to_string()),
                },
                Semantic::Pull => match adapter.pull(&request).await {
                    Ok(_) => (true, String::new()),
                    Err(error) => (false, error.to_string()),
                },
                Semantic::Sync => match adapter.sync(&sync_request).await {
                    Ok(_) => (true, String::new()),
                    Err(error) => (false, error.to_string()),
                },
            };
            if semantics.is_implemented(semantic) {
                implemented += 1;
                if !outcome {
                    assert!(
                        !message.contains("Unsupported"),
                        "{name} 的 {semantic} 已实现，不得被能力判定拦成 Unsupported: {message}"
                    );
                }
                continue;
            }
            unsupported += 1;
            assert!(!outcome, "{name} 的 {semantic} 登记为 Unsupported，不得返回成功");
            assert!(message.contains(&format!("不支持 {semantic}（Unsupported）")), "{name}/{semantic}: {message}");
            let reason = semantics.support(semantic).reason().expect("Unsupported 必须带原因");
            assert!(message.contains(reason), "{name}/{semantic} 的错误必须带具体原因: {message}");
            assert!(!message.contains("NotImplemented"), "{name}/{semantic} 不得是 NotImplemented 占位: {message}");
            assert!(
                matches!(semantics.support(semantic), SemanticSupport::Unsupported { .. }),
                "{name}/{semantic} 档位必须如实为 Unsupported"
            );
        }
    }
    assert_eq!(implemented, 13, "已实现语义：3 个工单类 ×3 + EDR ×3 + Slack push = 13");
    assert_eq!(unsupported, 23, "其余 23 条语义必须如实登记为 Unsupported（带原因）");
}

#[tokio::test]
pub(crate) async fn sync_push_direction_writes_back_without_pulling() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rest/api/2/issue/SEC-7/comment"))
        .and(body_partial_json(json!({"body": "只回写，不拉取"})))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": "10003"})))
        .expect(1)
        .mount(&server)
        .await;

    let jira = jira_at(&server, 5, retry_once()).await;
    let mut filter = BTreeMap::new();
    filter.insert(
        "local.SEC-7".to_string(),
        json!({"updated_at": "2026-01-06T00:00:00+00:00", "state": {"comment": "只回写，不拉取"}}).to_string(),
    );
    let request = PullRequest { resource: "issues".to_string(), filter, ..PullRequest::default() };
    let outcome = CoreAdapter::sync(&jira, SyncDirection::Push, &request).await.expect("push 方向对账");
    assert_eq!(outcome.pushed, 1);
    assert_eq!(outcome.pulled, 0, "push 方向不得拉取");
    assert!(outcome.warnings.iter().any(|w| w.contains("未拉取外部")), "{:?}", outcome.warnings);
    server.verify().await;
    let captured = requests(&server).await;
    assert_eq!(captured.len(), 1, "只应有回写请求，没有 GET");
    assert_eq!(captured[0].method.as_str(), "POST");
    assert!(captured.iter().all(|r| r.method.as_str() != "GET"));
}

#[tokio::test]
pub(crate) async fn sync_pull_direction_only_reads() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/api/2/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issues": [{"key": "SEC-7", "fields": {"status": {"name": "To Do"}, "updated": "2026-01-06T00:00:00+00:00"}}],
            "total": 1
        })))
        .expect(1)
        .mount(&server)
        .await;

    let jira = jira_at(&server, 5, retry_once()).await;
    let mut filter = BTreeMap::new();
    // 即便调用方给了本地快照与「本地优先」，Pull 方向也必须只读不回写
    filter.insert(
        "local.SEC-7".to_string(),
        json!({"updated_at": "2026-01-09T00:00:00+00:00", "state": {"comment": "不应被回写"}}).to_string(),
    );
    let request = PullRequest { resource: "issues".to_string(), filter, ..PullRequest::default() };
    let outcome = CoreAdapter::sync(&jira, SyncDirection::Pull, &request).await.expect("pull 方向对账");
    assert_eq!(outcome.pulled, 1);
    assert_eq!(outcome.pushed, 0, "pull 方向不得回写");
    assert_eq!(outcome.skipped, 0, "Pull 方向不做比对（本地快照被忽略）");
    server.verify().await;
    let captured = requests(&server).await;
    assert_eq!(captured.len(), 1);
    assert!(captured.iter().all(|r| r.method.as_str() == "GET"));
}
