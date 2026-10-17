//! 工单类（Jira / ServiceNow / 禅道）的 `push` / `pull` **真实往返**（wiremock）。
//!
//! 每个断言都覆盖**方法 / 路径 / 请求头 / JSON 请求体**，并在返回侧覆盖**解析与归一化**：
//!
//! - `push`：断言两次调用（Jira 状态推进 + 评论）的顺序与报文，以及回执 `remote_id`；
//! - `pull`：断言增量参数（JQL `updated >=` / `sysparm_query=sys_updated_on>=` / 客户端 `since` 过滤）
//!   与归一化字段（`agf_remote_id` / `agf_updated_at` / `agf_state`）；
//! - `sync`（拉取 → 裁决 → 回写）与**跨页去重**见 `semantics_sync.rs`。
//!
//! 构造辅助（`jira_at` / `servicenow_at` / `zentao_at` / `push_payload` / `local_snapshot`）在 `main.rs`。
//! 全部零外网：HTTP 走 `wiremock` 的 `127.0.0.1` 随机端口。
use super::*;

// ---------------------------------------------------------------------------
// Jira
// ---------------------------------------------------------------------------

#[tokio::test]
pub(crate) async fn jira_push_posts_transition_then_comment_with_exact_method_path_and_body() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/rest/api/2/issue/SEC-7/transitions"))
        .and(header("content-type", "application/json"))
        .and(body_partial_json(json!({ "transition": { "id": "31" } })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/rest/api/2/issue/SEC-7/comment"))
        .and(header("content-type", "application/json"))
        .and(body_partial_json(json!({ "body": "SOC 已处置，转 In Progress" })))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(json!({"id": "10001", "body": "SOC 已处置，转 In Progress"})),
        )
        .expect(1)
        .mount(&server)
        .await;

    let jira = jira_at(&server, 5, retry_once()).await;
    let payload = push_payload(
        "ticket.status",
        "SEC-7",
        json!({"status": "In Progress", "transition_id": "31", "comment": "SOC 已处置，转 In Progress"}),
    );
    let outcome = jira.push(&payload).await.expect("回写应成功");
    assert_eq!(outcome.requests, 2, "状态推进 + 评论 = 两次调用");
    assert!(!outcome.mocked);
    assert_eq!(outcome.attempts, 1);
    assert_eq!(outcome.remote_id.as_deref(), Some("10001"), "末次响应（评论）的 id 进回执");
    server.verify().await;

    let captured = requests(&server).await;
    assert_eq!(captured.len(), 2);
    assert_eq!(captured[0].method.as_str(), "PUT", "先推进状态");
    assert_eq!(captured[0].url.path(), "/rest/api/2/issue/SEC-7/transitions");
    assert_eq!(captured[1].method.as_str(), "POST", "后写评论");
    assert_eq!(captured[1].url.path(), "/rest/api/2/issue/SEC-7/comment");
    let auth = captured[0].headers.get("authorization").expect("Jira 必须带鉴权头").to_str().unwrap_or_default();
    assert!(auth.starts_with("Basic "), "Jira 用 Basic 鉴权: {auth}");
    for request in &captured {
        assert_eq!(
            request.headers.get("idempotency-key").expect("回写必须带幂等键").to_str().unwrap_or_default(),
            "idem-fixed-1"
        );
    }
    let body: Value = captured[1].body_json().expect("JSON 体");
    assert_eq!(body["body"], "SOC 已处置，转 In Progress");
}

#[tokio::test]
pub(crate) async fn jira_pull_searches_incrementally_with_jql_and_normalizes_items() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/api/2/search"))
        .and(header("accept", "application/json"))
        .and(query_param("jql", "project = \"SEC\" AND updated >= \"2026-01-05T00:00:00+00:00\" ORDER BY updated ASC"))
        .and(query_param("maxResults", "2"))
        .and(query_param("fields", "summary,status,updated,labels,priority"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "startAt": 0, "total": 2,
            "issues": [
                {"key": "SEC-7", "fields": {"summary": "提示词注入", "status": {"name": "To Do"}, "updated": "2026-01-06T00:00:00+00:00"}},
                {"key": "SEC-8", "fields": {"summary": "明文凭据", "status": {"name": "Done"}, "updated": "2026-01-07T00:00:00+00:00"}}
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let jira = jira_at(&server, 5, retry_once()).await;
    let response = jira
        .pull(&PullRequest {
            resource: "issues".to_string(),
            cursor: Some("2026-01-05T00:00:00+00:00".to_string()),
            limit: Some(2),
            filter: BTreeMap::new(),
        })
        .await
        .expect("增量拉取应成功");
    assert!(!response.mocked);
    assert_eq!(response.items.len(), 2);
    assert_eq!(response.items[0]["agf_remote_id"], "SEC-7");
    assert_eq!(response.items[0]["agf_updated_at"], "2026-01-06T00:00:00.000Z");
    assert_eq!(response.items[0]["agf_state"], json!({"status": "To Do"}), "归一化状态即可回写子集");
    assert_eq!(response.items[0]["key"], "SEC-7", "上游原始字段必须保留");
    assert_eq!(
        response.next_cursor.as_deref(),
        Some("2026-01-07T00:00:00.000Z"),
        "上游不给游标 ⇒ 由本页最大 updated 派生（下一轮 since，规范 RFC3339 形态）"
    );
    assert!(
        response.origin.starts_with(&format!("{}/rest/api/2/search", server.uri())),
        "origin 指向真实 endpoint: {}",
        response.origin
    );
    assert!(response.origin.contains("jql=") && response.origin.contains("maxResults="), "但查询串值已脱敏");
    server.verify().await;
}

// ---------------------------------------------------------------------------
// ServiceNow
// ---------------------------------------------------------------------------

#[tokio::test]
pub(crate) async fn servicenow_push_patches_incident_with_state_and_work_notes() {
    const SYS_ID: &str = "9d385017c611228701d22104cc95c371";
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path(format!("/api/now/table/incident/{SYS_ID}")))
        .and(header("authorization", "Bearer sn-token-abcdef"))
        .and(header("accept", "application/json"))
        .and(body_partial_json(json!({"state": "2", "work_notes": "已受理，转处理中"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": {"sys_id": SYS_ID, "number": "INC0010001", "state": "2"}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let servicenow = servicenow_at(&server, 5, retry_once()).await;
    let payload = push_payload("ticket.status", SYS_ID, json!({"state": "2", "work_notes": "已受理，转处理中"}));
    let outcome = servicenow.push(&payload).await.expect("回写应成功");
    assert_eq!(outcome.requests, 1, "ServiceNow 一次 PATCH");
    assert_eq!(outcome.remote_id.as_deref(), Some(SYS_ID));
    server.verify().await;

    let request = single_request(&server).await;
    assert_eq!(request.method.as_str(), "PATCH");
    assert_eq!(request.url.path(), format!("/api/now/table/incident/{SYS_ID}"));
    let body: Value = request.body_json().expect("JSON 体");
    assert_eq!(body["state"], "2");
    assert_eq!(body["work_notes"], "已受理，转处理中");
    assert!(body.get("correlation_id").is_none(), "回写只带要改的字段，不重发建单字段");
}

#[tokio::test]
pub(crate) async fn servicenow_pull_queries_incremental_incidents_by_sys_updated_on() {
    const SYS_ID: &str = "9d385017c611228701d22104cc95c371";
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/now/table/incident"))
        .and(header("authorization", "Bearer sn-token-abcdef"))
        .and(query_param("sysparm_query", "sys_updated_on>=2026-01-05 00:00:00^ORDERBYsys_updated_on"))
        .and(query_param("sysparm_limit", "10"))
        .and(query_param("sysparm_fields", "sys_id,number,state,sys_updated_on,short_description"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": [
                {"sys_id": SYS_ID, "number": "INC0010001", "state": "2", "sys_updated_on": "2026-01-06 08:30:00", "short_description": "提示词注入"}
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let servicenow = servicenow_at(&server, 5, retry_once()).await;
    let response = servicenow
        .pull(&PullRequest {
            resource: "incident".to_string(),
            cursor: Some("2026-01-05T00:00:00+00:00".to_string()),
            limit: Some(10),
            filter: BTreeMap::new(),
        })
        .await
        .expect("增量拉取应成功");
    assert_eq!(response.items.len(), 1);
    assert_eq!(response.items[0]["agf_remote_id"], SYS_ID);
    assert_eq!(response.items[0]["agf_state"], json!({"state": "2"}));
    assert_eq!(
        response.items[0]["agf_updated_at"], "2026-01-06T08:30:00.000Z",
        "ServiceNow 的 `YYYY-MM-DD HH:MM:SS`（UTC）必须归一为 RFC3339"
    );
    assert_eq!(response.items[0]["number"], "INC0010001", "人读单号保留在条目里");
    server.verify().await;
}

// ---------------------------------------------------------------------------
// 禅道
// ---------------------------------------------------------------------------

#[tokio::test]
pub(crate) async fn zentao_push_puts_bug_status_and_comment() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/api.php/v1/bugs/123"))
        .and(header("token", "zentao-token-abcdef"))
        .and(header("content-type", "application/json"))
        .and(body_partial_json(json!({"status": "resolved", "comment": "已修复并回归"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": 123, "status": "resolved"})))
        .expect(1)
        .mount(&server)
        .await;

    let zentao = zentao_at(&server, 5, retry_once()).await;
    let outcome = zentao
        .push(&push_payload("ticket.status", "123", json!({"status": "resolved", "comment": "已修复并回归"})))
        .await
        .expect("回写应成功");
    assert_eq!(outcome.requests, 1);
    assert_eq!(outcome.remote_id.as_deref(), Some("123"));
    server.verify().await;

    let request = single_request(&server).await;
    assert_eq!(request.method.as_str(), "PUT");
    assert_eq!(request.url.path(), "/api.php/v1/bugs/123");
    let body: Value = request.body_json().expect("JSON 体");
    assert_eq!(body["status"], "resolved");
    assert_eq!(body["comment"], "已修复并回归");
}

#[tokio::test]
pub(crate) async fn zentao_pull_reads_bugs_and_filters_since_cursor_client_side() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api.php/v1/bugs"))
        .and(header("token", "zentao-token-abcdef"))
        .and(query_param("product", "7"))
        .and(query_param("limit", "50"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "bugs": [
                {"id": 11, "status": "active", "lastEditedDate": "2026-01-01T00:00:00+00:00"},
                {"id": 12, "status": "resolved", "lastEditedDate": "2026-01-09T00:00:00+00:00"},
                {"id": 13, "status": "active"}
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let zentao = zentao_at(&server, 5, retry_once()).await;
    let response = zentao
        .pull(&PullRequest {
            resource: "bugs".to_string(),
            cursor: Some("2026-01-05T00:00:00+00:00".to_string()),
            limit: None,
            filter: BTreeMap::new(),
        })
        .await
        .expect("拉取应成功");
    let ids: Vec<&str> = response.items.iter().filter_map(|item| item["agf_remote_id"].as_str()).collect();
    assert_eq!(ids, vec!["12", "13"], "客户端 since 过滤：旧条目剔除，无时间戳条目保留（不漏数据）");
    assert_eq!(response.items[0]["agf_state"], json!({"status": "resolved"}));
    assert_eq!(response.items[0]["agf_updated_at"], "2026-01-09T00:00:00.000Z");
    server.verify().await;
}
