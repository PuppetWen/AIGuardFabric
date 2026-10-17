//! 工单类（Jira / ServiceNow / 禅道）的 `sync`（拉取 → 比对 → 回写）与**增量去重**往返测试。
//!
//! 断言重点：
//!
//! - **冲突策略**：外部优先（默认）时冲突**不回写**、本地优先时按策略回写，且两种情况下
//!   决策日志（`SyncOutcome.warnings`）都必须写明"哪条、按什么策略裁决"；
//! - **计数分类**：`SyncOutcome.changes` 里的 `push_local` / `conflict_external-wins` /
//!   `conflict_local-wins` 与 `pulled`/`pushed`/`skipped` 一致；
//! - **增量去重**：同页重复与跨页重复都只交付一次，游标由最大更新时间推进。
//!
//! 构造辅助（`jira_at` / `servicenow_at` / `zentao_at` / `local_snapshot`）在 `main.rs`。
use super::*;

#[tokio::test]
pub(crate) async fn jira_sync_reconciles_with_external_wins_then_local_wins() {
    let issue = json!({
        "key": "SEC-7",
        "fields": {"summary": "提示词注入", "status": {"name": "To Do"}, "updated": "2026-01-05T00:00:00+00:00"}
    });
    let local = vec![local_snapshot(
        "SEC-7",
        "2026-01-06T00:00:00+00:00",
        json!({"status": "In Progress", "transition_id": "31", "comment": "SOC 已处置"}),
    )];

    // 阶段一：默认策略「外部优先」⇒ 冲突但**不回写**
    let external_wins = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/api/2/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"issues": [issue.clone()], "total": 1})))
        .expect(1)
        .mount(&external_wins)
        .await;
    let jira = jira_at(&external_wins, 5, retry_once()).await;
    let outcome = jira.sync(&SyncRequest::new("issues").with_local(local.clone())).await.expect("对账应成功");
    assert_eq!(outcome.pulled, 1);
    assert_eq!(outcome.pushed, 0, "外部优先：冲突时不得回写");
    assert_eq!(outcome.skipped, 1);
    assert_eq!(outcome.changes.get("conflict_external-wins").copied(), Some(1));
    assert!(
        outcome.warnings.iter().any(|w| w.contains("conflict-external-wins") && w.contains("SEC-7")),
        "决策日志必须写明哪条、按什么策略裁决: {:?}",
        outcome.warnings
    );
    assert_eq!(requests(&external_wins).await.len(), 1, "外部优先下只发拉取请求，绝不回写");
    external_wins.verify().await;

    // 阶段二：显式「本地优先」⇒ 同一份输入必须回写（状态推进 + 评论）
    let local_wins = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/api/2/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"issues": [issue], "total": 1})))
        .expect(1)
        .mount(&local_wins)
        .await;
    Mock::given(method("PUT"))
        .and(path("/rest/api/2/issue/SEC-7/transitions"))
        .and(body_partial_json(json!({"transition": {"id": "31"}})))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&local_wins)
        .await;
    Mock::given(method("POST"))
        .and(path("/rest/api/2/issue/SEC-7/comment"))
        .and(body_partial_json(json!({"body": "SOC 已处置"})))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": "10002"})))
        .expect(1)
        .mount(&local_wins)
        .await;

    let jira = jira_at(&local_wins, 5, retry_once()).await;
    let outcome = jira
        .sync(&SyncRequest::new("issues").with_local(local).with_conflict_policy(ConflictPolicy::LocalWins))
        .await
        .expect("对账应成功");
    assert_eq!(outcome.pushed, 1);
    assert_eq!(outcome.failed, 0);
    assert!(!outcome.degraded);
    assert_eq!(
        outcome.changes.get("push_local").copied(),
        Some(1),
        "本地更新且外部未变 ⇒ 非冲突回写（本地优先下无需裁决）"
    );
    assert_eq!(outcome.pulled, 1);
    local_wins.verify().await;
    assert_eq!(requests(&local_wins).await.len(), 3, "拉取 + 状态推进 + 评论");
}

#[tokio::test]
pub(crate) async fn servicenow_sync_reconciles_local_case_conflicts() {
    const SYS_ID: &str = "9d385017c611228701d22104cc95c371";
    let record = json!({
        "sys_id": SYS_ID, "number": "INC0010001", "state": "1",
        "sys_updated_on": "2026-01-05 00:00:00", "short_description": "凭据泄露"
    });
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/now/table/incident"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"result": [record]})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path(format!("/api/now/table/incident/{SYS_ID}")))
        .and(body_partial_json(json!({"state": "6", "work_notes": "本地已关闭：误报"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"result": {"sys_id": SYS_ID, "state": "6"}})))
        .expect(1)
        .mount(&server)
        .await;

    let servicenow = servicenow_at(&server, 5, retry_once()).await;
    let outcome = servicenow
        .sync(
            &SyncRequest::new("incident")
                .with_local(vec![local_snapshot(
                    SYS_ID,
                    // 与外部 `sys_updated_on` 相同但状态不同 ⇒ 时间戳无法判定先后 = 真冲突
                    "2026-01-05T00:00:00+00:00",
                    json!({"state": "6", "work_notes": "本地已关闭：误报"}),
                )])
                .with_conflict_policy(ConflictPolicy::LocalWins),
        )
        .await
        .expect("对账应成功");
    assert_eq!(outcome.pulled, 1);
    assert_eq!(outcome.pushed, 1);
    assert_eq!(outcome.changes.get("conflict_local-wins").copied(), Some(1), "时间戳相同 ⇒ 真冲突，按策略回写");
    assert!(outcome.warnings.iter().any(|w| w.contains("本地优先")), "{:?}", outcome.warnings);
    server.verify().await;
}

#[tokio::test]
pub(crate) async fn zentao_sync_reconciles_with_local_wins_policy() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api.php/v1/bugs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "bugs": [{"id": 123, "status": "active", "lastEditedDate": "2026-01-01T00:00:00+00:00"}]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/api.php/v1/bugs/123"))
        .and(body_partial_json(json!({"status": "closed", "comment": "本地判定为误报，直接关闭"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": 123, "status": "closed"})))
        .expect(1)
        .mount(&server)
        .await;

    let zentao = zentao_at(&server, 5, retry_once()).await;
    let outcome = zentao
        .sync(
            &SyncRequest::new("bugs")
                .with_local(vec![local_snapshot(
                    "123",
                    "2026-01-02T00:00:00+00:00",
                    json!({"status": "closed", "comment": "本地判定为误报，直接关闭"}),
                )])
                .with_conflict_policy(ConflictPolicy::LocalWins),
        )
        .await
        .expect("对账应成功");
    assert_eq!(outcome.pulled, 1);
    assert_eq!(outcome.pushed, 1);
    assert_eq!(outcome.skipped, 0);
    assert_eq!(outcome.changes.get("push_local").copied(), Some(1), "本地更新且外部未变 ⇒ 回写");
    assert!(outcome.warnings.iter().any(|w| w.contains("push-local")), "{:?}", outcome.warnings);
    server.verify().await;
}

#[tokio::test]
pub(crate) async fn pull_deduplicates_repeated_items_across_pages() {
    let server = MockServer::start().await;
    let page = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let responder = std::sync::Arc::clone(&page);
    Mock::given(method("GET"))
        .and(path("/api.php/v1/bugs"))
        .respond_with(move |_request: &wiremock::Request| {
            let index = responder.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let bugs = if index == 0 {
                // 第一页：同一条重复出现（上游分页边界常见）
                json!({"bugs": [
                    {"id": 1, "status": "active", "lastEditedDate": "2026-01-01T00:00:00+00:00"},
                    {"id": 1, "status": "active", "lastEditedDate": "2026-01-01T00:00:00+00:00"}
                ]})
            } else {
                // 第二页：再次返回上一次的最后一条 + 一条新条目
                json!({"bugs": [
                    {"id": 1, "status": "active", "lastEditedDate": "2026-01-01T00:00:00+00:00"},
                    {"id": 2, "status": "active", "lastEditedDate": "2026-01-02T00:00:00+00:00"}
                ]})
            };
            ResponseTemplate::new(200).set_body_json(bugs)
        })
        .expect(2)
        .mount(&server)
        .await;

    let zentao = zentao_at(&server, 5, retry_once()).await;
    let request = PullRequest { resource: "bugs".to_string(), limit: None, ..PullRequest::default() };
    let first = zentao.pull(&request).await.expect("第一页");
    assert_eq!(first.items.len(), 1, "同页重复条目必须去重");
    assert_eq!(first.items[0]["agf_remote_id"], "1");

    let second = zentao.pull(&request).await.expect("第二页");
    assert_eq!(second.items.len(), 1, "跨页重复条目必须去重");
    assert_eq!(second.items[0]["agf_remote_id"], "2");
    assert_eq!(second.next_cursor.as_deref(), Some("2026-01-02T00:00:00.000Z"), "游标由最大更新时间推进");
    server.verify().await;
}
