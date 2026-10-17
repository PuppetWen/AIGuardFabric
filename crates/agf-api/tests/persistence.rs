//! 写后（write-behind）持久化桥：PG 是持久层、内存是读缓存。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines)]

mod common;

use common::*;

// ===========================================================================
// 19. 写后（write-behind）持久化桥：PG 是持久层、内存是读缓存
// ===========================================================================
//
// 本节**完全不依赖 PostgreSQL**（`cargo test` 无库也能过）：只验证
//   ① 仍使用写后桥的资源把写意图塞进队列；策略/凭据不得重复排队；
//   ② 队列有上限、超限丢弃并计数，且**不阻塞、不影响**内存写入（背压策略）；
//   ③ 「PG 持久层 / 内存缓存 / 最终一致（非事务性双写）」的口径与覆盖面如实进入报告与 notes。
// 真实 PG 的落库与「重启存活」由端口 18101 的人工实证覆盖（见交付说明）。

#[tokio::test]
async fn write_behind_journal_captures_persistable_writes() {
    let (h, queue, mut rx) = setup_with_journal(64).await;
    assert!(h.state.store.has_persistence(), "挂了队列就必须报告已启用写后持久化");
    assert_eq!(queue.capacity(), 64);

    // 资产发现：`AssetRepo::upsert` + `AssetRepo::snapshot` + `AssetRepo::insert_change`
    let ingested = ingest_mcp(&h, "persist-journal-01", "http://10.9.9.9:9000").await;
    assert_eq!(ingested.status, StatusCode::OK, "{}", ingested.text);

    // 策略直接保存带签名的 ConfigStore 注册表与审计，不再排队 PolicyRepo::upsert。
    // 本 harness 是离线内存发布；SQL 注册表/历史/审计的同事务持久性由 owned SQL 回归验收。
    let policy = h
        .post(
            "/api/v1/policies",
            json!({"name": "persist-journal-policy", "action": "audit", "structured": {}, "priority": 5}),
        )
        .await;
    assert_eq!(policy.status, StatusCode::CREATED, "{}", policy.text);
    let first = policy.json()["policy"].clone();
    let policy_id: agf_core::ids::Id = serde_json::from_value(first["id"].clone()).unwrap();
    assert_eq!(first["version"], 1);
    let uri = format!("/api/v1/policies/{policy_id}");
    let update = h
        .request(
            "PUT",
            &uri,
            Some(&h.admin),
            Some(json!({"name":"persist-journal-policy","action":"audit","structured":{},
                "priority":6,"expected_version":1})),
        )
        .await;
    assert_eq!(update.status, StatusCode::OK, "{}", update.text);
    let current = update.json()["policy"].clone();
    assert_eq!(current["version"], 2);
    let read = h.get(&uri).await;
    assert_eq!(read.status, StatusCode::OK, "{}", read.text);
    assert_eq!(read.json()["policy"], current);
    let registry = h
        .state
        .configurations
        .get::<Value>(h.tenant, "signed-policy-registry", agf_api::model_routes::tenant_record_id(h.tenant))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(registry["initialized"], true);
    assert_eq!(registry["entries"][policy_id.to_string()], current);
    assert_eq!(registry["history"][policy_id.to_string()], json!([first]));
    let history = h.get(&format!("{uri}/versions")).await;
    assert_eq!(history.status, StatusCode::OK, "{}", history.text);
    assert_eq!(history.json()["versions"], json!([first, current]));
    let signer = agf_api::policy_store::signer(&h.state).unwrap();
    for value in [&first, &current] {
        let row: agf_core::policy::Policy = serde_json::from_value(value.clone()).unwrap();
        assert_eq!((row.tenant_id, row.id), (h.tenant, policy_id));
        assert_eq!(row.content_hash, row.compute_hash());
        signer.verify(&row).expect("注册表与历史的 HMAC 必须验证成功");
    }
    let policy_id_text = policy_id.to_string();
    let audits = h.state.store.audit_chain_durable(h.tenant, 0, i64::MAX).await.unwrap();
    let policy_audits = audits
        .iter()
        .filter(|entry| entry.target.kind == "policy" && entry.target.id.as_deref() == Some(policy_id_text.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(policy_audits.len(), 2, "创建与修订各有一次原子成功审计");
    for (audit, (action, version)) in policy_audits.iter().zip([("create", 1), ("update", 2)]) {
        assert_eq!(audit.action.as_str(), action);
        assert_eq!(audit.outcome, agf_core::audit::AuditOutcome::Success);
        assert_eq!(audit.after.as_ref().unwrap()["version"], version);
    }
    assert!(h.state.store.audit_verify_durable(h.tenant).await.unwrap().passed);

    // 发现：`FindingRepo::insert`（没有 HTTP 创建入口——发现由扫描/灌库产出；这里直接走同一写方法）
    let finding = agf_core::risk::Finding::new(
        h.tenant,
        agf_core::enums::RiskDomain::CredentialLeak,
        agf_core::enums::Severity::High,
        "persist-journal-target",
        "写后桥发现",
        "写后桥必须把发现落 PG",
        "轮换凭据",
    );
    h.state.store.finding_insert(&finding).expect("写入发现失败");

    // 告警：`AlertRepo::upsert_dedup` + `AlertRepo::set_state`
    let alert =
        h.post("/api/v1/alerts", json!({"title": "写后桥告警", "description": "最终一致", "severity": "high"})).await;
    assert_eq!(alert.status, StatusCode::CREATED, "{}", alert.text);
    let alert_id = alert.json()["alert_id"].as_str().unwrap_or_default().to_string();
    let stated =
        h.post(&format!("/api/v1/alerts/{alert_id}/state"), json!({"state": "acknowledged", "assignee": "soc"})).await;
    assert_eq!(stated.status, StatusCode::OK, "{}", stated.text);

    // 案件：`CaseRepo::create` + `CaseRepo::add_event`
    let case = h.post("/api/v1/cases", json!({"title": "写后桥案件", "summary": "最终一致", "severity": "high"})).await;
    assert_eq!(case.status, StatusCode::CREATED, "{}", case.text);

    // API Key：`ApiKeyRepo::insert`（**服务凭据必须落库**，否则 agf-server 重启后
    // 调度器的 `asset-inventory` / `rule-hot-reload` 必然 401 —— 本轮修的真 bug）
    let key = h
        .post(
            "/api/v1/settings/api-keys",
            json!({"name": "persist-journal-key", "scopes": ["assets:read", "policies:write"]}),
        )
        .await;
    assert_eq!(key.status, StatusCode::CREATED, "{}", key.text);
    assert!(!key.json()["plaintext"].as_str().unwrap_or_default().is_empty(), "明文只在本次响应里出现");

    let mut labels = Vec::new();
    while let Ok(intent) = rx.try_recv() {
        labels.push(intent.label());
    }
    for expected in [
        "asset.upsert",
        "asset.snapshot",
        "asset.change",
        "finding.insert",
        "alert.dedup",
        "alert.set-state",
        "case.create",
        "case.add-event",
    ] {
        assert!(labels.contains(&expected), "缺少写意图 {expected}: {labels:?}");
    }
    assert!(!labels.contains(&"policy.upsert"), "策略注册表与审计已原子发布，不得重复非事务写后排队");
    assert!(!labels.contains(&"api-key.insert"), "凭据改为事务直写，不得重复写后排队");
    let (queued, applied, failed, dropped, remapped, depth) = queue.stats().snapshot();
    assert_eq!(queued as usize, labels.len(), "入队计数必须等于实际收到的写意图数");
    assert_eq!(depth, labels.len(), "没有消费者时队列深度等于入队数");
    assert_eq!(
        (applied, failed, dropped, remapped),
        (0, 0, 0, 0),
        "无消费者/无 PG 时不得有落库、失败、丢弃或 id 重映射"
    );
}

#[tokio::test]
async fn write_queue_drops_over_capacity_without_blocking_writes() {
    // 上限 2：第 3 条写意图必须被丢弃并计数，但**内存写入照常生效**（请求不受队列影响）。
    let (h, queue, mut rx) = setup_with_journal(2).await;
    for index in 0..3 {
        let asset = agf_core::asset::Asset::new(
            h.tenant,
            agf_core::enums::AssetKind::Agent,
            format!("drop-{index}"),
            format!("fp-drop-{index}"),
        );
        h.state.store.asset_upsert(&asset).expect("写内存失败");
        assert!(
            h.state.store.asset_get(h.tenant, asset.id).expect("读内存失败").is_some(),
            "队列满不得影响内存写入（内存是权威副本）"
        );
    }
    let (queued, applied, failed, dropped, remapped, depth) = queue.stats().snapshot();
    assert_eq!((queued, dropped, depth), (2, 1, 2), "上限 2：入队 2 条、丢弃 1 条、深度 2");
    assert_eq!((applied, failed, remapped), (0, 0, 0));

    let mut labels = Vec::new();
    while let Ok(intent) = rx.try_recv() {
        labels.push(intent.label());
    }
    assert_eq!(labels, vec!["asset.upsert", "asset.upsert"], "队列里只能是前 2 条写意图（顺序与内存写入一致）");
}

#[tokio::test]
async fn offline_state_reports_no_persistence_bridge() {
    let h = setup().await;
    assert!(h.state.persistence.is_none(), "离线模式不得装配持久化桥");
    assert!(!h.state.store.has_persistence(), "离线模式的 ApiStore 不得有写后队列");

    let text = h
        .request("GET", "/readyz", None, None)
        .await
        .json()
        .get("notes")
        .and_then(Value::as_array)
        .map(|notes| notes.iter().filter_map(Value::as_str).collect::<Vec<_>>().join("\n"))
        .unwrap_or_default();
    assert!(text.contains("离线内存模式：无写后持久化桥"), "必须如实说明没有持久化桥: {text}");
    assert!(!text.contains("已落 PostgreSQL 的资源"), "离线模式不得宣称已落 PG: {text}");
    assert!(
        !text.contains("资源读写尚未切到 agf-storage 的 SQL 仓储"),
        "旧口径（未落地的 TODO(api-persistence)）必须被新口径取代: {text}"
    );
}

#[test]
fn persistence_report_declares_durability_scope_honestly() {
    for resource in ["assets", "findings", "policies", "alerts", "cases", "audit_logs", "api_keys"] {
        assert!(DURABLE_RESOURCES.contains(&resource), "已落 PG 的清单缺少 {resource}");
    }
    for resource in ["quotas", "quota_usage", "reports", "report_schedules"] {
        assert!(MEMORY_ONLY_RESOURCES.contains(&resource), "仅内存清单缺少 {resource}");
    }
    // 一致性口径必须**明确**写清：PG 是持久层、内存是缓存、最终一致、非事务性双写、留 TODO 锚点。
    let line = PersistenceReport::consistency_line();
    for needle in ["PostgreSQL 为持久层", "内存为读缓存", "最终一致", "非事务性双写", "TODO(api-persistence-tx)"]
    {
        assert!(line.contains(needle), "一致性口径缺少「{needle}」: {line}");
    }
    // 写意图标签是日志/最近错误的定位键，必须稳定。
    let asset = agf_core::asset::Asset::new(TenantId::default_tenant(), agf_core::enums::AssetKind::Agent, "a", "fp-a");
    assert_eq!(PgWrite::AssetUpsert { asset: Box::new(asset.clone()) }.label(), "asset.upsert");
    assert_eq!(PgWrite::AssetUpsert { asset: Box::new(asset) }.tenant(), TenantId::default_tenant());
}

#[test]
fn case_code_round_trips_for_sequence_recovery() {
    // 水合必须恢复 `case_seq`：否则重启后新建案件会与 PG 里已有编号撞 `ux_cases_code`。
    let code = agf_core::case::Case::make_code(2031, 7);
    assert_eq!(code, "CASE-2031-0007");
    assert_eq!(agf_api::store::parse_case_code(&code), Some((2031, 7)));
    assert_eq!(agf_api::store::parse_case_code("CASE-2031"), None);
    assert_eq!(agf_api::store::parse_case_code("X-2031-0007"), None);
    assert_eq!(agf_api::store::parse_case_code("CASE-nope-0007"), None);
}

// ---------- 拦截点 p95 时延 / KPI 历史持久化（本轮新增能力） ----------

#[tokio::test]
async fn intercept_points_p95_and_throughput_come_from_real_seeded_interceptions() {
    let h = setup_console().await;
    // 用**真实引擎**灌演示拦截（`AGF_SEED_FIXTURES` 走的就是这条路径）：
    // 每条记录都带拦截入口实测的 `latency_micros`。
    let mut report = agf_api::seed::SeedReport::default();
    agf_api::seed::seed_runtime_interceptions(&h.state.runtime, h.tenant, &mut report).expect("演示拦截灌入失败");

    let chain = h.state.runtime.audit().by_tenant(h.tenant);
    assert!(!chain.is_empty(), "演示载荷必须真的在拦截链上留下记录");
    let mcp_records: Vec<_> = chain.iter().filter(|record| record.intercept_point.as_str() == "mcp-proxy").collect();
    assert!(!mcp_records.is_empty(), "mcp-proxy 点必须有记录");
    assert!(mcp_records.iter().all(|record| record.latency_micros > 0), "MCP 拦截记录必须带真实耗时");

    let body = h.get("/api/v1/runtime/intercept-points").await.json();
    let rows = body.as_array().expect("必须是裸数组");
    let mcp = rows.iter().find(|row| row["point"] == "mcp-proxy").expect("必须有 mcp-proxy 行");
    assert_eq!(
        mcp["throughput_per_min"].as_i64(),
        Some(mcp_records.len() as i64),
        "吞吐必须等于最近 60 秒落在该点上的链上条数: {body}"
    );
    // 微秒样本向上取整 ⇒ 有真实样本就**必须**非零（不再是"恒为 0"）
    let p95 = mcp["p95_latency_ms"].as_i64().unwrap_or(0);
    assert!(p95 >= 1, "p95 必须来自真实耗时样本（有样本即 ≥ 1ms）: {body}");
}

#[test]
fn risk_history_file_round_trips_the_in_process_series() {
    // 装配侧（`state.rs`）将要写的三条调用：points → Sample → save_to → load_from → group_by_tenant。
    let started = Timestamp::now();
    let history = agf_api::state::RiskHistory::new(started);
    let tenant = TenantId::default_tenant();
    history.record(tenant, started, 5.0);
    history.record(tenant, started.offset_secs(3_600), 9.0);

    let samples =
        agf_api::history::from_points(tenant, history.points(tenant).into_iter().map(|point| (point.at, point.value)));
    assert_eq!(samples.len(), 2, "保留两次跨小时实际观测");

    let path =
        std::env::temp_dir().join(format!("agf-api-risk-history-{}-roundtrip.json", Timestamp::now().unix_millis()));
    agf_api::history::save_to(&path, &samples);
    assert!(path.exists(), "原子写必须落地");

    let loaded = agf_api::history::load_from(&path).expect("加载失败");
    let grouped = agf_api::history::group_by_tenant(&loaded);
    let series = grouped.get(&tenant).expect("必须有该租户的序列");
    assert_eq!(series.len(), samples.len(), "往返不得丢点: {series:?}");
    assert!((series[0].value - 5.0).abs() < 1e-9, "首次实际观测: {series:?}");
    assert!((series[1].value - 9.0).abs() < 1e-9, "跨小时新点: {series:?}");
    let _ = std::fs::remove_file(&path);

    // The path resolver is tested separately; this test must never overwrite deployment history.
}
