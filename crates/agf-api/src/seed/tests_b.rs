//! 灌库单元测试（下）：后 12 个用例（自 seed.rs 拆出，断言未改）。

#![cfg_attr(test, allow(clippy::panic, clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines))]

use super::tests_a::*;
use super::*;
use serde_json::json;

#[test]
fn missing_directory_degrades_without_error() {
    let store = ApiStore::offline();
    let report =
        seed_demo_data(&store, Path::new("no/such/seed/dir"), tenant(), &QuotaDefaults::default(), &sample_library())
            .expect("目录缺失必须降级而不是返回错误");

    assert!(report.total_errors() > 0 || report.warnings.len() >= 5, "降级必须如实记录");
    assert!(!report.warnings.is_empty());
    assert_eq!(report.inserted(DS_ASSETS), 0);
    assert_eq!(report.inserted(DS_FINDINGS), 0);
    assert!(store.asset_list_all(tenant()).unwrap().is_empty());
    assert!(store.finding_list_all(tenant()).unwrap().is_empty());
    // 合成对象不依赖目录，仍应就绪
    assert_eq!(report.inserted(DS_SCANS), 2);
    assert_eq!(report.inserted(DS_REPORTS), 2);
    assert_eq!(report.inserted(DS_QUOTAS), 4);
}

#[test]
fn broken_and_partial_datasets_degrade_per_item() {
    let dir = std::env::temp_dir().join(format!("agf-seed-broken-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("创建临时目录失败");
    // assets.json：整体非法 JSON → 该数据集降级跳过
    std::fs::write(dir.join("assets.json"), "{ this is not json").expect("写文件失败");
    // findings.json：合法 JSON 但单条缺字段 → 只跳过该条
    std::fs::write(
        dir.join("findings.json"),
        serde_json::to_string(&json!({
            "dataset": "findings",
            "count": 2,
            "items": [
                { "id": "fnd-x", "title": "缺 severity", "domain": "runtime", "asset_id": "ast-agent-0001" },
                {
                    "id": "fnd-good",
                    "title": "合法条目",
                    "severity": "high",
                    "domain": "runtime",
                    "category": "prompt-injection",
                    "asset_id": "ast-agent-0001",
                    "detected_at": "2026-02-21T10:12:03Z"
                }
            ]
        }))
        .expect("序列化失败"),
    )
    .expect("写文件失败");

    let store = ApiStore::offline();
    let report = seed_demo_data(&store, &dir, tenant(), &QuotaDefaults::default(), &sample_library())
        .expect("坏数据必须降级而不是返回错误");

    let assets = report.datasets.get(DS_ASSETS).expect("assets 数据集应有统计");
    assert_eq!(assets.inserted, 0);
    assert_eq!(assets.skipped, 1, "整体解析失败记 skipped");
    // findings 引用的资产未灌入 → 引用不解析计 error；同时 count=2 与实际 2 条一致
    let findings = report.datasets.get(DS_FINDINGS).expect("findings 数据集应有统计");
    assert_eq!(findings.errors, 2, "缺字段 1 条 + 资产引用未解析 1 条");
    assert_eq!(findings.inserted, 1, "合法条目仍应写入");
    assert_eq!(store.finding_list_all(tenant()).unwrap().len(), 1);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn empty_case_library_skips_campaign_gracefully() {
    let store = ApiStore::offline();
    let report = seed_demo_data(
        &store,
        &fixtures_dir(),
        tenant(),
        &QuotaDefaults::default(),
        &CaseLibrary::from_cases(Vec::new()),
    )
    .expect("空用例库必须降级");
    assert_eq!(report.inserted(DS_CAMPAIGNS), 0);
    assert!(store.campaign_list(tenant()).unwrap().is_empty());
    assert!(report.warnings.iter().any(|w| w.contains(DS_CAMPAIGNS)), "应记录降级原因：{:?}", report.warnings);
}

#[test]
fn report_summary_lists_datasets() {
    let store = ApiStore::offline();
    let report = seed_once(&store, &fixtures_dir());
    let summary = report.summary();
    assert!(summary.contains("assets 8"), "{summary}");
    assert!(summary.contains("findings 6"), "{summary}");
    assert!(summary.contains("失败 0 条"), "{summary}");
    assert_eq!(report.datasets.get(DS_ASSETS).map(|d| d.file.as_str()), Some("assets.json"));
}

// ------------------------------------------------------------------
// 由真实组件产出的数据（拦截审计 / 计量 / 剧本执行 / 工具清单 / 路由策略）
// ------------------------------------------------------------------

#[test]
fn mcp_assets_carry_a_real_tool_list() {
    let store = ApiStore::offline();
    seed_once(&store, &fixtures_dir());
    let mcp = store
        .asset_get(tenant(), deterministic_id(NS_ASSET, "ast-mcp-0001"))
        .expect("读取失败")
        .expect("MCP 资产应存在");
    let tools = mcp.attributes.get("tools").and_then(Value::as_array).expect("MCP 资产必须带 tools 清单");
    assert!(tools.len() >= 3, "工具清单至少 3 条: {tools:?}");
    assert!(tools.iter().all(|t| t.get("name").and_then(Value::as_str).is_some()), "{tools:?}");
    // tool_count 必须与清单同源（列表页计数与详情条目不能对不上）
    assert_eq!(mcp.attributes.get("tool_count").and_then(Value::as_u64), Some(tools.len() as u64));
}

#[test]
fn route_policies_point_at_ledger_endpoints_only() {
    let store = ApiStore::offline();
    let report = seed_once(&store, &fixtures_dir());
    assert_eq!(report.inserted(DS_ROUTE_POLICIES), 2);
    let policies = store.route_policy_list(tenant()).expect("读取失败");
    assert_eq!(policies.len(), 2);
    let endpoint_id = deterministic_id(NS_ASSET, "ast-model-0001");
    for policy in &policies {
        assert_eq!(policy.primary_endpoint_id, endpoint_id.to_string(), "主端点必须指向台账里真实存在的模型端点");
        assert!(policy.fallback_endpoint_ids.is_empty(), "台账只有 1 个模型端点：降级链不得编造: {policy:?}");
        assert!(policy.enabled);
    }
    // 租户隔离：别的租户读不到
    assert!(store.route_policy_list(TenantId::new()).expect("读取失败").is_empty());
}

#[test]
fn priced_mock_model_usage_preserves_tokens_without_provider_charges() {
    let store = ApiStore::offline();
    let mut report = seed_demo_data(&store, &fixtures_dir(), tenant(), &QuotaDefaults::default(), &sample_library())
        .expect("灌库失败");
    let meter = Meter::new();
    seed_model_usage(&store, &meter, tenant(), &mut report).expect("计量灌入失败");

    assert_eq!(report.inserted(DS_MODEL_USAGE), DEMO_MODEL_PROMPTS.len());
    let totals = meter.tenant_totals(tenant());
    assert_eq!(totals.calls, DEMO_MODEL_PROMPTS.len() as u64);
    assert!(totals.prompt_tokens > 0, "输入 token 必须由真实 estimator 给出: {totals:?}");
    assert!(totals.completion_tokens > 0);
    // 演示台账即使有单价，实际 Mock 调用也没有上游费用。
    assert_eq!(totals.cost_micro, 0, "Mock 必须保留用量而不产生厂商费用: {totals:?}");
    assert_eq!(totals.mocked_calls, DEMO_MODEL_PROMPTS.len() as u64, "无凭据走 Mock 必须如实标记");
    assert_eq!(totals.cache_hits, 0);
    let recent = meter.recent(Meter::MAX_RECENT);
    assert_eq!(recent.len(), DEMO_MODEL_PROMPTS.len());
    assert!(recent.iter().all(|record| record.mocked && record.cost_micro == 0));
    assert_eq!(recent.iter().map(|record| record.prompt_tokens).sum::<u64>(), totals.prompt_tokens);
    assert_eq!(recent.iter().map(|record| record.completion_tokens).sum::<u64>(), totals.completion_tokens);
    assert_eq!(recent[0].endpoint_id, deterministic_id(NS_ASSET, "ast-model-0001"), "端点必须是台账里的模型端点");

    // 幂等：同一 Meter 再灌一次不产生重复行
    seed_model_usage(&store, &meter, tenant(), &mut report).expect("二次计量灌入失败");
    assert_eq!(meter.tenant_totals(tenant()).calls, DEMO_MODEL_PROMPTS.len() as u64);
}

#[test]
fn model_usage_degrades_without_endpoint_asset() {
    let store = ApiStore::offline();
    let mut report = SeedReport::new(Path::new("no/such/dir"));
    let meter = Meter::new();
    seed_model_usage(&store, &meter, tenant(), &mut report).expect("没有模型端点时必须降级而不是报错");
    assert_eq!(meter.tenant_totals(tenant()).calls, 0);
    assert!(report.warnings.iter().any(|w| w.contains(DS_MODEL_USAGE)), "{:?}", report.warnings);
}

#[test]
fn soar_runs_come_from_a_real_playbook_execution() {
    let store = ApiStore::offline();
    let report = seed_once(&store, &fixtures_dir());

    let cases = store.case_list(tenant()).expect("读取失败");
    assert_eq!(cases.len(), 2);
    assert_eq!(report.inserted(DS_SOAR_RUNS), cases.len(), "每个案件执行一次演示剧本");
    for case in &cases {
        let runs = store.soar_run_list(tenant(), case.id).expect("读取失败");
        assert_eq!(runs.len(), 1);
        let record = &runs[0];
        // 轨迹来自引擎：剧本键、逐步 StepTrace、审批步骤都在
        assert_eq!(record.run.playbook_key, "demo-contain-high-risk");
        assert_eq!(record.run.tenant_id, tenant());
        assert_eq!(record.run.case_id, Some(case.id));
        assert!(!record.run.dry_run, "真实执行（不是空转）");
        assert!(record.run.steps() >= 5, "5 步剧本应有 5 条轨迹: {:?}", record.run.trace);
        assert!(!record.run.has_failure(), "Mock 执行器 + 批准的审批门下不应有失败步: {:?}", record.run.trace);
        assert!(record.run.outcome.is_success());
        assert!(record.run.trace.iter().any(|t| t.kind == "approval"), "审批步骤必须留痕");
        assert!(
            record.run.executed_actions().iter().any(|a| a == "隔离 Agent"),
            "动作步骤应由注入执行器真实执行: {:?}",
            record.run.executed_actions()
        );
        // 案件隔离：别的案件/租户取不到
        assert!(store.soar_run_list(TenantId::new(), case.id).expect("读取失败").is_empty());
    }
    // 幂等
    let before = store.soar_run_list(tenant(), cases[0].id).expect("读取失败").len();
    let mut second = SeedReport::new(&fixtures_dir());
    seed_soar_runs(&store, tenant(), &mut second).expect("二次执行失败");
    assert_eq!(second.inserted(DS_SOAR_RUNS), 0, "已有运行记录时必须跳过");
    assert_eq!(store.soar_run_list(tenant(), cases[0].id).expect("读取失败").len(), before);
}

#[test]
fn soar_runs_degrade_without_cases() {
    let store = ApiStore::offline();
    let mut report = SeedReport::new(Path::new("no/such/dir"));
    seed_soar_runs(&store, tenant(), &mut report).expect("没有案件时必须降级而不是报错");
    assert_eq!(report.inserted(DS_SOAR_RUNS), 0);
    assert!(report.warnings.iter().any(|w| w.contains(DS_SOAR_RUNS)), "{:?}", report.warnings);
}

#[test]
fn runtime_events_are_produced_by_the_engine_itself() {
    let store = ApiStore::offline();
    let mut report = seed_demo_data(&store, &fixtures_dir(), tenant(), &QuotaDefaults::default(), &sample_library())
        .expect("灌库失败");
    let runtime = RuntimeEngine::in_memory(Vec::new(), Vec::new(), agf_runtime::engine::EngineConfig::default())
        .expect("引擎构造失败");
    assert!(runtime.audit().by_tenant(tenant()).is_empty(), "灌库前审计链应为空（这正是原缺陷）");

    seed_runtime_interceptions(&runtime, tenant(), &mut report).expect("运行时拦截灌入失败");
    assert_eq!(report.inserted(DS_RUNTIME_EVENTS), DEMO_MCP_PAYLOADS.len() + DEMO_POINT_PROBES.len());

    let records = runtime.audit().by_tenant(tenant());
    assert!(records.len() >= 4, "至少 4 条拦截记录: {}", records.len());
    let blocked: Vec<&agf_runtime::audit::InterceptionRecord> =
        records.iter().filter(|r| r.verdict.is_blocking()).collect();
    assert!(blocked.len() >= 3, "至少 3 条真实拦截（curl|bash、id_rsa、mkfs）: {blocked:?}");
    // 命中的是内置黑名单规则（引擎自己给出的原因），不是本模块编的原因
    assert!(blocked.iter().any(|r| r.reason.contains("cmd.curl-pipe-sh")), "{blocked:?}");
    assert!(blocked.iter().any(|r| r.reason.contains("path.ssh-id-rsa")));
    assert!(blocked.iter().any(|r| r.reason.contains("cmd.mkfs")));
    // 对照：正常读取被放行（也有审计记录，但 verdict 不是拦截）
    assert!(
        records.iter().any(|r| r.intercept_point.as_str() == "mcp-proxy" && !r.verdict.is_blocking()),
        "对照载荷应被放行并留痕: {records:?}"
    );
    // 拦截点覆盖：三个点都有拦截记录（与 /runtime/intercept-points 的 blocked_24h 同源）
    for point in ["mcp-proxy", "process-hook", "ai-gateway"] {
        assert!(blocked.iter().any(|r| r.intercept_point.as_str() == point), "{point} 应有拦截记录: {blocked:?}");
    }
    // 哈希链完整性（引擎自己的校验）
    assert!(runtime.audit().verify().passed, "拦截审计哈希链必须可校验");

    // 幂等：再来一次不追加
    let before = runtime.audit().by_tenant(tenant()).len();
    seed_runtime_interceptions(&runtime, tenant(), &mut report).expect("二次调用失败");
    assert_eq!(runtime.audit().by_tenant(tenant()).len(), before);
}

#[test]
fn runtime_seeding_is_recorded_in_summary_without_errors() {
    let store = ApiStore::offline();
    let mut report = seed_demo_data(&store, &fixtures_dir(), tenant(), &QuotaDefaults::default(), &sample_library())
        .expect("灌库失败");
    let runtime = RuntimeEngine::in_memory(Vec::new(), Vec::new(), agf_runtime::engine::EngineConfig::default())
        .expect("引擎构造失败");
    seed_runtime_interceptions(&runtime, tenant(), &mut report).expect("灌入失败");
    assert_eq!(report.total_errors(), 0, "happy path 不应有失败条数：{:?}", report.warnings);
    assert!(report.summary().contains("runtime_events"), "{}", report.summary());
}
