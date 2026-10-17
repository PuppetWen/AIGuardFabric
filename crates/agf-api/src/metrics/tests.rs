//! `metrics` 单元测试（自 `metrics.rs` 拆出，断言与原文件完全一致）。

use super::*;

#[test]
fn renders_required_metric_families() {
    let metrics = Metrics::new("0.1.0");
    assert!(metrics.is_ok());
    let Ok(metrics) = metrics else { return };
    metrics.record_request("GET", "/healthz", 200, 0.002);
    metrics.record_interception("deny");
    metrics.record_rate_limited();
    let text = metrics.render();
    assert!(text.contains("agf_http_requests_total"), "{text}");
    assert!(text.contains("agf_http_request_duration_seconds_bucket"), "{text}");
    assert!(text.contains("agf_interceptions_total"), "{text}");
    assert!(text.contains("agf_rate_limited_total"), "{text}");
    assert!(text.contains("agf_build_info"));
}

#[test]
fn counters_accumulate_without_panicking() {
    let Ok(metrics) = Metrics::new("test") else { return };
    for _ in 0..3 {
        metrics.record_request("POST", "/api/v1/auth/login", 401, 0.01);
    }
    let text = metrics.render();
    assert!(text.contains("agf_http_requests_total{method=\"POST\",path=\"/api/v1/auth/login\",status=\"401\"} 3"));
}

#[test]
fn readiness_gauge_and_inflight() {
    let Ok(metrics) = Metrics::new("test") else { return };
    metrics.set_ready(true);
    metrics.in_flight_inc();
    metrics.in_flight_dec();
    let text = metrics.render();
    assert!(text.contains("agf_ready 1"));
    assert!(text.contains("agf_http_in_flight 0"));
    assert!(text.contains("agf_build_info"));
}

#[test]
fn runtime_interception_series_exist_with_zero_traffic() {
    let Ok(metrics) = Metrics::new("test") else { return };
    let text = metrics.render();
    // 零流量下也要有序列（否则告警规则会时有时无）
    assert!(text.contains("agf_runtime_interceptions_total{action=\"deny\",point=\"mcp-proxy\"} 0"), "{text}");
    assert!(text.contains("agf_runtime_interceptions_total{action=\"allow\",point=\"egress-proxy\"} 0"), "{text}");
}

#[test]
fn ws_nats_series_exist_with_zero_traffic() {
    let Ok(metrics) = Metrics::new("test") else { return };
    let text = metrics.render();
    assert!(text.contains("agf_ws_nats_published_total 0"), "{text}");
    assert!(text.contains("agf_ws_nats_received_total 0"), "{text}");
    assert!(text.contains("agf_ws_local_fallback_total 0"), "{text}");
}

#[test]
fn interception_snapshot_windows_and_groups() {
    use agf_core::enums::{InterceptPoint, PolicyAction};
    use agf_core::ids::TenantId;
    use agf_runtime::audit::{InterceptionRecord, InterceptionVerdict};

    let now = Timestamp::now();
    let mut recent = InterceptionRecord::new(
        TenantId::default_tenant(),
        "s-1",
        InterceptPoint::McpProxy,
        InterceptionVerdict::Blocked,
        "命中黑名单",
    );
    recent.action = PolicyAction::Deny;
    recent.at = now;
    let mut old = InterceptionRecord::new(
        TenantId::default_tenant(),
        "s-2",
        InterceptPoint::AiGateway,
        InterceptionVerdict::Forwarded,
        "放行",
    );
    old.at = now.offset_secs(-600);
    let records = vec![recent, old];

    let all = interception_snapshot(&records, now, 0);
    assert_eq!(all.total, 2);
    assert_eq!(all.by_point.get("mcp-proxy").copied(), Some(1));
    assert_eq!(all.by_point_action.get(&("ai-gateway".to_string(), "allow".to_string())).copied(), Some(1));

    let windowed = interception_snapshot(&records, now, 60);
    assert_eq!(windowed.total, 1, "600 秒前的条目必须落在 60 秒窗口外");
    assert_eq!(windowed.by_point.get("ai-gateway"), None);
}

/// 构造一条带真实耗时样本的记录（`at` 显式给出，避免窗口判定被 `now` 抖动影响）。
fn latency_record(
    point: agf_core::enums::InterceptPoint,
    micros: u64,
    at: Timestamp,
) -> agf_runtime::audit::InterceptionRecord {
    let mut record = agf_runtime::audit::InterceptionRecord::new(
        agf_core::ids::TenantId::default_tenant(),
        "s-latency",
        point,
        agf_runtime::audit::InterceptionVerdict::Blocked,
        "耗时样本",
    )
    .with_latency_micros(micros);
    record.at = at;
    record
}

#[test]
fn percentile95_uses_nearest_rank() {
    assert_eq!(super::snapshot::percentile95(&[]), 0);
    assert_eq!(super::snapshot::percentile95(&[7]), 7);
    assert_eq!(super::snapshot::percentile95(&[1, 2, 3, 4, 5]), 5, "n=5 ⇒ 第 ceil(4.75)=5 名");
    assert_eq!(super::snapshot::percentile95(&(1..=20).collect::<Vec<u64>>()), 19, "n=20 ⇒ 第 19 名");
    assert_eq!(super::snapshot::percentile95(&[0, 0, 0, 1]), 1);
}

#[test]
fn latency_p95_uses_only_the_recent_window() {
    let now = Timestamp::now();
    let mcp = agf_core::enums::InterceptPoint::McpProxy;
    let mut records: Vec<_> =
        [100_u64, 200, 300, 400, 5_000].into_iter().map(|micros| latency_record(mcp, micros, now)).collect();
    // 窗口外的超大值（600 秒前，9 秒）：不得污染最近窗口的 p95
    records.push(latency_record(mcp, 9_000_000, now.offset_secs(-600)));
    records.push(latency_record(agf_core::enums::InterceptPoint::AiGateway, 2_000, now));

    let micros = interception_latency_p95_micros(&records, now, INTERCEPTION_P95_WINDOW_SECS);
    assert_eq!(micros.get("mcp-proxy").copied(), Some(5_000), "5 条样本的最近秩 p95");
    assert_eq!(micros.get("ai-gateway").copied(), Some(2_000));
    assert_eq!(micros.get("process-hook"), None, "窗口内无样本的点位不出现（不编造）");

    let millis = interception_latency_p95_ms(&records, now, INTERCEPTION_P95_WINDOW_SECS);
    assert_eq!(millis.get("mcp-proxy").copied(), Some(5), "5000µs ⇒ 5ms");
    assert_eq!(millis.get("egress-proxy"), None);

    // window <= 0：全链（把 600 秒前的 9 秒样本算进来）
    let all = interception_latency_p95_micros(&records, now, 0);
    assert_eq!(all.get("mcp-proxy").copied(), Some(9_000_000));
}

#[test]
fn sub_millisecond_p95_rounds_up_but_unmeasured_zero_stays_zero() {
    let now = Timestamp::now();
    let hook = agf_core::enums::InterceptPoint::ProcessHook;
    // 未测量（latency_micros = 0，如测试手工构造或 v0 记录）⇒ 如实 0ms，不得假造
    let zeros: Vec<_> = (0..4).map(|_| latency_record(hook, 0, now)).collect();
    assert_eq!(interception_latency_p95_ms(&zeros, now, 0).get("process-hook").copied(), Some(0));
    // 1µs 也必须在毫秒口径下非零（向上取整），否则真实分布又会显示成"恒为 0"
    let sub_millisecond = vec![latency_record(hook, 0, now), latency_record(hook, 1, now)];
    assert_eq!(interception_latency_p95_ms(&sub_millisecond, now, 0).get("process-hook").copied(), Some(1));
    let single = vec![latency_record(hook, 250, now)];
    assert_eq!(interception_latency_p95_ms(&single, now, 0).get("process-hook").copied(), Some(1));
}

#[test]
fn runtime_latency_p95_gauge_exists_with_zero_traffic() {
    let Ok(metrics) = Metrics::new("test") else { return };
    let text = metrics.render();
    assert!(text.contains("agf_runtime_interception_latency_p95_milliseconds{point=\"mcp-proxy\"} 0"), "{text}");
    assert!(text.contains("agf_runtime_interception_latency_p95_milliseconds{point=\"egress-proxy\"} 0"), "{text}");
}

#[test]
fn runtime_latency_p95_gauge_follows_the_audit_chain() {
    let Ok(runtime) = agf_runtime::engine::RuntimeEngine::in_memory(
        Vec::new(),
        Vec::new(),
        agf_runtime::engine::EngineConfig::default(),
    ) else {
        return;
    };
    let runtime = Arc::new(runtime);
    let now = Timestamp::now();
    for micros in [100_u64, 2_000, 3_000] {
        let record = latency_record(agf_core::enums::InterceptPoint::McpProxy, micros, now);
        assert!(runtime.record_interception(record).is_ok(), "写入拦截链失败");
    }
    let Ok(metrics) = Metrics::with_runtime("test", Arc::clone(&runtime)) else { return };
    let text = metrics.render();
    assert!(
        text.contains("agf_runtime_interception_latency_p95_milliseconds{point=\"mcp-proxy\"} 3"),
        "3 条样本的 p95 = 3000µs ⇒ 3ms: {text}"
    );
    // 该点无样本 ⇒ 0（不是"沿用上一次的值"）
    assert!(text.contains("agf_runtime_interception_latency_p95_milliseconds{point=\"process-hook\"} 0"), "{text}");
}

#[test]
fn traces_endpoint_appends_signal_path_only_when_missing() {
    assert_eq!(otel::traces_endpoint("http://127.0.0.1:4318"), "http://127.0.0.1:4318/v1/traces");
    assert_eq!(otel::traces_endpoint("http://127.0.0.1:4318/"), "http://127.0.0.1:4318/v1/traces");
    assert_eq!(otel::traces_endpoint("http://127.0.0.1:4318/v1/traces"), "http://127.0.0.1:4318/v1/traces");
    assert_eq!(otel::traces_endpoint("https://otlp.example.com/custom"), "https://otlp.example.com/custom");
}
