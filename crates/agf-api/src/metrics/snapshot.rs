//! 拦截快照与 p95 时延聚合辅助（自 `metrics.rs` 拆出，逻辑未变）。

use super::*;

/// 时延直方图分桶（秒）。
pub(super) const LATENCY_BUCKETS: [f64; 11] = [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 10.0];

/// 运行时拦截点的标签全集（与 `GET /runtime/intercept-points` 的 4 行一致）。
pub(super) const RUNTIME_POINTS: [&str; 4] = ["mcp-proxy", "ai-gateway", "process-hook", "egress-proxy"];

/// 策略动作标签全集（与 `agf_interceptions_total{action}` 的既有取值一致）。
pub(super) const KNOWN_ACTIONS: [&str; 8] =
    ["allow", "deny", "audit", "redact", "quota", "throttle", "approval", "isolate"];

/// p95 时延的样本窗口（秒）。
///
/// 比吞吐的 60 秒窗口（`console::THROUGHPUT_WINDOW_SECS`）更宽：p95 是**分位数**，
/// 60 秒内常常只有个位数样本，分位数会随单条记录剧烈跳动；300 秒是"够稳定 + 仍然是最近窗口"的折中。
/// **窗口内没有任何样本的点位 ⇒ 0**（不沿用更早的样本，也不编造）。
pub const INTERCEPTION_P95_WINDOW_SECS: i64 = 300;

/// 拦截审计快照（真实来源：`agf_runtime` 的拦截哈希链）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InterceptionSnapshot {
    /// 窗口内总条数。
    pub total: u64,
    /// `(拦截点, 动作)` → 条数。
    pub by_point_action: BTreeMap<(String, String), u64>,
    /// 拦截点 → 条数。
    pub by_point: BTreeMap<String, u64>,
}

/// 聚合拦截审计链。
///
/// `window_secs <= 0` 表示**不按时间截断**（全链，计数器用）；`> 0` 时只统计
/// `now - window_secs` 之后的条目（`/runtime/intercept-points` 的每分钟吞吐用）。
#[must_use]
pub fn interception_snapshot(
    records: &[agf_runtime::audit::InterceptionRecord],
    now: Timestamp,
    window_secs: i64,
) -> InterceptionSnapshot {
    let mut snapshot = InterceptionSnapshot::default();
    for record in records {
        if window_secs > 0 && now.since_secs(&record.at) > window_secs {
            continue;
        }
        snapshot.total += 1;
        let point = record.intercept_point.as_str().to_string();
        let action = record.action.as_str().to_string();
        *snapshot.by_point_action.entry((point.clone(), action)).or_insert(0) += 1;
        *snapshot.by_point.entry(point).or_insert(0) += 1;
    }
    snapshot
}

/// 拦截点 **p95 时延**（微秒）按 `point` 分组；窗口内没有样本的点位**不出现在结果里**。
///
/// ## 样本口径（**如实标注**）
///
/// - 样本 = 窗口内链上的 [`agf_runtime::audit::InterceptionRecord::latency_micros`]，
///   即各拦截入口真实测得的"进入处理 → 出决策"耗时（见 `mcp_proxy` / `engine` 的埋点）；
/// - **未测量**的记录该字段为 0（v0 记录缺字段、测试手工构造的记录），它们**照样是样本**
///   ——0 微秒是真实取值，不做特殊剔除（否则"手工构造的链"会显示成"无样本"）；
/// - `window_secs <= 0` 表示不按时间截断（全链）；
/// - 窗口内无样本 ⇒ 该点位无条目（调用方按 0 处理）。
///
/// 分位数用**最近秩法**（nearest-rank）：升序样本的第 `ceil(0.95 · n)` 个值（`n ≥ 1`）。
#[must_use]
pub fn interception_latency_p95_micros(
    records: &[agf_runtime::audit::InterceptionRecord],
    now: Timestamp,
    window_secs: i64,
) -> BTreeMap<String, u64> {
    let mut samples: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    for record in records {
        if window_secs > 0 && now.since_secs(&record.at) > window_secs {
            continue;
        }
        samples.entry(record.intercept_point.as_str().to_string()).or_default().push(record.latency_micros);
    }
    samples
        .into_iter()
        .map(|(point, mut values)| {
            values.sort_unstable();
            (point, percentile95(&values))
        })
        .collect()
}

/// 拦截点 **p95 时延（毫秒）**，供 `GET /runtime/intercept-points` 的 `p95_latency_ms` 使用。
///
/// 单位换算：`微秒 → 毫秒`**向上取整**（`div_ceil`）。这一点必须写清楚：
/// 本机单次判定常在 1 毫秒以下，若按"截断/四舍五入"换算，**真实测得**的分布会全部显示成 0，
/// 又退化成"恒为 0"的假象；向上取整保证"有样本 ⇒ ≥ 1ms"，同时**没有样本时严格是 0**
/// （不编造）。因此该字段的含义是"**上取整到毫秒的 p95**"，不是"精确到毫秒的 p95"。
#[must_use]
pub fn interception_latency_p95_ms(
    records: &[agf_runtime::audit::InterceptionRecord],
    now: Timestamp,
    window_secs: i64,
) -> BTreeMap<String, i64> {
    interception_latency_p95_micros(records, now, window_secs)
        .into_iter()
        .map(|(point, micros)| {
            let millis = micros.div_ceil(1_000);
            (point, i64::try_from(millis).unwrap_or(i64::MAX))
        })
        .collect()
}

/// 最近秩法 p95（输入必须升序；空切片返回 0）。
pub(super) fn percentile95(sorted_ascending: &[u64]) -> u64 {
    let len = sorted_ascending.len();
    if len == 0 {
        return 0;
    }
    // ceil(0.95 · n) 名（1 起）→ 下标 -1；`saturating_mul` 防御极端长度的溢出。
    let rank = len.saturating_mul(95).div_ceil(100);
    let index = rank.saturating_sub(1).min(len - 1);
    sorted_ascending[index]
}
