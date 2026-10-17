//! `Metrics` 注册表与全部指标记录方法（自 `metrics.rs` 拆出，逻辑未变）。

use super::*;

/// 指标集合。
pub struct Metrics {
    registry: Registry,
    requests: IntCounterVec,
    duration: HistogramVec,
    interceptions: IntCounterVec,
    in_flight: IntGauge,
    rate_limited: IntCounter,
    idempotent_replays: IntCounter,
    ready: IntGauge,
    /// 运行时拦截计数（`{point,action}`；来自拦截审计链，抓取时增量同步）。
    runtime_interceptions: IntCounterVec,
    /// 运行时拦截点 p95 时延（毫秒，`{point}`；来自拦截审计链的最近窗口，抓取时同步）。
    runtime_latency_p95: IntGaugeVec,
    /// 上次同步到的链上计数（按 `(point, action)`）。
    runtime_seen: Mutex<BTreeMap<(String, String), u64>>,
    /// 运行时引擎（`None` = 本进程没有拦截链可聚合：指标恒 0 但序列存在）。
    runtime: Option<Arc<RuntimeEngine>>,
    /// `/ws`：成功交给 NATS 的条数。
    ws_nats_published: IntCounter,
    /// `/ws`：从 NATS 订阅回灌的条数。
    ws_nats_received: IntCounter,
    /// `/ws`：退回进程内广播的条数。
    ws_local_fallback: IntCounter,
}

impl std::fmt::Debug for Metrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Metrics")
            .field("in_flight", &self.in_flight.get())
            .field("runtime_aggregated", &self.runtime.is_some())
            .finish_non_exhaustive()
    }
}

impl Metrics {
    /// 构造并注册全部指标（**不聚合运行时拦截链**：`agf_runtime_interceptions_total` 恒 0）。
    ///
    /// # Errors
    /// 指标名重复或注册表异常时返回 [`DomainError::Internal`]（正常不会发生）。
    pub fn new(version: &str) -> DomainResult<Self> {
        Self::build(version, None)
    }

    /// 构造并注册全部指标，并把运行时拦截链接进 `agf_runtime_interceptions_total`。
    ///
    /// # Errors
    /// 同 [`Self::new`]。
    pub fn with_runtime(version: &str, runtime: Arc<RuntimeEngine>) -> DomainResult<Self> {
        Self::build(version, Some(runtime))
    }

    fn build(version: &str, runtime: Option<Arc<RuntimeEngine>>) -> DomainResult<Self> {
        let registry = Registry::new();
        let requests = IntCounterVec::new(
            Opts::new("agf_http_requests_total", "HTTP 请求计数（按方法/路由模板/状态码）"),
            &["method", "path", "status"],
        )
        .map_err(internal)?;
        let duration = HistogramVec::new(
            HistogramOpts::new("agf_http_request_duration_seconds", "HTTP 请求时延（秒）")
                .buckets(LATENCY_BUCKETS.to_vec()),
            &["method", "path"],
        )
        .map_err(internal)?;
        let interceptions =
            IntCounterVec::new(Opts::new("agf_interceptions_total", "运行时策略拦截计数（按动作）"), &["action"])
                .map_err(internal)?;
        let runtime_interceptions = IntCounterVec::new(
            Opts::new(
                "agf_runtime_interceptions_total",
                "运行时拦截审计链的真实计数（按拦截点/动作；来自 RuntimeEngine::audit）",
            ),
            &["point", "action"],
        )
        .map_err(internal)?;
        let runtime_latency_p95 = IntGaugeVec::new(
            Opts::new(
                "agf_runtime_interception_latency_p95_milliseconds",
                "运行时拦截点 p95 时延（毫秒，向上取整；来自拦截审计链的最近窗口；无样本为 0）",
            ),
            &["point"],
        )
        .map_err(internal)?;
        let in_flight = IntGauge::new("agf_http_in_flight", "当前在途请求数").map_err(internal)?;
        let rate_limited = IntCounter::new("agf_rate_limited_total", "被限流拒绝的请求数").map_err(internal)?;
        let idempotent_replays =
            IntCounter::new("agf_idempotent_replays_total", "命中幂等键而复用历史响应的请求数").map_err(internal)?;
        let ready = IntGauge::new("agf_ready", "就绪探针结果（1=就绪，0=未就绪）").map_err(internal)?;
        let build_info =
            IntGaugeVec::new(Opts::new("agf_build_info", "构建信息（恒为 1）"), &["version"]).map_err(internal)?;
        let ws_nats_published =
            IntCounter::new("agf_ws_nats_published_total", "/ws 事件成功投递到 NATS 的条数").map_err(internal)?;
        let ws_nats_received =
            IntCounter::new("agf_ws_nats_received_total", "/ws 从 NATS 订阅回灌的事件条数（>0 即经过 NATS）")
                .map_err(internal)?;
        let ws_local_fallback =
            IntCounter::new("agf_ws_local_fallback_total", "/ws 事件退回进程内广播的条数（NATS 不可用/失败/队满）")
                .map_err(internal)?;

        registry.register(Box::new(requests.clone())).map_err(internal)?;
        registry.register(Box::new(duration.clone())).map_err(internal)?;
        registry.register(Box::new(interceptions.clone())).map_err(internal)?;
        registry.register(Box::new(runtime_interceptions.clone())).map_err(internal)?;
        registry.register(Box::new(runtime_latency_p95.clone())).map_err(internal)?;
        registry.register(Box::new(in_flight.clone())).map_err(internal)?;
        registry.register(Box::new(rate_limited.clone())).map_err(internal)?;
        registry.register(Box::new(idempotent_replays.clone())).map_err(internal)?;
        registry.register(Box::new(ready.clone())).map_err(internal)?;
        registry.register(Box::new(build_info.clone())).map_err(internal)?;
        registry.register(Box::new(ws_nats_published.clone())).map_err(internal)?;
        registry.register(Box::new(ws_nats_received.clone())).map_err(internal)?;
        registry.register(Box::new(ws_local_fallback.clone())).map_err(internal)?;

        if let Ok(gauge) = build_info.get_metric_with_label_values(&[version]) {
            gauge.set(1);
        }
        // 预先建出拦截计数的时间序列：空 `IntCounterVec` 不会出现在 /metrics 输出里，
        // 会让"拦截计数指标存在性"这类断言与告警规则时有时无。
        for action in KNOWN_ACTIONS {
            if let Ok(counter) = interceptions.get_metric_with_label_values(&[action]) {
                let _ = counter.get();
            }
        }
        // 同理：运行时拦截计数在"零流量"时也必须存在（4 个拦截点 × 8 个动作，基数有界）。
        for point in RUNTIME_POINTS {
            for action in KNOWN_ACTIONS {
                if let Ok(counter) = runtime_interceptions.get_metric_with_label_values(&[point, action]) {
                    let _ = counter.get();
                }
            }
            // p95 gauge 同样预建（4 个拦截点），否则零流量时该指标族整族消失。
            if let Ok(gauge) = runtime_latency_p95.get_metric_with_label_values(&[point]) {
                gauge.set(0);
            }
        }

        Ok(Self {
            registry,
            requests,
            duration,
            interceptions,
            in_flight,
            rate_limited,
            idempotent_replays,
            ready,
            runtime_interceptions,
            runtime_latency_p95,
            runtime_seen: Mutex::new(BTreeMap::new()),
            runtime,
            ws_nats_published,
            ws_nats_received,
            ws_local_fallback,
        })
    }

    /// 记录一次请求完成。
    pub fn record_request(&self, method: &str, path: &str, status: u16, elapsed_secs: f64) {
        let status_text = status.to_string();
        if let Ok(counter) = self.requests.get_metric_with_label_values(&[method, path, &status_text]) {
            counter.inc();
        }
        if let Ok(histogram) = self.duration.get_metric_with_label_values(&[method, path]) {
            histogram.observe(elapsed_secs);
        }
    }

    /// 记录一次运行时拦截。
    pub fn record_interception(&self, action: &str) {
        if let Ok(counter) = self.interceptions.get_metric_with_label_values(&[action]) {
            counter.inc();
        }
    }

    /// 记录一次 `/ws` 事件成功投递到 NATS。
    pub fn record_ws_nats_published(&self) {
        self.ws_nats_published.inc();
    }

    /// 记录一次 `/ws` 从 NATS 订阅回灌的事件。
    pub fn record_ws_nats_received(&self) {
        self.ws_nats_received.inc();
    }

    /// 记录一次 `/ws` 事件退回进程内广播。
    pub fn record_ws_local_fallback(&self) {
        self.ws_local_fallback.inc();
    }

    /// 在途请求 +1/-1。
    pub fn in_flight_inc(&self) {
        self.in_flight.inc();
    }

    /// 在途请求 -1。
    pub fn in_flight_dec(&self) {
        self.in_flight.dec();
    }

    /// 记录一次限流拒绝。
    pub fn record_rate_limited(&self) {
        self.rate_limited.inc();
    }

    /// 记录一次幂等复用。
    pub fn record_idempotent_replay(&self) {
        self.idempotent_replays.inc();
    }

    /// 设置就绪状态。
    pub fn set_ready(&self, ready: bool) {
        self.ready.set(i64::from(ready));
    }

    /// 渲染 Prometheus 文本格式（抓取前先把拦截链增量同步进 `agf_runtime_interceptions_total`）。
    #[must_use]
    pub fn render(&self) -> String {
        self.sync_runtime_interceptions();
        self.sync_runtime_latency();
        let families = self.registry.gather();
        TextEncoder::new().encode_to_string(&families).unwrap_or_else(|e| format!("# 指标编码失败: {e}\n"))
    }

    /// 把运行时拦截链的**最近窗口** p95 时延同步到
    /// `agf_runtime_interception_latency_p95_milliseconds{point}`。
    ///
    /// 与计数器不同：gauge 允许上下变化（窗口滚动、记录滚出缓冲都会让 p95 变小），
    /// 因此这里每次抓取都**覆盖**为最新值；窗口内无样本的点位写 0（而不是保留旧值）。
    /// 没有装配运行时引擎时直接返回（4 条序列仍以 0 存在）。
    fn sync_runtime_latency(&self) {
        let Some(runtime) = &self.runtime else {
            return;
        };
        let p95 =
            interception_latency_p95_ms(&runtime.audit().records(), Timestamp::now(), INTERCEPTION_P95_WINDOW_SECS);
        for point in RUNTIME_POINTS {
            if let Ok(gauge) = self.runtime_latency_p95.get_metric_with_label_values(&[point]) {
                gauge.set(p95.get(point).copied().unwrap_or(0));
            }
        }
    }

    /// 把运行时拦截链上的计数增量同步到 `agf_runtime_interceptions_total`。
    ///
    /// 没有装配运行时引擎时直接返回（指标仍以 0 存在，不报错）。
    fn sync_runtime_interceptions(&self) {
        let Some(runtime) = &self.runtime else {
            return;
        };
        let snapshot = interception_snapshot(&runtime.audit().records(), Timestamp::now(), 0);
        let Ok(mut seen) = self.runtime_seen.lock() else {
            return;
        };
        for (key, count) in &snapshot.by_point_action {
            let previous = seen.get(key).copied().unwrap_or(0);
            let labels = [key.0.as_str(), key.1.as_str()];
            if *count > previous {
                if let Ok(counter) = self.runtime_interceptions.get_metric_with_label_values(&labels) {
                    counter.inc_by(*count - previous);
                }
            }
            // 链上计数回退（环形缓冲滚出旧条目）时只回写基线：Prometheus 计数器不得下降。
            seen.insert(key.clone(), *count);
        }
    }
}

fn internal(e: prometheus::Error) -> DomainError {
    DomainError::Internal(format!("指标注册失败: {e}"))
}
