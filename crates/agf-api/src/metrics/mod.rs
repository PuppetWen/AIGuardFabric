//! 可观测性：Prometheus 指标（`GET /metrics`）与 OTLP 链路导出装配（`AGF_OTLP_ENDPOINT` 门控）。
//!
//! ## Prometheus 指标
//!
//! 使用 workspace 已声明的 `prometheus` crate 显式维护注册表：指标命名与标签基数完全由
//! 本模块决定，且**路径标签先归一到路由模板**（`/api/v1/assets/{id}`），避免
//! "每个 UUID 一条时序"这类基数爆炸。
//!
//! 必备指标组：
//! - `agf_http_requests_total{method,path,status}` —— 请求计数；
//! - `agf_http_request_duration_seconds{method,path}` —— 时延直方图；
//! - `agf_interceptions_total{action}` —— 拦截计数（策略 deny/redact/quota/approval）；
//! - `agf_runtime_interceptions_total{point,action}` —— **运行时拦截审计链**的真实聚合
//!   （`TODO(api-console-runtime-metrics)` 的计数面）：抓取时按链上条目增量同步，
//!   标签基数被固定为 4 个拦截点 × 8 个动作，**没有流量时序列存在且为 0**；
//! - `agf_runtime_interception_latency_p95_milliseconds{point}` —— 同一份链的**真实 p95 时延**
//!   （[`INTERCEPTION_P95_WINDOW_SECS`] 窗口内的 `latency_micros` 样本，最近秩法分位数，
//!   微秒样本**向上取整**到毫秒；窗口内无样本 ⇒ 0。见 [`interception_latency_p95_ms`]）；
//! - `agf_ws_nats_published_total` / `agf_ws_nats_received_total` /
//!   `agf_ws_local_fallback_total` —— `/ws` 事件面的 NATS 投递/回灌/降级计数
//!   （见 [`crate::ws`] 的模块文档）。
//!
//! 全部取指标都走 `get_metric_with_label_values`（返回 `Result`），不使用会 panic 的
//! `with_label_values`。
//!
//! ## 计数器的单调性
//!
//! `agf_runtime_interceptions_total` 的值来自拦截链（[`crate::metrics::interception_snapshot`]），
//! 而链是**环形缓冲**：滚出旧条目后链上计数会回退。Prometheus 计数器不允许下降
//! （下降会被判为 reset），因此这里按"增量累加 + 只回写基线"处理：链上计数变大就
//! `inc_by(delta)`，变小就只更新基线、**不回退已导出的计数器**（宁可少报也不假报 reset）。
//!
//! ## OTLP（`TODO(server-otlp)` 的落地）
//!
//! 见 [`otel`] 子模块：由 `AGF_OTLP_ENDPOINT`（或 `AGF_OTEL_ENABLED=1` +
//! `AGF_OTEL_ENDPOINT`）门控装配 span exporter；**未配置时不构建任何导出器**，
//! `tracing` 初始化与既有行为完全一致（无后台线程、无网络客户端、无副作用）。

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use agf_core::error::{DomainError, DomainResult};
use agf_core::time::Timestamp;
use agf_runtime::engine::RuntimeEngine;
use prometheus::{
    HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry, TextEncoder,
};

// 兄弟子模块（`registry` / `tests`）通过 `use super::*;` 复用这几个名字。
use snapshot::{KNOWN_ACTIONS, LATENCY_BUCKETS, RUNTIME_POINTS};

pub use registry::*;
pub use snapshot::*;

pub mod otel;
mod registry;
mod snapshot;
#[cfg(test)]
mod tests;
