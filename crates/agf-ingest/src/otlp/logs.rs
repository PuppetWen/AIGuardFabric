//! OTLP/HTTP 日志接入（`POST /v1/logs`）：**JSON（必需）与 Protobuf（同源实现）双编码**。
//!
//! ## 协议面
//!
//! 按 [OTLP/HTTP 规范](https://opentelemetry.io/docs/specs/otlp/#otlphttp) 接收
//! `ExportLogsServiceRequest`，路径 `/v1/logs`：
//!
//! | `Content-Type` | 处理 |
//! |---|---|
//! | `application/json` | OTLP/JSON 映射（int64 为字符串、`camelCase` 字段、`traceId` 为 hex） |
//! | `application/x-protobuf` | 手写 protobuf wire-format 解码（字段号与 `opentelemetry-proto` v1.7 一致） |
//! | `application/json; charset=utf-8` 等带参数 | 按前缀归一后判定 |
//!
//! 同时支持 `Content-Encoding: gzip`（OTLP exporter 的常见缺省行为）。
//!
//! ## 映射规则（ResourceLogs → ScopeLogs → LogRecord → AGF-ECS 事件）
//!
//! 每条 `LogRecord` 归一化成一个 JSON 载荷交给既有 [`crate::pipeline::IngestPipeline`]
//! （**不另造解析/落库通路**）：
//!
//! ```json
//! {
//!   "@timestamp": "2026-02-21T10:23:45.000000123Z",
//!   "message": "<body 的字符串化>",
//!   "severity_text": "ERROR", "severity_number": 17,
//!   "trace_id": "4bf9...", "span_id": "00f0...",
//!   "resource": {"service.name": "checkout", "host.name": "prod-01"},
//!   "scope": {"name": "my.instrumentation", "version": "1.2.3"},
//!   "attributes": {"http.status_code": "500"},
//!   "event_name": "exception"
//! }
//! ```
//!
//! `resource` / `attributes` 的键**保持 OTLP 原文**（如 `service.name`），由解析模板
//! 决定如何落进 ECS 字段——接入层不猜测语义，避免"接入即失真"。
//!
//! ## 为什么手写 protobuf 解码而不是引 `opentelemetry-proto`
//!
//! `opentelemetry-proto` 会拽入 `prost` + 生成代码（并默认带 `tonic`），而本接收器只用到
//! `ExportLogsServiceRequest` 这一个消息树。手写 wire-format 读取器（见 [`proto`]）约 200 行、
//! 零新增依赖、未知字段按规范跳过，且**可在无网络的单测里逐字段验证**。
//!
//! ## OTLP/gRPC（4317）与未实现项（如实标注）
//!
//! * OTLP/gRPC（4317）**已实现**（[`crate::otlp_grpc`]）：`tonic` + `opentelemetry-proto`
//!   提供官方 `opentelemetry.proto.collector.logs.v1.LogsService/Export`，接受 `Content-Encoding: gzip`，
//!   并按 OTLP 规范回填 `partial_success`（被拒条数 + `error_message`，不假装全收下）。
//!   请求体经 `serde_json` 转成等价的 OTLP/JSON 字节后**复用本模块的映射**，
//!   因此 gRPC 与 HTTP 两条通道不存在"第二套语义"。OTLP/HTTP（4318 或任意端口）同样可用，
//!   绝大多数 exporter 可直接把 `protocol` 配成 `http/protobuf` 或 `http/json`。
//! * **gRPC 端口自身的 TLS/mTLS 已接线**（`AGF_INGEST_OTLP_GRPC_TLS=1` + `..._TLS_CERT`/`..._TLS_KEY`，
//!   `..._TLS_CLIENT_CA` 配置即**要求并校验客户端证书**）：默认明文以保持向后兼容，证书缺失/非法
//!   只 `warn` + 继续明文（实际形态进 `/readyz` 的 notes）；`zstd`/`snappy` 消息压缩亦未开启
//!   （只接受未压缩与 gzip，`TODO ingest-otlp-grpc-zstd`）。
//! * traces / metrics 信号已实现（[`crate::otlp::traces`] / [`crate::otlp::metrics_signal`]）：
//!   `POST /v1/traces` 与 `POST /v1/metrics` 与本模块共用 proto/JSON/gzip/上限保护，
//!   经 [`crate::otlp::signal_router`] 统一挂载（装配点须登记 `declare_wired`）。
//!   **gRPC 侧 TraceService/MetricsService 未实现**：[`crate::otlp_grpc`] 只注册 `LogsService`，
//!   traces/metrics 的 gRPC 调用会得到 `Unimplemented`（显式失败）——**不是**"由某个任务接线中"。

use std::collections::BTreeMap;
use std::sync::Arc;

use agf_core::enums::IngestProtocol;
use agf_core::error::{DomainError, DomainResult};
use agf_core::source::LogSource;
use async_trait::async_trait;
use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::post;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tracing::{debug, warn};

use crate::metrics::ReceiverCounters;
use crate::pipeline::IngestPipeline;
use crate::receiver::{Receiver, ReceiverDescriptor, ReceiverStatus};

// ---------------------------------------------------------------------------
// 与 traces/metrics 子模块共享的底层解码（proto wire-format 读取器、AnyValue、
// KeyValue、Resource/Scope、JSON 键查找、gzip 与编码归一）——只写一份，三个信号同源。
// ---------------------------------------------------------------------------
pub(super) use super::decode_any_value;
pub(super) use super::decode_key_value;
pub(super) use super::decode_resource;
pub(super) use super::decode_scope;
pub(super) use super::get;
pub(super) use super::gunzip;
pub(super) use super::is_gzip;
pub(super) use super::parse_key_values;
pub(super) use super::proto;
pub(super) use super::string_map;
pub(super) use super::supported_media;

mod parse;
mod receiver;
mod record;

#[cfg(test)]
mod tests;

pub use parse::*;
pub use receiver::*;
pub use record::*;
