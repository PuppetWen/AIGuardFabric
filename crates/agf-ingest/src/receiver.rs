//! 接入接收器：Webhook / Syslog / 文件采集 / HTTP 拉取 / NATS / **OTLP / 对象存储拉取 /
//! SQL 拉取 / MQTT / SNMP Trap / Kafka / Pulsar（经 KoP 复用 Kafka 接收器）**（§4.5 协议接入）。
//!
//! ## 状态总表
//!
//! **四态**见 [`ReceiverStatus`]：`ready`（已实现 **且本进程已装配**）/ `not-wired`
//! （已实现但**本进程未装配**）/ `not-implemented`（代码层面就没有）/ `mock`。
//! 状态由装配点（`apps/ingest`）通过 [`declare_wired`] 报到，未登记的模块一律按
//! `not-wired` 处理——"挂没挂路由"因此是**可判定的事实**，而不是文档承诺。
//!
//! | 协议 | 状态 | 实现位置与说明 |
//! |---|---|---|
//! | Webhook（HTTP 推送） | 已实现 | 本模块：axum handler + Bearer 鉴权 + JSON/NDJSON 拆包 |
//! | Syslog TCP/UDP/TLS | 已实现 | [`crate::syslog`]（TLS 需证书，见 capability matrix 的 todo） |
//! | 文件采集（Filebeat/Fluent Bit/Vector 落盘） | 已实现 | 本模块轮询式 tail（`TODO ingest-notify-watch`） |
//! | HTTP Pull | 已实现 | 本模块：增量游标 + 可插拔 [`HttpFetcher`] |
//! | NATS 事件总线发布 | 已实现（默认特性 `nats`） | [`crate::bus`]：**核心协议 publish，非 JetStream**；无服务器时返回依赖不可用 |
//! | **OTLP/HTTP logs** | 已实现 | [`crate::otlp`]：JSON + Protobuf 双编码、gzip、`partialSuccess` |
//! | **OTLP/HTTP traces** | 已实现（`POST /v1/traces`） | [`crate::otlp::traces_receiver`]：Span → 归一化载荷；**路由必须由装配点 merge**，否则状态为 `not-wired` |
//! | **OTLP/HTTP metrics** | 已实现（`POST /v1/metrics`） | [`crate::otlp::metrics_receiver`]：data point → 归一化载荷；同上按装配事实报状态 |
//! | **NATS JetStream 入向订阅** | 已实现（`AGF_INGEST_JETSTREAM_URL`） | [`crate::jetstream`]：durable 幂等 provision + `ack_with(AckKind)` 显式应答 + pull/push |
//! | **对象存储拉取（OSS/S3/MinIO）** | 已实现 | [`crate::object_pull`]：ETag 幂等游标 + 游标落盘 |
//! | **JDBC / SQL 拉取** | 已实现（PostgreSQL / MySQL / MSSQL / Oracle，按 DSN scheme 自动选驱动） | [`crate::jdbc`]：游标列 + 游标落盘 + 单轮上限（`LIMIT` / `TOP(n)` / `OFFSET…FETCH`）+ 方言化占位符/转型/引号 |
//! | **MQTT** | 已实现 | [`crate::mqtt`]：rumqttc 订阅 + 退避重连 |
//! | **SNMP Trap** | 已实现（v1/v2c） | [`crate::snmp`]：BER 手写解析；v3 未实现 |
//! | **Kafka** | 已实现 | [`crate::kafka`]：rskafka 纯 Rust + 全分区独立 offset 游标 + SASL/TLS + 退避重连 |
//! | Pulsar | **经 KoP 复用 Kafka 接收器**（Ready） | [`PulsarReceiver`]：走 **KoP（Kafka on Pulsar）** 的 Kafka 协议监听，取数内核 = [`crate::kafka`]；**Pulsar 原生协议（binary protocol / WebSocket）未实现** |
//! | 南向采集器上行（AgentReport） | 已实现 | 本模块：mTLS 指纹纯函数校验 + 信封解码 |
//!
//! 每个接收器的**协议层指标**（收到 / 解析命中 / 解析失败 / 丢弃）统一由
//! [`crate::metrics::MetricsRegistry`] 承接，`/metrics` 直接输出四族计数器；
//! Kafka/KoP 另输出 offset / lag / 失败 / 重连等分区级指标（见 [`crate::kafka`]）。
//!
//! **Mock 回放通道**：[`MockReceiver`] 用于"配置模型已就绪但取数通道未启用"的协议。
//! 当前唯一使用者是 **Pulsar**：未配置 KoP 地址时不假装可用（能力矩阵显示 `not-implemented`），
//! 但仍可用离线样本把"归一化 + 落库"链路跑通。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use agf_core::enums::IngestProtocol;
use agf_core::error::{DomainError, DomainResult};
use agf_core::source::{CollectorRegistration, LogSource};
use agf_core::time::Timestamp;
use async_trait::async_trait;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tracing::{debug, warn};

use crate::pipeline::{IngestOutcome, IngestPipeline};

// Pulsar（经 KoP）与单元测试共用的 Kafka 取数内核类型：原为文件级导入，拆分后上移到 façade，
// 这样子模块与 `tests` 都能经 `use super::*` 取到（仍为私有导入 ⇒ 公开 API 不变）。
use crate::kafka::{
    KafkaPullConfig, KafkaSaslConfig, KafkaSaslMechanism, KafkaSecurity, KafkaSource, KafkaStats, KafkaTlsConfig,
    RskafkaSource,
};

mod capability;
mod file_tail;
mod http_pull;
mod kop;
mod mock;
mod pulsar;
mod status;
mod traits;
mod uplink;
mod webhook;

#[cfg(test)]
mod tests;

pub use capability::*;
pub use file_tail::*;
pub use http_pull::*;
pub use kop::*;
pub use mock::*;
pub use pulsar::*;
pub use status::*;
pub use traits::*;
pub use uplink::*;
pub use webhook::*;
