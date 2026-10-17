//! MQTT 订阅接收器（`rumqttc`，纯 Rust 客户端）：TCP/TLS、**WebSocket(ws/wss)**、
//! 共享订阅、遗嘱（LWT）、退避重连，以及 **MQTT 5 专有特性**。
//!
//! ## 定位
//!
//! 物联网/边缘设备与部分安全设备（网关、探针）用 MQTT 上送日志；主题通常形如
//! `agf/sec/events` 或 `vendor/+/alarm`。本接收器订阅主题，把**每条 PUBLISH 的载荷**
//! 按 JSON 数组 / NDJSON / 单条正文拆开后交给既有解析流水线（**不另造解析通路**）。
//!
//! ## 连接与降级
//!
//! * broker 不可达时 `rumqttc` 的 `poll()` 返回错误 ⇒ **只 warn + 退避重连**
//!   （[`BackoffPolicy`] 指数退避，默认 1s→30s），接收器任务常驻、进程照常启动；
//! * 载荷拆分/解析失败按既有口径计入 `parse_failed` / `dropped`，绝不静默；
//! * QoS：`0`/`1`/`2` 由 `rumqttc` 保证（QoS1/2 的 PUBACK/PUBREC 握手由客户端完成），
//!   clean session/clean start 默认 `true`（平台侧幂等由 `IngestPipeline` 去重与业务主键承担，
//!   不承诺 MQTT 会话级"精确一次"）；
//! * TLS 相关失败会**分类计数**（[`MqttLinkError`]），`/metrics` 可见，不混在"网络错误"里。
//!
//! ## 配置
//!
//! | 字段 | 环境变量 | 默认 |
//! |---|---|---|
//! | broker | `AGF_INGEST_MQTT_BROKER`（`mqtt://host:1883` / `mqtts://host:8883` / **`ws://host:9001/mqtt`** / **`wss://host:9002/mqtt`** / `host:1883`） | 空（未配置 ⇒ 不启停） |
//! | 主题 | `AGF_INGEST_MQTT_TOPIC` | 空（必填；支持 `+` / `#` 通配与 `$share/<group>/<filter>`） |
//! | QoS | `AGF_INGEST_MQTT_QOS` | 1 |
//! | 客户端 id | `AGF_INGEST_MQTT_CLIENT_ID` | `agf-ingest-<source id>` |
//! | 用户名/口令 | `AGF_INGEST_MQTT_USERNAME` / `AGF_INGEST_MQTT_PASSWORD` | 空（匿名） |
//! | TLS 开关 | `AGF_INGEST_MQTT_TLS=1`（或 broker 用 `mqtts://`/`wss://`） | 关闭（明文 TCP/WS） |
//! | TLS 信任锚 | `AGF_INGEST_MQTT_TLS_CA`（PEM 文件路径） | 空 ⇒ 用内置 webpki 公共根证书 |
//! | mTLS | `AGF_INGEST_MQTT_TLS_CERT` + `AGF_INGEST_MQTT_TLS_KEY`（PEM 路径，**必须成对**） | 空 ⇒ 不带客户端证书 |
//! | 跳过校验 | `AGF_INGEST_MQTT_TLS_INSECURE_SKIP_VERIFY=1` | 0（**默认校验证书链**；跳过必 `warn!`） |
//! | 遗嘱主题 | `AGF_INGEST_MQTT_WILL_TOPIC` | 空 ⇒ 不注册 LWT |
//! | 遗嘱载荷 | `AGF_INGEST_MQTT_WILL_PAYLOAD` | `agf-ingest collector offline` |
//! | 遗嘱 QoS/retain | `AGF_INGEST_MQTT_WILL_QOS`（0/1/2） / `AGF_INGEST_MQTT_WILL_RETAIN`（0/1） | 1 / 0 |
//! | 重连退避 | `AGF_INGEST_MQTT_RECONNECT_INITIAL_SECS` / `..._MAX_SECS` | 1 / 30 |
//! | **协议版本** | `AGF_INGEST_MQTT_PROTOCOL_VERSION`（`3.1.1` / `5`） | `3.1.1`（既有行为不变） |
//! | Clean Start / clean session | `AGF_INGEST_MQTT_CLEAN_START` | 1（true） |
//! | 会话过期（v5） | `AGF_INGEST_MQTT_SESSION_EXPIRY_SECS` | 未配置 |
//! | Topic Alias（v5） | `AGF_INGEST_MQTT_TOPIC_ALIAS_MAX`（我方声明的入站别名上限） | 0（不接受别名） |
//! | Receive Maximum（v5） | `AGF_INGEST_MQTT_RECEIVE_MAXIMUM` | 未配置 |
//! | 订阅选项（v5） | `AGF_INGEST_MQTT_SUBSCRIBE_NOLOCAL` / `..._RETAIN_AS_PUBLISHED` / `..._RETAIN_HANDLING`（0/1/2） | 0 / 0 / 0 |
//! | CONNECT 用户属性（v5） | `AGF_INGEST_MQTT_USER_PROPERTIES`（`k=v,k2=v2`） | 空 |
//!
//! **v5 专有项配在 3.1.1 上会直接报错**（[`MqttProtocolConfig::validate`]）：3.1.1 报文里
//! 没有这些字段，"配了当没看见"是最坏的沉默——错误会写进 `/readyz` 的 notes。
//!
//! ## WebSocket（`ws://` / `wss://`）
//!
//! `ws`/`wss` 走 `rumqttc` 的 `websocket` 特性（`Transport::Ws` / `Transport::Wss`），
//! 与 TCP/TLS **共用**同一套订阅解析、别名处理与落库流水线；端点必须是完整 URL
//! （[`MqttEndpoint::broker_address`] 负责拼 scheme/端口/路径，默认路径 `/mqtt`）。
//! `ws://` 是明文 WebSocket：与 TLS 材料同时配置属于**矛盾配置**，启用阶段直接报错
//! （要加密请用 `wss://`），绝不静默改写 scheme。
//!
//! ## 共享订阅（`$share/<group>/<topic>`）
//!
//! 语义：**同一 group 内的订阅者竞争消费**（每条消息只投递给组内一个客户端），
//! 适合"多副本 agf-ingest 同时在线、但每条日志只处理一次"的横向扩容场景；
//! 不同 group 各自收到一份（= 广播）。用法：把 `AGF_INGEST_MQTT_TOPIC` 配成
//! `$share/agf-ingest/agf/sec/#`，然后**多个副本用同一个 group 名**即可。
//! 本模块对 `$share/` 语法做**严格校验**（组名非空且不含通配符、过滤器合法、禁止嵌套），
//! 非法组合在启用阶段就报错，而不是等 broker 回一个含糊的 SUBACK 失败。
//!
//! ## MQTT 5 专有特性（实现清单）
//!
//! | 特性 | 落地位置 | 说明 |
//! |---|---|---|
//! | Session Expiry / Clean Start | CONNECT 属性（`session_expiry_interval` / `clean_start`） | `AGF_INGEST_MQTT_SESSION_EXPIRY_SECS` / `..._CLEAN_START` |
//! | Topic Alias | `topic_alias_maximum` 声明 + 入站别名解析（[`TopicAliasTable`]） | 越界/未登记 ⇒ 丢弃并 `warn`（协议错误计数） |
//! | 订阅选项 | `Filter{nolocal, preserve_retain, retain_forward_rule}` | NoLocal / RetainAsPublished / RetainHandling 可配 |
//! | Receive Maximum | CONNECT 属性（流控） | `AGF_INGEST_MQTT_RECEIVE_MAXIMUM` |
//! | Properties 透传 | 入站属性 → `MqttMessage::properties` → `origin` 查询串 | 落在事件 `extra["log.origin"]`（见下"未实现"第 2 条） |
//!
//! ## 未实现（如实标注）
//!
//! * MQTT 5 的 **AUTH 增强认证**（`authentication_method`/`authentication_data`）未接线：
//!   目前只用 `username/password`（PLAIN），需要 AUTH 交换的 broker 会拒绝——
//!   `TODO ingest-mqtt-v5-auth`；
//! * v5 **用户属性未单独写入 `Event::extra` 的独立键**：`IngestPipeline::ingest_batch`
//!   的入参只有 `(payload, origin)`，没有逐条元数据通道；因此用户属性等以查询串形式
//!   随 `origin` 透传（落 `extra["log.origin"]` 与 `raw_logs.origin`），保真但键名不理想。
//!   `TODO ingest-mqtt-v5-properties-extra`；
//! * **出站** topic alias（我方作为发布者压缩主题）不适用：本接收器只订阅、不发布。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use agf_core::enums::IngestProtocol;
use agf_core::error::{DomainError, DomainResult};
use agf_core::source::LogSource;
use async_trait::async_trait;
use rumqttc::v5::mqttbytes::QoS as V5QoS;
use rumqttc::v5::mqttbytes::v5::LastWill as V5LastWill;
use rumqttc::{AsyncClient, Event, LastWill, MqttOptions, Packet, QoS, TlsConfiguration, Transport};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::metrics::ReceiverCounters;
use crate::pipeline::IngestPipeline;
use crate::receiver::{HttpPullReceiver, Receiver, ReceiverDescriptor, ReceiverStatus};

mod link;
mod properties;
mod protocol;
mod receiver;
mod subscription;
mod tls;
mod topic;
mod v5_client;
mod will;

#[cfg(test)]
mod tests;

pub use link::*;
pub use properties::*;
pub use protocol::*;
pub use receiver::*;
pub use subscription::*;
pub use tls::*;
pub use topic::*;
pub use v5_client::*;
pub use will::*;
