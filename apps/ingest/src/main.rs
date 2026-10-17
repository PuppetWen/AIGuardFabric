//! agf-ingest 服务入口（§4.5 统一接入）。
//!
//! ## 职责
//!
//! 把"设备/云平台 → 平台"的接入链路跑成一个**独立进程**：Syslog（UDP/TCP）接收 →
//! 解析归一（`agf-ingest` 的流水线）→ 落库/总线；同时提供 Webhook 接入与健康检查。
//!
//! ## 端口与开关（与 `docker-compose.yml` 的 `agf-ingest` 服务一致）
//!
//! | 环境变量 | 默认 | 用途 |
//! |---|---|---|
//! | `AGF_INGEST_HOST` | `0.0.0.0` | HTTP 监听地址 |
//! | `AGF_INGEST_PORT` | `8090` | HTTP 端口（`/healthz`、`/ingest/webhook`、`/metrics`） |
//! | `AGF_SYSLOG_TCP_PORT` | `5514` | Syslog TCP（octet-counting / non-transparent 自动识别） |
//! | `AGF_SYSLOG_UDP_PORT` | `5514` | Syslog UDP |
//! | `AGF_SYSLOG_TLS_PORT` | `6514` | Syslog TLS（RFC5425）；`0` = 关闭；需证书/密钥才监听 |
//! | `AGF_SYSLOG_TLS_CERT` | 空 | TLS 服务端证书链（PEM 文件路径） |
//! | `AGF_SYSLOG_TLS_KEY` | 空 | TLS 服务端私钥（PEM 文件路径） |
//! | `AGF_SYSLOG_TCP_IDLE_TIMEOUT_SECS` | `60` | TCP/TLS 连接空闲超时（超时即关闭该连接） |
//! | `AGF_SYSLOG_MAX_CONNECTIONS` | `128` | TCP+TLS 并发连接任务上限（超出即拒绝并 warn） |
//! | `AGF_WEBHOOK_TOKEN` | 空 | Webhook Bearer 令牌；空 = 不校验（仅限内网/前置网关已鉴权） |
//! | `AGF_INGEST_PLUGIN_DIR` | `<项目根>/plugins` | **Rust 动态库插件**目录（`engine: plugin` 模板用）；缺省目录不存在 ⇒ 不装载（缺插件不是错误）；填 `0`/`off`/`none` ⇒ 显式关闭 |
//! | `AGF_INGEST_PLUGIN_TIMEOUT_MS` | `500` | 单次插件调用超时；`0` = 不启用（同进程调用**无法真正中断**：超时只放弃结果，插件线程仍在跑） |
//!
//! ## 新增协议接收器（全部"未配置 = 不启用"，任一失败只 warn，绝不影响进程启动）
//!
//! | 协议 | 环境变量 | 默认 |
//! |---|---|---|
//! | OTLP/HTTP（三信号） | `AGF_INGEST_OTLP_ENABLED`（`0` 关闭）、`AGF_OTLP_HTTP_LISTEN`（可选专用监听，如 `0.0.0.0:4318`）、`AGF_INGEST_OTLP_MAX_RECORDS`（单请求上限，默认 10000） | 启用（`/v1/logs` + `/v1/traces` + `/v1/metrics` 挂主 HTTP 端口） |
//! | OTLP/gRPC(4317) | AGF_INGEST_OTLP_GRPC_ENABLED、LISTEN、MAX_RECORDS、MAX_MESSAGE_BYTES 与 TLS 配置 | 官方 Logs/Trace/MetricsService，独立源 ID、gzip、TLS/mTLS；错误配置拒绝该监听器 |
//! | OTLP/gRPC **端口 TLS/mTLS** | `AGF_INGEST_OTLP_GRPC_TLS=1`、`..._TLS_CERT`/`..._TLS_KEY`（PEM）、`..._TLS_CLIENT_CA`（配置 ⇒ **要求客户端证书**） | 默认**明文**；证书缺失/非法则拒绝启动该接收器，原因写进 `/readyz` 的 notes |
//! | **NATS JetStream 入向订阅** | `AGF_INGEST_JETSTREAM_URL`（NATS 地址列表）、`..._IDENTITY`（默认 `default`，决定 stream/durable 名 ⇒ 重启不丢的前提）、`..._SUBJECT`（默认 `agf.ingest.<identity>`）、`..._MODE`（`pull`/`push`）、`..._BATCH`、`..._ACK_WAIT_SECS`、`..._MAX_DELIVER` | 未配置 URL ⇒ 不启用（能力矩阵显示 `not-wired`） |
//! | 对象存储（S3/OSS/MinIO） | `AGF_INGEST_OBJECT_PULL_BUCKET`、`..._PREFIX`、`..._INTERVAL_SECS`、`..._MAX_OBJECTS`、`..._STATE`；凭据复用 `AGF_S3_ENDPOINT/REGION/ACCESS_KEY/SECRET_KEY/FORCE_PATH_STYLE` | 未配置桶 ⇒ 不启用 |
//! | SQL 拉取（"JDBC"） | `AGF_INGEST_SQL_DSN`（`postgres://` ⇒ sqlx/PostgreSQL；`mysql://`/`mariadb://` ⇒ sqlx/MySQL；`mssql://`/`sqlserver://` ⇒ tiberius/MSSQL；`oracle://`/`oracle+tcps://` ⇒ oracle/OCI）、`AGF_INGEST_SQL_QUERY`、`..._CURSOR_FIELD`、`..._CURSOR_TYPE`、`..._BATCH_LIMIT`、`..._INTERVAL_SECS`、`..._CURSOR_PATH`、`..._MAX_CONNECTIONS`（Oracle/MSSQL 是单连接句柄，该参数不适用）；Oracle 另需 `AGF_ORACLE_CLIENT_LIB_DIR`（OCI 运行库目录，缺省仓库内 `tools/oracle/instantclient_23_5`，**不写全局 PATH**） | 未配置 DSN+QUERY ⇒ 不启用；Oracle OCI 缺失/连接失败只 warn + 写 `/readyz` notes，进程照常启动 |
//! | MQTT | `AGF_INGEST_MQTT_BROKER`（`mqtt://`/`mqtts://`/**`ws://`**/**`wss://`**）、`AGF_INGEST_MQTT_TOPIC`（支持 `$share/<group>/<filter>`）、`..._QOS`、`..._CLIENT_ID`、`..._USERNAME`、`..._PASSWORD` | 未配置 broker+topic ⇒ 不启用 |
//! | MQTT 加固 | `..._TLS=1`/`..._TLS_CA`/`..._TLS_CERT`+`..._TLS_KEY`/`..._TLS_INSECURE_SKIP_VERIFY=1`、`..._WILL_TOPIC/_PAYLOAD/_QOS/_RETAIN`、`..._RECONNECT_INITIAL_SECS/_MAX_SECS` | TLS 默认关闭（`mqtts://`/`wss://` 自动开启、默认校验证书链）；遗嘱未配主题 ⇒ 不注册 |
//! | MQTT 5 专有特性 | `..._PROTOCOL_VERSION`（`3.1.1`/`5`，默认 3.1.1）、`..._CLEAN_START`、`..._SESSION_EXPIRY_SECS`、`..._TOPIC_ALIAS_MAX`、`..._RECEIVE_MAXIMUM`、`..._SUBSCRIBE_NOLOCAL`/`..._SUBSCRIBE_RETAIN_AS_PUBLISHED`/`..._SUBSCRIBE_RETAIN_HANDLING`、`..._USER_PROPERTIES` | 默认 3.1.1（既有行为不变）；**v5 专有项配在 3.1.1 上直接报错**并写进 `/readyz` notes（不静默忽略） |
//! | SNMP Trap | `AGF_INGEST_SNMP_LISTEN`（如 `0.0.0.0:1162`）、`..._COMMUNITY`、`..._VERSION`（`v1`/`v2c`/`v3`）；v3：`..._V3_USER`、`..._V3_SECURITY_LEVEL`（`noAuthNoPriv`/`authNoPriv`/`authPriv`）、`..._V3_AUTH_PROTOCOL`（`md5`/`sha`）、`..._V3_AUTH_PASSWORD`、`..._V3_PRIV_PROTOCOL`（`aes`/`des`，默认 `aes`）、`..._V3_PRIV_PASSWORD` | 未配置 ⇒ 不启用；v3 `authPriv` 的 **CBC-DES(RFC3414 §8) 与 CFB128-AES-128(RFC3826 §3) 已实现**（凭据绝不进日志/Debug/错误文本） |
//! | **冷归档回灌** | `AGF_ARCHIVE_REPLAY=1`（启动前回灌一次）或子命令 `agf-ingest archive-replay`；`AGF_ARCHIVE_REPLAY_KEYS`（逗号分隔对象键，优先）/`..._DATE`（某天 `dt=` 分区）/（都缺省 ⇒ 整个前缀）、`..._FROM`/`..._TO`（RFC3339 或 `YYYY-MM-DD`）、`..._TENANT`、`..._LIMIT`（单次列举上限，默认 1000）、`..._STATE`（幂等账本路径）；对象存储复用 `AGF_S3_*`/`AGF_ARCHIVE_PREFIX` | 默认 **关**；开启后按 `raw_hash` 账本**幂等**（同批第二次回灌入库 0 条），报告以 JSON 打到 stdout；失败只 `warn`/非零退出，绝不让接入服务起不来 |
//! | Kafka | `AGF_INGEST_KAFKA_BROKERS`、`AGF_INGEST_KAFKA_TOPIC`、`..._START_FROM`、`..._MAX_RECORDS`、`..._CURSOR_PATH` | 未配置 ⇒ 不启用 |
//! | Kafka 鉴权 | `AGF_INGEST_KAFKA_SASL_MECHANISM`（`PLAIN`/`SCRAM-SHA-256`/`SCRAM-SHA-512`）、`..._SASL_USERNAME`、`..._SASL_PASSWORD` | 未配置 ⇒ 匿名；**凭据只在建连时取用，绝不进日志/指标/响应体** |
//! | Kafka TLS | `AGF_INGEST_KAFKA_TLS=1`、`..._TLS_CA`、`..._TLS_CERT`/`..._TLS_KEY`、`..._TLS_INSECURE_SKIP_VERIFY=1` | 默认关闭；开启后默认**校验证书链**；跳过校验必 `warn!` |
//! | Kafka 重连 | `..._RECONNECT_INITIAL_MS`、`..._RECONNECT_MAX_MS`、`..._RECONNECT_MAX_ATTEMPTS` | 500 / 30000 / 0（永不放弃） |
//! | **Kafka 真消费者组协议** | `AGF_INGEST_KAFKA_GROUP_ID`（**非空即启用**；空/未配置 ⇒ 走本地游标，行为与历史版本一致）、`..._SESSION_TIMEOUT_MS`、`..._HEARTBEAT_INTERVAL_MS`、`..._MAX_POLL_INTERVAL_MS`、`..._REBALANCE_TIMEOUT_MS`、`..._ASSIGNOR`（`range`/`roundrobin`）、`..._MEMBER_ID` | 组协议默认**关**；启用后分区分配由协调器下发、offset 提交到 `__consumer_offsets`（`kafka-consumer-groups.sh --describe` 可见）；KoP 同名前缀换成 `AGF_INGEST_PULSAR_*` |
//! | **Pulsar（经 KoP 复用 Kafka 接收器）** | `AGF_INGEST_PULSAR_SERVICE_URL`（KoP 的 **Kafka 协议**监听，如 `kafka://host:9092`）、`..._TOPIC`、`..._SUBSCRIPTION`、`..._TOKEN`、`..._TLS`、`..._TENANT_NAMESPACE`、`..._CURSOR_PATH` | 未配置 ⇒ 不启用（**Pulsar 原生协议**见下一行；`agf_ingest::receiver::PULSAR_NATIVE_TODO` 描述的是 KoP 行的边界） |
//! | **Pulsar 原生二进制协议**（`agf_ingest::pulsar`） | `AGF_INGEST_PULSAR_URL`（`pulsar://host:6650` 或 `pulsar+ssl://host:6651`，逗号分隔多 broker）、`..._TOPIC`、`..._SUBSCRIPTION`、`..._SUB_TYPE`（`exclusive`/`shared`/`failover`/`key_shared`）、`..._INITIAL_POSITION`（`latest`/`earliest`）、`..._RECEIVER_QUEUE_SIZE`、`..._TOKEN`、`..._CONNECT_TIMEOUT_SECS`、`..._BATCH`、`..._ACK_MODE`、`..._ACK_EVERY`、`..._TLS_CA`/`..._TLS_CERT`/`..._TLS_KEY`/`..._TLS_INSECURE_SKIP_VERIFY`、`..._RECONNECT_INITIAL_MS`/`..._RECONNECT_MAX_MS`/`..._RECONNECT_MAX_ATTEMPTS` | 未配置 ⇒ 不启用（`/readyz` 写 note；能力矩阵 `pulsar-native` 行显示 `not-wired`）。**与 KoP 行并存**：`AGF_INGEST_PULSAR_URL` **优先**，配了它就不再起 KoP 段（避免同订阅双通道消费）；两条路径各自 env、各自指标标签（`pulsar` / `pulsar-native`） |
//!
//! 新增观测面：`GET /stats` 给出流水线统计 + **每个接收器的四类计数**
//! （收到 / 命中 / 解析失败 / 丢弃）+ **Kafka/KoP 每个分区的 offset/lag/失败状态**；
//! `GET /metrics` 输出同样的四族 Prometheus 计数器，外加
//! `agf_ingest_kafka_{offset,lag,fetch_failures_total,reconnects_total,...}` 分区级指标，
//! 以及协议专属的三族：`agf_ingest_jdbc_*`（拉取条数/丢弃/失败/游标推进）、
//! `agf_ingest_snmp_usm_*`（6 类认证/解密失败 + 通过计数 + authPriv 解密细分）、
//! `agf_ingest_coldarchive_*`（对象数/字节数/事件数/回落次数 + 回灌对象/入库/重复/过滤）
//! ——这三族**未配置也照常输出全零序列**。
//!
//! ## 降级行为（绝不静默跳过）
//!
//! | 能力 | 现状 | 降级 |
//! |---|---|---|
//! | 事件落库 | 部署默认 PostgreSQL（`AGF_INGEST_SQL_SINK=1`） | 数据库不可用时不启动；只有显式 mock 模式允许内存 |
//! | 事件总线发布 | AGF_NATS_ENABLED=1 且 SQL 模式 | 原文、事件与投递队列同事务保存；JetStream 存储确认、自动重试与跨实例领取 |
//! | NATS JetStream（**入向**订阅） | **已实现并装配**（`agf_ingest::jetstream`，`async-nats`） | 未配置 `AGF_INGEST_JETSTREAM_URL` ⇒ 不启用；连接/`provision` 失败 ⇒ 只 warn + 计入 `/readyz` 的 notes，**且不登记装配** ⇒ 能力矩阵显示 `not-wired`（不谎报 `ready`） |
//! | MCP HTTP 代理 | 由 `agf-server` 在 8091 监听 | 与 API 共享租户认证、策略和配额；配置见控制台 MCP 管理及 docs/mcp-http-guide.md |
//! | Syslog TLS（RFC5425） | **已实现**（`SyslogTlsListener`） | `AGF_SYSLOG_TLS_PORT=0` 或未提供 `AGF_SYSLOG_TLS_CERT/KEY` → 只 `warn` 不启用（进程照常启动），`/readyz` 的 `listeners`/`notes` 如实标注 |
//! | OTLP（logs/traces/metrics）/对象拉取/JDBC/MQTT/SNMP/Kafka | **已实现**（见 `agf-ingest` 各模块）；SNMP v3 `authPriv`（CBC-DES / CFB128-AES-128）亦已实现 | 未配置 ⇒ 不启用；连接失败 ⇒ 只 `warn` + 下一轮重试，`/readyz` 的 `listeners`/`notes` 如实标注 |
//! | 冷归档回灌（`AGF_ARCHIVE_REPLAY` / `archive-replay`） | **已实现**（arrow `RecordBatchReader` 读回 + `raw_hash` 幂等账本） | 未配置 ⇒ 不跑；启动期回灌失败只 `warn`（服务照常起）；子命令失败 ⇒ 非零退出 |
//! | OTLP gRPC traces/metrics | 已实现 | 与 LogsService 共端口，复用 HTTP 解析与租户源管理 |
//! | OTLP/gRPC **端口 TLS/mTLS** | **已接线**（`ServerTlsConfig` + rustls） | 默认明文（向后兼容）；`AGF_INGEST_OTLP_GRPC_TLS=1` 但证书缺失/非法 ⇒ **拒绝启动该接收器**，原因写进 `/readyz` 的 notes 与能力矩阵（不静默） |
//! | MQTT **WebSocket / MQTT 5** | **已接线**（`rumqttc` 的 `websocket` 特性 + `rumqttc::v5`） | `ws://`/`wss://` 与 TCP/TLS 同一路径；v5 与 broker 不兼容（如 CONNACK 拒绝）按链路错误分类计数 + 退避重连；v5 专有项配在 3.1.1 上 ⇒ **启用阶段报错** |
//! | Pulsar | **两条路径并存**：① **原生二进制协议**（`AGF_INGEST_PULSAR_URL`，`agf_ingest::pulsar`，**本轮新实现**：真 CONNECT/SUBSCRIBE/FLOW/ACK + batch 拆条 + CRC32C + 退避重连）；② **经 KoP（Kafka on Pulsar）复用 Kafka 接收器**（`AGF_INGEST_PULSAR_SERVICE_URL`，原行为一字不改） | 两条都没配 ⇒ 不启用；**原生 URL 优先**；KoP 行配置指向 `pulsar://host:6650`（原生端口）仍**显式拒绝并写明原因**（不静默降级）；`receiver_capability_matrix` 的 `pulsar` / `pulsar-native` **两行分别列出**差异 |
//! | Pulsar 原生协议的未覆盖面 | **已实现**：单条 + batch 消息、token 鉴权、Individual/Cumulative ACK、Shared/Exclusive/Failover 声明、CRC32C 校验、`CommandError` 分类、指数退避重连、`CommandCloseConsumer` 重订阅、ZLIB 解压 | **未实现（如实）**：LZ4/ZSTD/SNAPPY 压缩（收到即按 `ValidationError=DecompressionError` 回执并计数）、分区 topic 与 `CommandLookupTopic`、Key_Shared 分派、死信/多 topic、非持久 topic、AckReceipt/事务；连接级指标（`PulsarNativeStats`）经公开 API 暴露，**未**接进 `/metrics`（需改 `serve.rs`，超出本轮允许范围） |
//! | **Rust 动态库插件**（`engine: plugin` 模板） | **已实现**（`crates/agf-plugin` 的版本化 C ABI + `agf-ingest` 侧接线） | 启动期装载 `AGF_INGEST_PLUGIN_DIR`（缺省 `<项目根>/plugins`）；**坏插件只 `warn` 并登记，绝不影响启动**，好插件照常可用；未装载 / 插件名不存在 / 调用失败 / 超时 / 返回非法 JSON ⇒ 该模板如实报错/未命中（**原始日志照常落库**），五类失败分别计数；装载与失败清单进 `/readyz` 的 `notes` |
//!
//! ## 子命令
//!
//! `agf-ingest`（默认启动服务）· `agf-ingest healthcheck --url <url>`（compose 健康检查，退出码 0/1）·
//! `agf-ingest archive-replay`（冷归档 arrow 列式回灌，报告以 JSON 打到 stdout；见上表 env）

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::panic, clippy::unwrap_used, clippy::expect_used))]

pub(crate) use std::collections::BTreeMap;

pub(crate) use std::io::Write;

pub(crate) use std::path::Path;
pub(crate) use std::path::PathBuf;

pub(crate) use std::sync::Arc;

pub(crate) use std::sync::atomic::AtomicU64;
pub(crate) use std::sync::atomic::Ordering;

use anyhow::Context as _;

pub(crate) use axum::Router;

pub(crate) use axum::http::StatusCode;

pub(crate) use axum::response::IntoResponse;

pub(crate) use axum::routing::get;

pub(crate) use clap::Parser;
pub(crate) use clap::Subcommand;

pub(crate) use tokio::net::TcpListener;

pub(crate) use agf_core::enums::HealthState;
pub(crate) use agf_core::enums::IngestProtocol;

pub(crate) use agf_core::ids::Id;
pub(crate) use agf_core::ids::TenantId;

pub(crate) use agf_core::source::CollectionMode;
pub(crate) use agf_core::source::LogSource;
pub(crate) use agf_core::source::SourceConnection;

pub(crate) use agf_core::time::Timestamp;

pub(crate) use agf_ingest::bus::EventBus;
pub(crate) use agf_ingest::bus::InMemoryEventBus;

pub(crate) use agf_ingest::jdbc::JdbcReceiver;
pub(crate) use agf_ingest::jdbc::SqlCursorFile;
pub(crate) use agf_ingest::jdbc::SqlDialect;
pub(crate) use agf_ingest::jdbc::SqlPullConfig;
pub(crate) use agf_ingest::jdbc::connect_from_dsn;

pub(crate) use agf_ingest::jetstream::AsyncNatsJetStream;
pub(crate) use agf_ingest::jetstream::ConsumerPlan;
pub(crate) use agf_ingest::jetstream::JetMode;
pub(crate) use agf_ingest::jetstream::JetStreamReceiver;
pub(crate) use agf_ingest::jetstream::StreamPlan;
pub(crate) use agf_ingest::jetstream::parse_nats_urls;

pub(crate) use agf_ingest::kafka::KafkaPullConfig;
pub(crate) use agf_ingest::kafka::KafkaReceiver;
pub(crate) use agf_ingest::kafka::KafkaSaslConfig;
pub(crate) use agf_ingest::kafka::KafkaSaslMechanism;
pub(crate) use agf_ingest::kafka::KafkaSeries;
pub(crate) use agf_ingest::kafka::KafkaShutdown;
pub(crate) use agf_ingest::kafka::KafkaStats;
pub(crate) use agf_ingest::kafka::KafkaTlsConfig;
pub(crate) use agf_ingest::kafka::kafka_prometheus;
pub(crate) use agf_ingest::kafka::parse_brokers;

pub(crate) use agf_ingest::metrics::MetricsRegistry;
pub(crate) use agf_ingest::metrics::SharedMetrics;

pub(crate) use agf_ingest::mqtt::MqttReceiver;

pub(crate) use agf_ingest::object_pull::ObjectPullConfig;
pub(crate) use agf_ingest::object_pull::ObjectPullReceiver;
pub(crate) use agf_ingest::object_pull::S3ObjectSource;

pub(crate) use agf_ingest::otlp::OtlpLogsReceiver;
pub(crate) use agf_ingest::otlp::OtlpMetricsReceiver;
pub(crate) use agf_ingest::otlp::OtlpTracesReceiver;
pub(crate) use agf_ingest::otlp::signal_router;

pub(crate) use agf_ingest::pipeline::InMemorySink;
pub(crate) use agf_ingest::pipeline::IngestConfig;
pub(crate) use agf_ingest::pipeline::IngestPipeline;
pub(crate) use agf_ingest::pipeline::Sink;
pub(crate) use agf_ingest::pipeline::SqlSink;

use agf_ingest::receiver::{PulsarReceiver, Receiver as _, declare_wired};

// Pulsar **原生二进制协议**消费者（`AGF_INGEST_PULSAR_URL`）：与 KoP 路径**并存**的第二条路。
pub(crate) use agf_ingest::pulsar::PulsarNativeConfig;
pub(crate) use agf_ingest::pulsar::PulsarNativeReceiver;
pub(crate) use agf_ingest::pulsar::PulsarNativeStats;
pub(crate) use agf_ingest::pulsar::PulsarRoute;
pub(crate) use agf_ingest::pulsar::pulsar_route;

pub(crate) use agf_ingest::registry::ParserRegistry;

pub(crate) use agf_ingest::snmp::SnmpTrapReceiver;

pub(crate) use agf_ingest::syslog::SyslogTcpListener;
pub(crate) use agf_ingest::syslog::SyslogTlsListener;
pub(crate) use agf_ingest::syslog::SyslogUdpListener;

#[allow(unused_imports)]
pub(crate) use build_sink::*;
#[allow(unused_imports)]
pub(crate) use drain_connection::*;
#[allow(unused_imports)]
pub(crate) use impl_listener_state::*;
#[allow(unused_imports)]
pub(crate) use serve::*;
#[allow(unused_imports)]
pub(crate) use spawn_extra_receivers::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 进程内统计（`/metrics` 数据源）。
#[derive(Debug, Default)]
struct Stats {
    /// 已接收的 syslog 帧数。
    syslog_frames: AtomicU64,
    /// 未命中任何模板的报文数。
    parse_failures: AtomicU64,
    /// 被分帧层**丢弃**的帧数（畸形长度头 / 超长帧 / 连接关闭时的半帧）。
    ///
    /// 单列的理由：历史缺陷是"单连接第 65 帧起静默丢弃"——没有这个计数器，
    /// 丢弃在 `/metrics` 上完全不可见（见 `tools/simulators/README.md` 第 7 节第 6 条）。
    syslog_frames_dropped: AtomicU64,
    /// 因并发连接上限被拒绝的连接数（拒绝不是静默：同时会 warn）。
    syslog_connections_rejected: AtomicU64,
}

/// 监听器运行态快照（`/readyz` 如实汇报"哪个口真的起来了"，没起来的写明原因）。
///
/// `notes` 用 `Arc<Mutex<..>>` 而非 `Vec`：接收器的**连接**在后台任务里建立
/// （这样"数据库/broker 不可达"不会拖住 HTTP 启动），失败原因必须在连接之后
/// 仍能写进 `/readyz`——否则运维看到的就只是"这个协议没起来"而不知道为什么。
#[derive(Debug, Clone)]
struct ListenerState {
    /// HTTP（webhook + healthz/readyz/metrics/stats + OTLP 日志端点）监听地址。
    http: Option<String>,
    /// Syslog UDP 监听地址。
    syslog_udp: Option<String>,
    /// Syslog TCP 监听地址。
    syslog_tcp: Option<String>,
    /// Syslog TLS（RFC5425）监听地址。
    syslog_tls: Option<String>,
    /// OTLP/HTTP 专用监听地址（未配置时 OTLP 只走主 HTTP 端口）。
    otlp_http: Option<String>,
    /// OTLP/gRPC(4317) 监听地址（官方 `LogsService/Export`；未启用/绑定失败时为 `None`）。
    otlp_grpc: Option<String>,
    /// NATS JetStream 入向订阅（未配置 `AGF_INGEST_JETSTREAM_URL` 时为 `None`）。
    ///
    /// **只在连接 + `provision` 都成功后才赋值**：这一格为空 = 订阅没装配
    /// （能力矩阵的 `nats-jetstream` 也会是 `not-wired`），两处口径永远一致。
    nats_jetstream: Option<String>,
    /// SNMP Trap UDP 监听地址。
    snmp_trap: Option<String>,
    /// **实际的落库后端**（`memory` / `sql`）——由 `Sink::backend()` 在装配时填入。
    ///
    /// 存在的理由：`/readyz` 此前**硬编码**了"事件落库为内存 Sink"的 `reason`，而
    /// `AGF_INGEST_SQL_SINK=1` 且库可达时进程实际用的是 PostgreSQL ⇒ 口径不实；
    /// `/stats` 的 `sink` 字段此前也不存在（尽管 `build_sink` 的注释声称有）。
    /// 现在两处都读这一格。
    sink: String,
    /// 未启用 / 降级原因（`/readyz` 的 `notes`）。
    notes: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

/// 手工 `Default`（不是 `derive`）：把**插件装载状态**作为第一批 notes 播进 `/readyz`。
///
/// `serve()` 用 `..ListenerState::default()` 构造监听器状态，而插件目录在 `main()` 的
/// "插件目录加载段"里**先于** `serve()` 装载完成（进程级运行时）⇒ 这里读到的是本进程
/// 本次启动的真实装载结果。没有这一手，`engine: plugin` 的装载失败在观测面上完全不可见
/// （这正是本轮要消灭的"口径不实"）。`Default` 只读全局状态，不碰文件系统、不起任务。
impl Default for ListenerState {
    fn default() -> Self {
        Self {
            http: None,
            syslog_udp: None,
            syslog_tcp: None,
            syslog_tls: None,
            otlp_http: None,
            otlp_grpc: None,
            nats_jetstream: None,
            snmp_trap: None,
            sink: String::new(),
            notes: std::sync::Arc::new(std::sync::Mutex::new(
                agf_ingest::engine::plugin::plugin_runtime_status().notes(),
            )),
        }
    }
}

/// 命令行。
#[derive(Debug, Parser)]
#[command(name = "agf-ingest", version, about = "AIGuardFabric 统一接入服务")]
struct Cli {
    /// 子命令（缺省 = 启动接入服务）。
    #[command(subcommand)]
    command: Option<Command>,
}

/// 子命令。
#[derive(Debug, Subcommand)]
enum Command {
    /// 健康检查：探测 `/healthz`，成功退出码 0，失败 1（compose healthcheck 用）。
    Healthcheck {
        /// 目标 URL。
        #[arg(long, default_value = "http://127.0.0.1:8090/healthz")]
        url: String,
    },
    /// 冷归档回灌：按 env 把归档对象（Parquet/gzip NDJSON）解回事件写进落库目标。
    ///
    /// 全部参数走环境变量（`AGF_ARCHIVE_*` / `AGF_ARCHIVE_REPLAY_*` / `AGF_S3_*`），
    /// 与启动期 `AGF_ARCHIVE_REPLAY=1` 是**同一条**回灌路径（同一个 sink 构造方式）。
    ArchiveReplay,
}

/// 冷归档回灌（`archive-replay` 子命令 / 启动期 `AGF_ARCHIVE_REPLAY=1` 共用）。
///
/// 落库目标用 [`build_sink`]（与 `serve()` 同一套 `AGF_INGEST_SQL_SINK` 判定），
/// 因此回灌写进的就是**流水线用的那个后端**（默认内存、`AGF_INGEST_SQL_SINK=1` 时是 PostgreSQL）。
// 回灌报告要以 JSON 打到 stdout（脚本对账用）——这是**子命令的产物**，不是日志噪音，
// 因此显式放行 `clippy::print_stdout`（其余日志仍走 tracing）。
#[allow(clippy::print_stdout)]
async fn archive_replay() -> anyhow::Result<()> {
    let sink = build_sink().await?;
    let report =
        agf_ingest::coldarchive::replay_from_env(sink).await.map_err(|e| anyhow::anyhow!("冷归档回灌失败：{e}"))?;
    // 回灌报告是**对账凭据**：stdout 给 JSON（脚本可解析），日志给人读摘要
    println!("{}", report.to_json());
    tracing::info!(report = %report.summary(), "冷归档回灌报告");
    if !report.failures.is_empty() {
        for failure in &report.failures {
            tracing::warn!(key = %failure.key, reason = %failure.reason, "回灌对象失败");
        }
    }
    Ok(())
}

/// 服务入口（**必须留在 crate 根**）。
///
/// `#[tokio::main] async fn main()` 是 bin 的入口点，也是 rustc `dead_code` 分析的
/// **存活根**：一旦把它挪进子模块（例如 `impl_listener_state.rs`，那里曾是拆分后的落点），
/// bin 的 `--test` 目标就再也找不到根，整棵调用树都会被报成"never used"。
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Healthcheck { url }) => healthcheck(&url).await,
        Some(Command::ArchiveReplay) => archive_replay().await,
        None => {
            // `AGF_ARCHIVE_REPLAY=1`：启动前先做一次归档回灌（走同一个 sink 构造），
            // 失败只 `warn`——回灌问题绝不让接入服务起不来（可用性优先）。
            if env_flag("AGF_ARCHIVE_REPLAY") {
                if let Err(e) = archive_replay().await {
                    tracing::warn!(error = %e, "启动期冷归档回灌失败（接入服务照常启动）");
                }
            }
            // 插件目录加载段（Rust 动态库插件，`engine: plugin` 模板用）：
            // 目录由 `AGF_INGEST_PLUGIN_DIR` 配置（缺省 `<项目根>/plugins`），
            // **坏插件只 warn 并登记、缺目录不是错误**——绝不让进程起不来；
            // 装载/失败清单经 `ListenerState::default()` 进 `/readyz` 的 notes。
            agf_ingest::engine::plugin::install_plugin_runtime_from_env(
                &std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            );
            serve().await
        }
    }
}

/// 额外接收器的产出：OTLP 三信号路由 + Kafka/KoP 的分区指标句柄 + 需要优雅停机的后台任务。
struct ExtraReceivers {
    /// OTLP/HTTP **logs** 接收器（未启用时 `None`）。
    otlp: Option<Arc<OtlpLogsReceiver>>,
    /// OTLP/HTTP **traces** 接收器（未启用时 `None`）。与 logs 同源，必须真的挂上路由。
    otlp_traces: Option<Arc<OtlpTracesReceiver>>,
    /// OTLP/HTTP **metrics** 接收器（未启用时 `None`）。
    otlp_metrics: Option<Arc<OtlpMetricsReceiver>>,
    /// Kafka/KoP 的分区指标（`/metrics` 与 `/stats` 共用）。
    kafka_series: Vec<KafkaSeries>,
    /// Kafka/KoP 消费任务（SIGINT/SIGTERM 时先广播停机、再等它们刷新游标）。
    kafka_tasks: Vec<tokio::task::JoinHandle<()>>,
}

mod build_sink;
mod drain_connection;
mod event_delivery;
mod impl_listener_state;
mod serve;
mod source_identity;
use source_identity::SourceIdentity;
mod spawn_extra_receivers;
#[cfg(test)]
mod tests;
