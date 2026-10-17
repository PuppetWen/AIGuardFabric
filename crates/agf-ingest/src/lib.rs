#![forbid(unsafe_code)]
//! # agf-ingest — AIGuardFabric 统一日志与告警接入（§4.5）
//!
//! 本 crate 覆盖"设备/云平台 → 平台"的**协议接入 → 解析 → 归一化 → 脱敏 → 分层存储 → 回放**
//! 全链路，输出统一的 AGF-ECS [`agf_core::event::Event`]。
//!
//! ## 模块地图
//!
//! | 模块 | 职责 |
//! |---|---|
//! | [`syslog`] | RFC3164 / RFC5424 解析、TCP 分帧（流式收帧）、TCP/UDP/TLS 监听 |
//! | [`engine`] | 解析引擎：Grok / Regex / JSONPath / JQ(jaq) / Syslog / CEF / LEEF / GELF / CSV / KV / CEL 派生 / **`plugin`（Rust 动态库插件，见 [`engine::plugin`]）** |
//! | [`template`] | 内置厂商模板目录（19 个）与样本清单（`tests/fixtures/logs/manifest.json`） |
//! | [`registry`] | 模板注册表：YAML 目录加载 + 优先级匹配 + 样本打分 + 统计 |
//! | [`normalize`] | 解析结果 → AGF-ECS `Event`（severity/category/action/主机/用户/网络/AI） |
//! | [`ai_parser`] | 无模板时的 AI 推断落地点（离线启发式 + Mock + 远程 TODO） |
//! | [`pipeline`] | 接入流水线：去重 → 解析 → 归一化 → 脱敏 → 落库 → 投递；[`pipeline::Sink`] 抽象 |
//! | [`bus`] | 事件总线：内存 / Noop / NATS |
//! | [`replay`] | 原始日志回放与差分报告 |
//! | [`coldarchive`] | 冷存储归档（默认列式 Parquet，编码失败回落 gzip NDJSON）+ 保留策略 |
//! | [`receiver`] | 接收器：Webhook / 文件 tail / HTTP Pull / **NATS JetStream 入向订阅** / 采集器上行 + 已实现协议的路径重导出；状态是**四态**（`ready`/`not-wired`/`not-implemented`/`mock`），`ready` 必须与装配登记（`declare_wired`）一致 |
//! | [`otlp`] | OTLP/HTTP 三信号：`POST /v1/logs`（LogRecord → Event）+ `POST /v1/traces`（Span）+ `POST /v1/metrics`（data point）；JSON + Protobuf 双编码、gzip、`partialSuccess` |
//! | [`otlp_grpc`] | OTLP/gRPC（4317）：官方 Logs/Trace/MetricsService，gzip、TLS/mTLS、租户日志源与持久入库 |
//! | [`object_pull`] | 对象存储（S3/OSS/MinIO）轮询拉取：ETag 幂等游标 + 游标落盘 |
//! | [`jdbc`] | SQL（"JDBC"）增量拉取：游标列 + 游标落盘 + 单轮上限（PostgreSQL / MySQL / MSSQL / Oracle 按 DSN scheme 自动选驱动） |
//! | [`mqtt`] | MQTT 订阅（`rumqttc`）：QoS 0/1/2、通配主题、退避重连、TLS(`mqtts://`)、共享订阅 `$share/<group>/<topic>`、遗嘱（LWT） |
//! | [`snmp`] | SNMP v1/v2c/v3 Trap：BER 手写解析 + UDP 监听；v3 USM 支持 `noAuthNoPriv`/`authNoPriv`（MD5/SHA） |
//! | [`kafka`] | Kafka 消费（`rskafka` 纯 Rust）：全分区独立 offset 游标 + SASL/TLS + 退避重连；KoP 复用点 |
//! | [`pulsar`] | **Pulsar 原生二进制协议**消费者（`pulsar://`，手写 `PulsarApi` 消息子集 + 帧/CRC32C + batch 拆条 + 真 ACK + token 鉴权 + 退避重连）；与 KoP 路径**并存** |
//! | [`jetstream`] | NATS JetStream **入向订阅**（`async-nats`）：durable stream/consumer 幂等 `provision` + 真 `ack_with(AckKind)`（ack/nak/term）+ pull/push 双模式；名字由 `AGF_INGEST_JETSTREAM_IDENTITY` 决定（重启不丢） |
//! | [`metrics`] | 接收器统一指标：收到 / 命中 / 解析失败 / 丢弃（Prometheus 文本） |
//!
//! ## 降级行为总表（重要）
//!
//! 平台承诺"**永远可启动、绝不丢数据**"，因此所有未完成能力都显式降级并带 TODO 锚点：
//!
//! | 能力 | 现状 | 降级路径 / TODO |
//! |---|---|---|
//! | Syslog TCP/UDP、RFC3164/5424、octet-counting / non-transparent | 已实现 | — |
//! | Syslog TLS（RFC5425） | 已实现（[`syslog::SyslogTlsListener`]） | 证书/密钥缺失只 `warn` 不监听（`AGF_SYSLOG_TLS_CERT/KEY`）；`AGF_SYSLOG_TLS_PORT=0` 显式关闭 |
//! | Webhook（HTTP 推送，Bearer 鉴权） | 已实现 | — |
//! | Grok / Regex / JSONPath / JQ / Syslog / CEF / LEEF / GELF / CSV / KV | 已实现 | 纯进程内，离线可用 |
//! | CEL 派生字段 | **已实现**（[`cel`]） | 模板 `derived` 段经 `cel-interpreter` 求值，编译带缓存；单条失败记入 `derived_errors` 不中断解析 |
//! | 自定义 Rust 插件（动态库） | **已实现**（[`engine::plugin`]） | 运行时装载 `.dll`/`.so`/`.dylib`（`crates/agf-plugin` 的版本化 C ABI `agf_plugin_descriptor_v1` + `abi_version` 门禁）：模板 `engine: plugin` + `pattern: plugin=<name>` ⇒ 调插件 `normalize` 取回 AGF-ECS JSON，再走**既有**映射/归一化路径；目录 `AGF_INGEST_PLUGIN_DIR`（缺省 `<项目根>/plugins`，缺目录 = 无插件、**不阻止启动**），超时 `AGF_INGEST_PLUGIN_TIMEOUT_MS`（默认 500ms）；未装载 / 插件名不存在 / 调用失败 / 超时 / 非法 JSON 五类**分别计数 + 落诊断**，不 panic、不静默丢弃（原始日志照常落库）；插件与宿主**同进程同权限**，不做沙箱承诺 |
//! | AI 推断解析器 | 部分实现 | 离线启发式（不打网络）；真实 LLM 走 `agf-aigw`；`TODO ingest-ai-parser-remote` |
//! | 文件采集 | 已实现（轮询） | 事件驱动 watcher 待接入 `notify`；`TODO ingest-notify-watch` |
//! | HTTP Pull | 已实现 | 增量游标 + `reqwest` 取数 |
//! | NATS 订阅/发布 | 已实现（默认特性 `nats`） | 可用 `--no-default-features` 关闭；无服务器时返回依赖不可用。**事件总线发布**（[`bus`]）使用 SQL 事务队列与 JetStream 存储确认，支持故障重试；**入向 JetStream 订阅**见 [`jetstream`] |
//! | OTLP/HTTP | **已实现（logs + traces + metrics）**（[`otlp`]） | JSON + Protobuf + gzip；三信号经 [`otlp::signal_router`] 统一挂载，装配点须 `declare_wired` 登记（未登记显示 `not-wired`） |
//! | OTLP/gRPC（4317） | 三信号已实现（[`otlp_grpc`]） | 三类官方服务复用 HTTP 解析；按实际装配展示状态；无效 TLS 配置拒绝启动 |
//! | OSS/S3 对象拉取 | **已实现**（[`object_pull`]） | ETag 幂等游标 + 游标落盘；对象正文限 NDJSON/JSON 文本，列式 Parquet 对象需 `arrow`（本仓未声明） |
//! | SQL 拉取（"JDBC"） | **已实现（PostgreSQL / MySQL / MSSQL / Oracle）**（[`jdbc`]） | 驱动按 DSN scheme 自动选（`postgres://`/`mysql://`/`mssql://`/`oracle://`）；Oracle 走 `oracle` crate（OCI/ODPI-C，**构建期需 C 编译器**、运行期需 Instant Client，本项目放仓库内 `tools/oracle/`，由 `AGF_ORACLE_CLIENT_LIB_DIR` 指给驱动）；OCI 缺失/连接失败只 warn，`/readyz` notes 如实说明；未覆盖项见 `TODO ingest-jdbc-oracle-extras` |
//! | MQTT | **已实现**（[`mqtt`]） | TLS(`mqtts://`/`wss://`，rustls，默认校验证书链) + **WebSocket(`ws://`/`wss://`)** + **MQTT 5**（会话过期/Clean Start、Topic Alias、Receive Maximum、订阅选项、用户属性） + 共享订阅(`$share/<group>/<topic>`) + 遗嘱(LWT) 已接线；v5 AUTH 增强认证未接线：`TODO ingest-mqtt-v5-auth` |
//! | SNMP Trap | **已实现（v1/v2c；v3 USM 三种安全级别全落地）**（[`snmp`]） | `noAuthNoPriv` / `authNoPriv`(HMAC-MD5-96/`SHA-96`) / **`authPriv`：CBC-DES(RFC3414 §8) + CFB128-AES-128(RFC3826 §3)**（[`snmp::privacy`]）；认证/解密失败按 `usmStats` 分类计数；Inform 只解析不回应答：`TODO ingest-snmp-inform-ack` |
//! | Kafka | **已实现**（[`kafka`]，纯 Rust `rskafka` 0.6 + 自研消费者组协议） | 多分区独立游标 + SASL/PLAIN\|SCRAM-SHA-256/512 + TLS（默认校验证书链）+ 指数退避重连 + offset/lag 指标 + 优雅停机；**消费者组协议**（`AGF_INGEST_KAFKA_GROUP_ID`，[`kafka::group`]）在 `apache/kafka:3.9.0` 真机实测通过（入组/分配/接管/续消费）；SASL/OAUTHBEARER 与粘性分配未实现：`TODO ingest-kafka-oauthbearer` |
//! | Pulsar | **两条路径并存**：① [`pulsar`] = **原生二进制协议**（`AGF_INGEST_PULSAR_URL`，本轮实现）；② [`receiver::PulsarReceiver`] = **经 KoP（Kafka on Pulsar）复用 Kafka 接收器**（`AGF_INGEST_PULSAR_SERVICE_URL`） | 原生路径**未覆盖**：LZ4/ZSTD/SNAPPY 压缩、分区 topic/LOOKUP、Key_Shared 分派、死信/多 topic、AckReceipt/事务（收到未实现能力时显式报错/按 ValidationError 回执，不静默）；KoP 路径：订阅类型/消息级 ack/non-persistent topic 不可用；两条路径都未配置 ⇒ 不启用（能力矩阵两行如实标注） |
//! | 冷存储 Parquet | **已实现（写 + 读 + 回灌）** | 写出走低层 `parquet`（SNAPPY，列由 `Event` 字段派生）；读回走 **arrow `RecordBatchReader`**（[`coldarchive::read_parquet_arrow`]）+ 低层行式对照；编码失败自动回落 gzip NDJSON 并 `warn`；**arrow 列式回灌**（[`coldarchive::ColdReplayer`]，`AGF_ARCHIVE_REPLAY`，按时间/租户过滤 + `raw_hash` 幂等账本） |
//! | 采集器上行（AgentReport + 原始日志） | 已实现 | mTLS 指纹纯函数校验 + 信封解码 |
//!
//! 所有能力都会在 [`receiver::receiver_capability_matrix`] 与
//! [`registry::engine_support_matrix`] 中如实呈现，接入能力页直接渲染这两张表；
//! `/readyz` 的 `listeners` 另给出"本进程真的绑定了哪些端口"。
//! **Rust 动态库插件**另有一张"本进程真实装载结果"的表：
//! [`engine::plugin::plugin_runtime_status`]（已装载 / 装载失败 / 五类调用失败计数 /
//! 最近诊断），`/readyz` 的 `notes` 与启动日志直接引用它。
//!
//! ## 离线可测
//!
//! 全部单元测试**不需要网络、不需要 PostgreSQL、不需要 docker**：持久化走
//! [`pipeline::InMemorySink`]，对象存储走可注入的 [`object_pull::ObjectSource`]，
//! SQL 走可注入的 [`jdbc::SqlSource`]，MQTT 走可注入的 [`mqtt::MqttSubscription`]，
//! Kafka 走可注入的 [`kafka::KafkaSource`]，HTTP 取数走可注入的 [`receiver::HttpFetcher`]，
//! OTLP 三信号走 `axum` 路由的**进程内** `ServiceExt::oneshot`（`tests/otlp_signal_routes.rs`），
//! JetStream 走可注入的 [`jetstream::FakeJetStream`]，SNMP 走**手写 BER 编码器**构造的报文（[`snmp::ber`]）。
//! Docker/真实服务只在 `docker-compose.ingest-test.yml` 的端到端验证里使用
//! （真机用例：`tests/jetstream_live.rs` 需 `AGF_E2E_JETSTREAM_URL`，`tools/simulators/run_e2e_cel_otlp_jetstream.ps1` 是总跑法）。

pub mod ai_parser;
pub mod bus;
pub mod cel;
pub mod coldarchive;
pub mod engine;
pub mod jdbc;
pub mod jetstream;
pub mod kafka;
pub mod metrics;
pub mod mqtt;
pub mod normalize;
pub mod object_pull;
pub mod otlp;
pub mod otlp_grpc;
pub mod payload;
pub mod pipeline;
pub mod pulsar;
pub mod receiver;
pub mod registry;
pub mod replay;
pub mod snmp;
pub mod syslog;
pub mod template;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// 便捷重导出：接入侧最常用的类型。
pub mod prelude {
    pub use crate::bus::{EventBus, InMemoryEventBus, NoopEventBus};
    pub use crate::normalize::{SourceMeta, normalize};
    pub use crate::pipeline::{InMemorySink, IngestConfig, IngestOutcome, IngestPipeline, Sink, SqlSink};
    pub use crate::receiver::{Receiver, ReceiverDescriptor, ReceiverStatus, WebhookReceiver};
    pub use crate::registry::ParserRegistry;
}
