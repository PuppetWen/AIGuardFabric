//! Kafka 消费接收器：**纯 Rust 客户端（`rskafka`）**，避免 librdkafka 的 C 工具链依赖。
//!//! 本模块同时是 **Pulsar（KoP）接收器的取数内核**：Pulsar 侧经 KoP（Kafka on Pulsar）
//! 暴露 Kafka 协议监听后，直接复用本接收器（见 [`crate::receiver::PulsarReceiver`]）。
//!
//! ## 为什么不用 `rdkafka`
//!
//! workspace 里声明了 `rdkafka = { features = ["cmake-build", "ssl-vendored"] }`，它在 Windows 上
//! 需要 CMake + C 编译器 + OpenSSL/Perl 才能构建，落地成本高且与"接入进程永远可启动"无关。
//! `rskafka` 是纯 Rust 实现（wire protocol 直连 broker），本接收器因此可以在任何平台构建。
//!
//! ## 产品语义：**至少一次（at-least-once）**
//!
//! * `rskafka` **不提供消费者组**（无 broker 侧 offset 提交、无 rebalance）。平台侧采用
//!   "**显式 offset + 本地游标文件**"：游标 = `topic/partition → 下一个待消费 offset`，
//!   JSON 原子落盘；
//! * 游标**在处理成功之后**才推进（`最后一条已消费记录 offset + 1`）：进程崩溃/被 kill
//!   最多**重放当前这一批**，绝不会丢记录；
//! * 重放与流水线去重口径一致：`agf_ingest` 的流水线对"同源 + 同时间 + 同载荷哈希"的记录
//!   去重，因此重放表现为 `deduped` 计数增加而**不会重复产生事件**；
//!   重复消费条数由 `agf_ingest_kafka_deduped_total`（Prometheus）与
//!   [`KafkaStats::deduped_total`] 如实给出——**"至少一次 + 去重"= 有效一次**；
//! * 反过来，**不做**"先推进游标再处理"（那是至多一次，会丢数据）。需要严格一次语义时，
//!   应在下游按业务主键幂等，而不是依赖本接收器。
//!
//! ## 多分区
//!
//! 每轮都向 broker **重新列出 topic 的全部分区**（而不是只认首轮结果）：
//!
//! * 每个分区**独立游标**（key = `topic/partition`），互不影响；
//! * **新增分区自动纳入**（新分区没有游标 ⇒ 按 `start_from` 解析起始位置）；
//! * 分区发现走两条路：先问 broker 的**全量 topic 列表**；拿不到（例如 KoP 这类
//!   协议兼容层对"不带 topic 的 Metadata 请求"返回空）则退化为**按分区号递增探测
//!   topic 级 metadata**（上限 64 个分区，见 [`partition_probe_range`]）。
//!   两条路都拿不到 ⇒ 视为 topic 不存在（`NotFound`，如实报错而不是静默空转）；
//! * 分区消失（或游标越出保留窗口）⇒ 该分区本轮只 warn + 计数，下游标被丢弃，
//!   下一轮按 `start_from` 重新定位（否则游标会永久卡在失效位置）。
//!
//! ## 鉴权（SASL）与传输加密（TLS）
//!
//! | 机制 | 环境变量 | 说明 |
//! |---|---|---|
//! | `SASL/PLAIN` | `AGF_INGEST_KAFKA_SASL_MECHANISM=PLAIN` | KoP 的 token 鉴权即走此机制（username=`token`、password=Pulsar token） |
//! | `SASL/SCRAM-SHA-256` | `AGF_INGEST_KAFKA_SASL_MECHANISM=SCRAM-SHA-256` | 主流 Kafka 均支持 |
//! | `SASL/SCRAM-SHA-512` | `AGF_INGEST_KAFKA_SASL_MECHANISM=SCRAM-SHA-512` | 同上 |
//! | 凭据 | `AGF_INGEST_KAFKA_SASL_USERNAME` / `_PASSWORD` | **只从环境变量（settings）取**；[`KafkaSaslConfig`] 的 `Debug` 与 [`KafkaSecurity::describe`] 一律以 `<redacted>` 占位，密码绝不进日志/错误文本 |
//! | TLS | `AGF_INGEST_KAFKA_TLS=1` | 默认**关闭**；开启后默认**校验证书链** |
//! | 自签 CA | `AGF_INGEST_KAFKA_TLS_CA=<PEM 路径>` | 注入私有 CA（与 webpki 公共根一起构成信任库） |
//! | 双向 TLS | `AGF_INGEST_KAFKA_TLS_CERT` / `_KEY` | 客户端证书（PEM）+ 私钥 |
//! | 跳过校验 | `AGF_INGEST_KAFKA_TLS_INSECURE_SKIP_VERIFY=1` | **仅排障**；启用时必 `warn!`，且**只**在该显式开关下生效 |
//!
//! ## 断线重连与背压
//!
//! * broker 断开：按**指数退避**重连（`AGF_INGEST_KAFKA_RECONNECT_INITIAL_MS` 起，
//!   每轮 ×2，**上限** `AGF_INGEST_KAFKA_RECONNECT_MAX_MS`，默认 500ms → 30s）；
//! * **不退避刷屏**：同一故障只 warn 一次，后续降为 `debug!`，恢复时 info 一条；
//! * **不丢游标**：重连期间游标保持在上次成功位置，broker 恢复后从该位置续传；
//! * 单分区单轮条数上限 `AGF_INGEST_KAFKA_MAX_RECORDS` 就是**背压阀**：超出的记录
//!   留在 broker（游标不越过它们），下一轮继续，不会丢也不会内存膨胀。
//!
//! ## 可观测
//!
//! | 指标 | 语义 |
//! |---|---|
//! | `agf_ingest_kafka_offset{receiver,topic,partition}` | 本地游标（下一个待消费 offset） |
//! | `agf_ingest_kafka_lag{receiver,topic,partition}` | 滞后 = broker 高水位 − 本地游标 |
//! | `agf_ingest_kafka_fetch_failures_total{...}` | 该分区定位/拉取失败累计次数 |
//! | `agf_ingest_kafka_reconnects_total{receiver,topic}` | 退避重连次数 |
//! | `agf_ingest_kafka_reconnect_backoff_seconds{...}` | 当前退避间隔（秒） |
//! | `agf_ingest_kafka_records_consumed_total{...}` | 已消费（游标已推进）记录数 |
//! | `agf_ingest_kafka_deduped_total{...}` | 流水线去重命中的记录数（重放的可见证据） |
//! | `agf_ingest_kafka_skipped_records_total{...}` | 协议层跳过（墓碑/空值）记录数 |
//!
//! `agf_ingest_receiver_{received,matched,parse_failed,dropped}_total{receiver=...}` 四族由
//! [`crate::metrics`] 统一承接；`/stats` 另给出**每个分区的状态**
//! （offset / lag / 累计条数 / 连续失败次数 / 最近失败原因）。
//!
//! ## 优雅停机
//!
//! SIGINT/SIGTERM：由 `apps/ingest` 通过 [`KafkaShutdown`] 广播停机信号 →
//! 本接收器**立即跳出等待、刷新游标落盘、返回 `Ok(())`**，绝不在退出路径上丢游标。
//!
//! ## 配置
//!
//! | 字段 | 环境变量 | 默认 |
//! |---|---|---|
//! | brokers | `AGF_INGEST_KAFKA_BROKERS`（逗号分隔） | 空（未配置 ⇒ 不启停） |
//! | topic | `AGF_INGEST_KAFKA_TOPIC` | 空（必填） |
//! | 消费起点 | `AGF_INGEST_KAFKA_START_FROM`（`earliest`/`latest`） | `earliest` |
//! | 单分区单轮上限 | `AGF_INGEST_KAFKA_MAX_RECORDS` | 500 |
//! | 拉取字节上限 | `AGF_INGEST_KAFKA_MAX_BYTES` | 1 MiB |
//! | 长轮询等待 | `AGF_INGEST_KAFKA_MAX_WAIT_MS` | 500 |
//! | 间隔 | `AGF_INGEST_KAFKA_INTERVAL_SECS` | 5 |
//! | 游标文件 | `AGF_INGEST_KAFKA_CURSOR_PATH` | `data/ingest/kafka-cursor.json` |
//! | 退避初始/上限 | `AGF_INGEST_KAFKA_RECONNECT_INITIAL_MS` / `_MAX_MS` | 500 / 30000 |
//! | 放弃阈值 | `AGF_INGEST_KAFKA_RECONNECT_MAX_ATTEMPTS` | 0（永不放弃） |
//! | **副本序号** | `AGF_INGEST_*_INSTANCE_ID`（Pulsar/KoP 填 `..._PULSAR_INSTANCE_ID`） | 未配置 = 单副本 |
//! | **副本总数** | `AGF_INGEST_*_INSTANCE_COUNT` | 1 |
//! | **租约目录**（多副本接管） | `AGF_INGEST_*_LEASE_DIR` | 未配置 = 纯静态取模，不接管 |
//! | 租约判活时长 | `AGF_INGEST_*_LEASE_TTL_MS` | 15000 |
//! | 启动静默期 | `AGF_INGEST_*_ASSIGN_SETTLE_MS` | 3000 |
//!
//! ## 多副本分区分配（无消费者组时的并行消费语义）
//!
//! `rskafka` 没有 JoinGroup/SyncGroup/Heartbeat ⇒ 并行消费由本接收器自己承担：
//! `owner(p) = live[p % live.len()]`（见 [`partition_owner`]，纯函数、确定性、无重叠无遗漏）。
//!
//! * **静态模式**（只配 `INSTANCE_ID/COUNT`）：`live` = 配置的 `0..count`，不接管；
//! * **租约模式**（再配 `LEASE_DIR`）：`live` = 心跳未过期的副本集合 ⇒ 对端判死后
//!   **全量重分片**（不留无主分区），接管者从共享目录里的**分区分片游标**继续
//!   （`cursor-{订阅名}-{topic}-p{N}.json`）⇒ **接管不丢不重**；
//! * **启动静默期**（`ASSIGN_SETTLE_MS`）：等价 Kafka 的 `group.initial.rebalance.delay.ms`。
//!   没有它时"先启动的副本在第一轮就把全部分区认领并开始消费"，与随后启动的同伴
//!   形成**重叠消费窗口**（实测：副本 0 认领 [0,1,2]、副本 1 也认领 [1]）；
//! * **降级**：租约目录不可写 ⇒ 回落静态取模并 `warn!`（宁可不接管，也不冒重复消费的险）；
//! * **观测**：`/stats` 的 `kafka_partitions.*.{owned,owner_instance,live_instances}`
//!   （未负责的分区 `next_offset/lag = -1` = 未知），`/metrics` 的
//!   `agf_ingest_kafka_partition_owned` / `_partition_takeovers_total` / `_instance_info{...,settling=}`。
//!
//! **语义边界（如实）**：没有 broker 侧 generation fence，副本增减的瞬时重分片存在
//! ≤1 个轮询间隔的重叠窗口（由流水线内容去重兜住：at-least-once + 去重）；
//! 接管路径（对端租约到期后才认领）没有该窗口。接管时间上界 = `LEASE_TTL_MS` + 一个轮询间隔。
//!
//! ## 两条路径：**真消费者组协议** vs 本地游标（默认）
//!
//! 配了 `AGF_INGEST_KAFKA_GROUP_ID` ⇒ 走 [`group`] 的**broker 侧消费者组协议**
//! （`FindCoordinator` → `JoinGroup` → `SyncGroup` → `Heartbeat` → `OffsetFetch` → `Fetch` →
//! `OffsetCommit` → `LeaveGroup`；分区分配由协调器/组长下发，offset 提交到 `__consumer_offsets`，
//! 有**代际栅栏**）。**未配置 ⇒ 行为与历史版本逐字节一致**（`rskafka` + 本地游标 + 可选租约接管）。
//! 两条路径的逐项差异（分配、offset 存放、判活、接管延迟、适用面）见 [`group`] 的模块文档。
//!
//! ## 未实现（如实标注）
//!
//! * **SASL/OAUTHBEARER**：`rskafka` 0.6 具备该能力，但本接收器未接线（需要 token 回调）。
//!   `TODO ingest-kafka-oauthbearer`；
//! * **消费者组路径的 SASL/SCRAM**：组协议客户端只实现 `SASL/PLAIN`（KoP 的 token 鉴权用它）；
//!   SCRAM 需要完整的 client-first/server-first/client-final 状态机，未接线。
//!   `TODO ingest-kafka-group-scram`（本地游标路径的 SCRAM 不受影响，`rskafka` 已支持）。

// 测试代码用 `panic!`/`unwrap` 作为断言手段（仓库 lints 在发布路径上仍然 deny）。
#![cfg_attr(test, allow(clippy::panic, clippy::unwrap_used, clippy::expect_used))]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agf_core::enums::IngestProtocol;
use agf_core::error::{DomainError, DomainResult};
use agf_core::source::LogSource;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::metrics::ReceiverCounters;
use crate::pipeline::IngestPipeline;
use crate::receiver::{HttpPullReceiver, Receiver, ReceiverDescriptor, ReceiverStatus};

mod config;
mod cursor;
mod group;
mod lease;
mod receiver;
mod receiver_pull;
mod security;
mod source;
mod stats;

#[cfg(test)]
#[allow(clippy::redundant_pub_crate)]
pub(crate) mod tests;

pub use config::*;
pub use cursor::*;
pub use group::*;
pub use lease::*;
pub use receiver::*;
pub use security::*;
pub use source::*;
pub use stats::*;
