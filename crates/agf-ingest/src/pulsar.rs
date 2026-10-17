//! Pulsar **原生二进制协议**消费者（`pulsar://host:6650`）—— 与既有 **KoP 路径并存**的另一条路。
//!
//! ## 与 KoP 路径的关系（**两条路径分别列行，不互相冒充**）
//!
//! | 路径 | 入口配置 | 取数方式 | 能力矩阵行 |
//! |---|---|---|---|
//! | **KoP（既有，不改动）** | `AGF_INGEST_PULSAR_SERVICE_URL=kafka://host:19092` | Kafka wire protocol → [`crate::receiver::PulsarReceiver`] → [`crate::kafka`] | `pulsar` |
//! | **原生（本模块）** | `AGF_INGEST_PULSAR_URL=pulsar://host:6650` | Pulsar binary protocol（本模块手写编解码） | `pulsar-native` |
//!
//! 装配点的优先级：**配置了 `AGF_INGEST_PULSAR_URL` ⇒ 走原生**（显式配置优先）；
//! 未配置时若配了 `AGF_INGEST_PULSAR_SERVICE_URL` ⇒ 回落 KoP；两者都未配置 ⇒ 不启用。
//! 两条路径**互不改变对方**：KoP 的 env 名、`PulsarReceiver` 的公开 API 与原行为逐字保留。
//!
//! ## 本模块的分层
//!
//! | 文件 | 职责 |
//! |---|---|
//! | [`proto`] | `PulsarApi.proto` 的最小消息子集（**手写**，prost derive，无 protoc） |
//! | [`frame`] | 长度前缀帧 + MAGIC `0x0e01` + CRC32C 校验（编解码与校验**纯函数**） |
//! | [`batch`] | `num_messages_in_batch > 1` 的拆条 + 压缩（ZLIB） |
//! | [`config`] | `AGF_INGEST_PULSAR_*` 配置解析与校验（URL/TLS/topic/订阅类型…） |
//! | [`client`] | TCP 连接、CONNECT/SUBSCRIBE/FLOW/ACK、错误分类、指数退避重连 |
//! | [`receiver`] | [`PulsarNativeReceiver`]：`Receiver` trait 实现（接流水线 + 真 ack） |
//!
//! ## 协议事实（实现依据，逐条可对照 Apache Pulsar `branch-3.3` 源码）
//!
//! * **帧格式**（`Commands.serializeWithSize`）：
//!   `[TOTAL_SIZE u32 BE = 4 + CMD_SIZE][CMD_SIZE u32 BE][BaseCommand]`
//!   ——`TOTAL_SIZE` **不含**自身那 4 字节；
//! * **消息帧**（`Commands.serializeCommandMessageWithSize`）在命令之后再接：
//!   `[MAGIC u16 = 0x0e01][CHECKSUM u32 BE][METADATA_SIZE u32 BE][MessageMetadata][PAYLOAD]`；
//! * **CRC32C 覆盖范围**（`Commands.serializeMetadataAndPayload`）：`METADATA_SIZE`
//!   这 4 字节 + `MessageMetadata` + `PAYLOAD`（**不含** MAGIC 与 CHECKSUM 本身）；
//! * **魔数只出现在消息帧**：客户端→broker 的命令帧没有魔数（题面里"发送魔数"的说法与
//!   上游实现不符——本实现按上游实现校验**收到**的每一帧魔数，并在自测里对编码侧同样断言）。
//!
//! ## 未实现（如实，能力矩阵同步标注）
//!
//! * **压缩**：只支持 `NONE` 与 `ZLIB`；`LZ4`/`ZSTD`/`SNAPPY` 未实现 ⇒ 收到时按
//!   `CommandAck.validation_error = DecompressionError` **显式回执并计数**（不静默丢，
//!   也不会让 broker 无限重投）；
//! * **分区 topic / LOOKUP**：不做 `CommandLookupTopic` 与分区 topic 元数据查询，
//!   只直连给定 broker、订阅单个（非分区或已由外部指定分区的）topic；
//! * **Key_Shared / 死信 / 多 topic / non-persistent**：未实现；
//! * **Ack receipt / 事务 / schema 版本解释**：未实现（不请求 receipt，schema 一律 `NONE`）。

mod batch;
mod client;
mod config;
mod frame;
mod proto;
mod receiver;
mod tls;

#[cfg(test)]
mod tests;

pub use batch::*;
pub use client::*;
pub use config::*;
pub use frame::*;
pub use proto::*;
pub use receiver::*;
pub use tls::*;

/// 原生路径的 TODO 锚点（**一字不差地写清"原生已实现到什么程度"**）。
///
/// 与 [`crate::receiver::PULSAR_NATIVE_TODO`]（KoP 路径的"原生协议未实现"锚点）**不同**：
/// 这条锚点描述的是本模块**已实现**原生协议之后**仍未覆盖**的能力。
pub const PULSAR_NATIVE_REMAINING_TODO: &str = "TODO ingest-pulsar-native-extras：Pulsar 原生协议已实现\
     （CONNECT/SUBSCRIBE/FLOW/MESSAGE/ACK + batch 拆条 + CRC32C + token 鉴权 + 断线退避重连）；\
     未实现：LZ4/ZSTD/SNAPPY 压缩、分区 topic 与 CommandLookupTopic、Key_Shared/死信/多 topic、\
     非持久 topic、AckReceipt 与事务";
