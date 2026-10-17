//! NATS JetStream **入向**接入：durable stream/consumer 幂等声明 + ack/nak/term 语义 +
//! pull（批量拉取）/ push（服务端推送）两种订阅模式（§4.5 协议接入）。
//!
//! > **与事件总线无关**：本模块是"从 NATS 收日志进来"；[`crate::bus`] 的 `NatsEventBus`
//! > 是"把事件发布出去"，**只有核心协议 publish，不是 JetStream**（PV-013 / DOC-PV-029 另论）。
//!
//! ## 语义模型
//!
//! | 能力 | 语义 | 说明 |
//! |---|---|---|
//! | durable stream | 幂等创建 | 服务端 `get_or_create_stream`；同名重复声明返回既有 stream |
//! | durable consumer | 幂等创建 | 服务端 `get_or_create_consumer`；同名重复声明返回既有 consumer |
//! | ack | 处理完成 | 事件落库成功后显式确认（**真** `ack_with(AckKind::Ack)`，见 [`nats_impl`]） |
//! | nak | 稍后重投 | 暂态失败（如落库抖动）显式拒绝（`AckKind::Nak(None)`，按 `ack_wait` 重投），**不**计入 `dropped` |
//! | term | 终止投递 | 消息非法（无记录可拆/超过 `max_deliver` 次重投）时终止（`AckKind::Term`），并计入 `dropped` |
//! | pull 模式 | 批量拉取 | `fetch_batch` 按批取回（过期时间内服务器聚合，天然背压） |
//! | push 模式 | 订阅推送 | 服务端推送到 deliver subject，接收器逐条消费 |
//!
//! 投递语义：**至少一次**。落库成功才 ack；失败一律 nak 重投（超次后由接收器 term），
//! 与 [`crate::bus`] / [`crate::kafka`] / [`crate::mqtt`] 的口径一致。
//!
//! ## 真机事实（本轮修复）
//!
//! 修复前 [`nats_impl::AsyncNatsJetStream::ack`] 是**空实现**（只 `debug!` + `Ok(())`，
//! 从不 `ack_with`）：真机上"至少一次"不成立——消息永远不会被应答，只会按 `ack_wait`
//! 无限重投（`/jsz` 的 `num_redelivered` 单调增长、`num_ack_pending` 永不归零）。
//! 现在取数点登记原始消息句柄、应答点调 `ack_with(AckKind)` 并摘除句柄；
//! 句柄缺失时**返回错误**（不静默成功）。
//!
//! ## 命名与"重启不丢"
//!
//! 真机装配用 [`plan::StreamPlan::for_identity`] / [`plan::ConsumerPlan::for_identity`]：
//! 名字只由配置（`AGF_INGEST_JETSTREAM_IDENTITY`）决定，**不**用每次启动新生成的
//! `LogSource::id`——否则重启后 stream/consumer 名一变，durable 续投就不成立。
//!
//! ## 离线可测
//!
//! 真实实现走 `async-nats`（默认特性 `nats`；`--no-default-features` 可整体关闭，见 [`nats_impl`]）。
//! 测试注入 [`source::FakeJetStream`] 内存实现，**不需要真实 NATS / docker**；
//! 部署拓扑（stream/consumer 计划）是纯函数（见 [`plan`]），可在无连接下直接断言。

pub mod plan;
mod receiver;
pub mod source;

#[cfg(feature = "nats")]
pub mod nats_impl;

#[cfg(test)]
mod tests;

pub use plan::{
    ConsumerPlan, DEFAULT_BATCH_SIZE, DEFAULT_CONSUMER_PREFIX, DEFAULT_STREAM_PREFIX, JetAckAction, JetConsumerStats,
    JetMessage, JetMode, JetStreamState, StreamPlan, parse_nats_urls, sanitize_token, stream_name_for_durable,
};
pub use receiver::{JetIngestReport, JetStreamReceiver};
pub use source::{FakeJetStream, JetStreamSource};

#[cfg(feature = "nats")]
pub use nats_impl::{AsyncNatsJetStream, ack_kind};
