//! 冷存储归档：热数据过期后落到对象存储（§4.5 分层存储：热 30 天 ClickHouse/TimescaleDB，
//! 冷对象存储 **Parquet**）。
//!
//! ## 分层策略
//!
//! | 层 | 介质 | 保留 | 用途 |
//! |---|---|---|---|
//! | 热 | ClickHouse / TimescaleDB | `hot_days`（默认 30 天） | 检索、关联、看板 |
//! | 冷 | 对象存储（OSS/S3/MinIO） | `cold_days`（默认 365 天） | 审计、取证、合规留存 |
//!
//! ## 落地格式（`AGF_ARCHIVE_FORMAT`）
//!
//! | 值 | 格式 | 状态 |
//! |---|---|---|
//! | `parquet`（默认） | 列式 Parquet（SNAPPY） | **已实现**：写出走低层列式 API；读回走 **arrow `RecordBatchReader`**（`parquet` 的 `arrow` 特性 + `arrow` facade） |
//! | `ndjson-gzip` | gzip NDJSON | 已实现（Parquet 编码失败时**自动回落**到这里并 warn） |
//! | `ndjson` | 未压缩 NDJSON | 已实现（排障用，体积大） |
//!
//! ### arrow 生态的两条读回路径
//!
//! | 路径 | 入口 | 依赖面 |
//! |---|---|---|
//! | 低层行式 | [`decode_parquet_rows`]（`parquet::record`） | 只取 `raw_json` 列，作对照/兜底 |
//! | **arrow 列式** | [`decode_parquet`] / [`read_parquet_arrow`] / [`arrow_facts`] | 真正的 `RecordBatch`：可逐列核对列名/arrow 类型/单元格 |
//!
//! 写出仍走低层列式 API（`parquet::schema` / `parquet::column::writer` / `parquet::file::writer`）——
//! 写侧不需要 arrow 的数组内核；读侧需要（下游分析/谓词下推都在 arrow 生态里）。
//!
//! ### 列式 schema（由既有 [`Event`] 字段派生，没有虚构字段）
//!
//! `time`(INT64, TIMESTAMP_MILLIS) / `ingested_at`(INT64, TIMESTAMP_MILLIS) /
//! `tenant_id` / `source_id` / `source_name` / `protocol` / `vendor` / `product` /
//! `host` / `severity` / `message` / `raw_hash` / `raw_json`（均为 STRING）。
//!
//! 最后两列是**保真回灌**的关键：`raw_json` 存整条事件的序列化 JSON，因此
//! "写出去 → 读回来"是无损的（列式字段只服务于下游分析/谓词下推）；
//! 其余 12 列由 [`event_column_text`] 给出**与写出侧同一份**映射，供逐列比对。
//!
//! ### 回灌（`AGF_ARCHIVE_REPLAY`）
//!
//! [`ColdReplayer`] 把归档对象解回事件，按 [`ReplayFilter`]（时间窗/租户）过滤后写回
//! **既有 [`crate::pipeline::Sink`]**（与流水线同一个实例），并用 [`ReplayLedger`]
//! （`AGF_ARCHIVE_REPLAY_STATE`，`raw_hash` 集合）保证**幂等**：同一批回灌两次，第二次入库 0 条。
//! 回灌计数走 `agf_ingest_coldarchive_replay_*`。
//!
//! ### 回落语义（重要）
//!
//! Parquet 编码失败**绝不让归档失败**：warn 后自动改用 gzip NDJSON，并把对象键后缀与
//! `content_type` 一并改成 gzip（对象里**不放与内容不符的后缀**）。
//! 读取侧 [`ColdFormat::sniff`] 按内容魔数判格式，因此回落对象也能被原样读回。
//!
//! ## 指标
//!
//! [`archive_metrics`] 提供进程级计数：归档对象数 / 字节数 / 事件数 / 回落次数 / Parquet 对象数 /
//! 回灌对象数·入库数·重复跳过数·过滤数，以及 Prometheus 文本（`agf_ingest_coldarchive_*`）。

use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use agf_core::error::{DomainError, DomainResult};
use agf_core::event::Event;
use agf_core::time::Timestamp;
use bytes::Bytes;
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use parquet::basic::Compression as ParquetCompression;
use parquet::data_type::{ByteArray, ByteArrayType, Int64Type};
use parquet::file::properties::WriterProperties;
use parquet::file::reader::{FileReader, SerializedFileReader};
use parquet::file::writer::SerializedFileWriter;
use parquet::record::Field;
use parquet::schema::parser::parse_message_type;
use serde::{Deserialize, Serialize};
use tracing::warn;

mod arrow_codec;
mod encode;
mod format;
mod metrics;
mod parquet_codec;
mod replay;
mod replay_env;

#[cfg(test)]
mod tests;

pub use arrow_codec::*;
pub use encode::*;
pub use format::*;
pub use metrics::*;
pub use parquet_codec::*;
pub use replay::*;
pub use replay_env::*;
