//! 对象存储拉取接收器（S3 / OSS / MinIO 兼容）：**幂等拉新对象**并走既有解析流水线。
//!
//! ## 为什么需要它
//!
//! 云平台（OSS/S3/COS）与离线设备常把日志**批量落成对象**（NDJSON / 每行一条），
//! 而不是实时推送。这类接入是"拉"而不是"收"，且必须解决两个问题：
//!
//! 1. **幂等**：同一个对象不能被重复拉取（否则事件会翻倍）；
//! 2. **断点续传**：进程重启后不能从头再拉一遍。
//!
//! 本接收器用 `(key → ETag + LastModified + size)` 作为"已处理指纹"：
//!
//! * 键**没出现过** ⇒ 拉取；
//! * 键出现过但 **ETag 变化** ⇒ 重新拉取（对象被覆盖，内容确实变了）；
//! * 键出现过且 ETag 未变 ⇒ **跳过**（不重复拉取、不重复落库）。
//!
//! 游标以 JSON 落盘（默认 `<AGF_DATA_DIR>/ingest/object-pull-cursor.json`），
//! **每拉完一个对象即原子写盘**（先写 `.tmp` 再 `rename`）：崩溃后最多重放"当前正在拉的那个对象"，
//! 不会产生"已入库但游标未落盘"的重复窗口以外的不一致。
//!
//! ## 配置（环境变量见 `apps/ingest` 的模块文档）
//!
//! | 字段 | 环境变量 | 默认 |
//! |---|---|---|
//! | bucket | `AGF_INGEST_OBJECT_PULL_BUCKET` | 空（未配置 ⇒ 接收器不启停） |
//! | prefix | `AGF_INGEST_OBJECT_PULL_PREFIX` | 空（整桶） |
//! | interval | `AGF_INGEST_OBJECT_PULL_INTERVAL_SECS` | 60 |
//! | max_objects | `AGF_INGEST_OBJECT_PULL_MAX_OBJECTS` | 200 |
//! | max_object_bytes | `AGF_INGEST_OBJECT_PULL_MAX_OBJECT_BYTES` | 64 MiB |
//! | state | `AGF_INGEST_OBJECT_PULL_STATE` | `data/ingest/object-pull-cursor.json` |
//!
//! 端点/区域/凭据复用 `AGF_S3_ENDPOINT` / `AGF_S3_REGION` / `AGF_S3_ACCESS_KEY` /
//! `AGF_S3_SECRET_KEY` / `AGF_S3_FORCE_PATH_STYLE`，与 `agf-storage` 的 `S3ObjectStore`
//! 完全相同（同一 SDK、同一份 SigV4 实现），因此不需要在 `tools/simulators` 里另写签名。
//!
//! ## 降级
//!
//! * 列桶/取对象失败 ⇒ **只 warn + 计入 `dropped`**，接收器下一轮重试；进程不受影响；
//! * 单对象超限 ⇒ 跳过并**标记为已处理**（否则每轮都会重试同一个超大对象，形成活锁）；
//! * 游标文件损坏 ⇒ 视为空游标（会重新拉一遍，**不丢数据**，宁可重复也不漏）。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use agf_core::enums::IngestProtocol;
use agf_core::error::{DomainError, DomainResult};
use agf_core::source::LogSource;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::metrics::ReceiverCounters;
use crate::pipeline::IngestPipeline;
use crate::receiver::{HttpPullReceiver, Receiver, ReceiverDescriptor, ReceiverStatus};

mod cursor;
mod receiver;
mod source;

#[cfg(test)]
mod tests;

pub use cursor::*;
pub use receiver::*;
pub use source::*;
