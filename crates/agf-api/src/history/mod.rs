//! 风险趋势保存真实的小时观测：每租户最多 168 点，没有观测时不补零。
//!
//! v2 文件按小时保留最后一次观测。旧版文件可能混入启动零值，因此完整归档后重新采样。
//! 归档保留原始字节，内容哈希命名且不覆盖；归档、读取或解析失败时继续服务并禁止自动写盘。
//! 持久化以本实例数据目录为边界，默认每 5 分钟一次；多副本不合并，长期指标使用 Prometheus。
//! 文件格式：`{"version":2,"samples":[{"tenant_id":"...","ts":"...","value":5}]}`。

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use agf_core::error::DomainResult;
use agf_core::ids::TenantId;
use agf_core::time::Timestamp;
use serde::{Deserialize, Serialize};
use tracing::warn;

pub use io::*;
pub use series::*;
pub use types::*;

mod io;
mod migration;
mod series;
#[cfg(test)]
mod tests;
mod types;
