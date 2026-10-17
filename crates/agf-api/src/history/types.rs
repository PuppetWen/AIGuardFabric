//! 风险历史的数据类型与常量（自 `history.rs` 拆出，逻辑未变）。

use super::*;

/// 环境变量：风险历史文件路径（**优先于**数据目录约定；空串视为未设置）。
pub const ENV_RISK_HISTORY_PATH: &str = "AGF_RISK_HISTORY_PATH";

/// 环境变量：数据目录（与 `AppConfig::data_dir` 同源；空串视为未设置）。
pub const ENV_DATA_DIR: &str = "AGF_DATA_DIR";

/// 数据目录缺省值（与 `AppConfig::data_dir` 的默认一致）。
pub const DEFAULT_DATA_DIR: &str = "data";

/// 相对数据目录的子目录。
pub const STATE_DIR: &str = "state";

/// 相对数据目录的文件名。
pub const FILE_NAME: &str = "risk-history.json";

/// 每个租户最多保留的采样点数（7 天 × 24 小时；与 `state::RiskHistory::MAX_SAMPLES` 一致）。
pub const MAX_SAMPLES_PER_TENANT: usize = 168;

/// 本进程能写/能读的最高文件格式版本。
pub const FORMAT_VERSION: u32 = 2;

/// 落盘的一个采样点（小时级 KPI 采样）。
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Sample {
    /// 所属租户（按租户隔离：超管切换租户不该看到混在一起的曲线）。
    pub tenant_id: TenantId,
    /// 采样时刻（UTC，ISO 8601 / RFC 3339）。
    pub ts: Timestamp,
    /// 采样值（当前口径：未结的严重 + 高危发现数）。
    pub value: f64,
}

impl Sample {
    /// 构造一个采样点。
    #[must_use]
    pub const fn new(tenant_id: TenantId, ts: Timestamp, value: f64) -> Self {
        Self { tenant_id, ts, value }
    }

    /// 所属小时桶（Unix 小时序号，UTC）——与 `state::RiskHistory` 的分桶口径一致。
    #[must_use]
    pub const fn hour_bucket(&self) -> i64 {
        self.ts.unix_secs() / 3_600
    }
}

/// 磁盘文件封套（带版本，便于将来演进格式）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct HistoryFile {
    /// 格式版本（0/1 含无法区分的零值占位，升级时先归档再重新观测）。
    #[serde(default)]
    pub(super) version: u32,
    /// 采样点（平铺，跨租户）。
    pub(super) samples: Vec<Sample>,
}

/// 风险历史持久化的**命名空间**（无状态：只是把一组函数挂到一个好记的名字下）。
///
/// 它**不持有**运行期采样序列——进程内的滚动集合仍是 [`crate::state::RiskHistory`]；
/// 本类型只负责"从磁盘读"（[`Self::load_from`]）与"往磁盘写"（[`Self::save_to`]）。
#[derive(Debug)]
pub struct RiskHistory;

impl RiskHistory {
    /// 从磁盘加载采样点（等价于模块级 [`load_from`]）。
    ///
    /// 文件不存在返回空列表；格式损坏、版本不支持、读取或归档失败返回 Err。
    /// 调用方继续服务，但停止自动覆盖原历史。
    ///
    /// # Errors
    /// 文件存在但读取失败（权限不足、路径是目录、IO 错误）。
    pub fn load_from(path: impl AsRef<Path>) -> DomainResult<Vec<Sample>> {
        load_from(path)
    }

    /// 原子写入采样点（等价于模块级 [`save_to`]）。
    ///
    /// 写临时文件 + `rename` 替换；任何失败只 `warn`（**不返回错误**：一次采样没落盘
    /// 不应该让 `/overview` 失败）。
    pub fn save_to(path: impl AsRef<Path>, samples: &[Sample]) {
        save_to(path, samples);
    }

    /// 缺省文件路径（环境变量优先，见 [`path_for`]）。
    #[must_use]
    pub fn default_path() -> PathBuf {
        default_path()
    }
}
