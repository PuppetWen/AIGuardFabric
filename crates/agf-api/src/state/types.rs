//! 状态层的数据类型：运行模式、启动结论、WS 事件、风险历史（自 `state.rs` 拆出）。

use super::*;

/// 运行模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceMode {
    /// 离线内存模式（未配置数据库，或 `AGF_MOCK_MODE=1`）。
    Offline,
    /// 已连接 PostgreSQL（资源仍以内存为准，见 [`crate::store`] 文档）。
    Database,
}

impl ServiceMode {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Offline => "offline",
            Self::Database => "database",
        }
    }

    /// 是否为离线模式。
    #[must_use]
    pub const fn is_offline(&self) -> bool {
        matches!(self, Self::Offline)
    }
}

/// 引导管理员创建结果。
#[derive(Debug, Clone)]
pub enum BootstrapOutcome {
    /// 已创建。
    Created {
        /// 用户。
        user: User,
        /// 随机生成的口令（仅在未显式提供口令时返回；调用方**不得**写日志）。
        generated_password: Option<String>,
    },
    /// 已存在（幂等启动）。
    AlreadyExists {
        /// 用户。
        user: User,
    },
}

/// 事件推送消息（`GET /ws`）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WsEvent {
    /// 事件类型（`alert` / `finding` / `asset` / `scan` / `policy` / `heartbeat`）。
    pub kind: String,
    /// 所属租户。
    pub tenant_id: TenantId,
    /// 事件时间。
    pub at: Timestamp,
    /// 载荷。
    pub payload: serde_json::Value,
}

/// 风险趋势采样点（`/overview` 的 `riskTrend`，前端 `SeriesPoint`）。
#[derive(Debug, Clone, Copy)]
pub struct RiskSample {
    /// 采样时刻。
    pub at: Timestamp,
    /// 采样值（当前口径：未结的严重 + 高危发现数）。
    pub value: f64,
}

/// 每租户最多 168 个真实小时观测值，周期性保存到本实例的数据目录。
/// 首次观测前保持空序列；重启通过 history 模块恢复，不推造零值启动点。
#[derive(Debug)]
pub struct RiskHistory {
    /// 各租户的采样序列（升序；按租户隔离，避免超级管理员切换租户看到混在一起的曲线）。
    samples: Mutex<BTreeMap<TenantId, Vec<RiskSample>>>,
}

impl RiskHistory {
    /// 每个租户最多保留的采样点数（7 天 × 24 小时）。
    pub const MAX_SAMPLES: usize = 168;

    /// 新建空观测序列；保留参数以兼容既有装配入口。
    #[must_use]
    pub fn new(_started_at: Timestamp) -> Self {
        Self { samples: Mutex::new(BTreeMap::new()) }
    }

    /// 记录一次采样。
    ///
    /// 同一小时桶内**覆盖当前点**（曲线按小时聚合，不会因高频请求膨胀成锯齿），
    /// 跨小时追加新点；同一小时只保留最新实际观测。
    /// 锁中毒时静默跳过（可观测性数据不值得阻断请求）。
    pub fn record(&self, tenant: TenantId, at: Timestamp, value: f64) {
        let Ok(mut samples) = self.samples.lock() else {
            return;
        };
        let series = samples.entry(tenant).or_default();
        let bucket = hour_bucket(at);
        match series.binary_search_by_key(&bucket, |sample| hour_bucket(sample.at)) {
            Ok(index) if series[index].at <= at => series[index] = RiskSample { at, value },
            Ok(_) => {} // An older observation must not replace a newer sample in the same hour.
            Err(index) => series.insert(index, RiskSample { at, value }),
        }
        while series.len() > Self::MAX_SAMPLES {
            series.remove(0);
        }
    }

    /// 某租户的真实采样序列，从未采样时为空。
    #[must_use]
    pub fn points(&self, tenant: TenantId) -> Vec<RiskSample> {
        self.samples.lock().ok().and_then(|samples| samples.get(&tenant).cloned()).unwrap_or_default()
    }

    /// 已采样过的租户列表（供周期性落盘枚举用；顺序稳定，便于测试与可复现输出）。
    #[must_use]
    pub fn tenants(&self) -> Vec<TenantId> {
        self.samples
            .lock()
            .map(|samples| {
                let mut tenants: Vec<TenantId> = samples.keys().copied().collect();
                tenants.sort_by_key(ToString::to_string);
                tenants
            })
            .unwrap_or_default()
    }

    /// 采样点总数（所有租户合计；`/readyz` 之类的自检可用）。
    #[must_use]
    pub fn len(&self) -> usize {
        self.samples.lock().map(|samples| samples.values().map(Vec::len).sum()).unwrap_or(0)
    }

    /// 是否还没有任何采样点。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// 小时桶（Unix 小时序号，UTC）。
fn hour_bucket(at: Timestamp) -> i64 {
    at.as_datetime().timestamp() / 3_600
}
