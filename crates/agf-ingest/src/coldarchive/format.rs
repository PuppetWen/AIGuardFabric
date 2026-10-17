//! 归档格式与保留策略：落盘格式（Parquet / gzip NDJSON）、归档配置与热/冷保留计划。

use super::*;

/// 冷归档落地格式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ColdFormat {
    /// 列式 Parquet（SNAPPY 压缩）——**默认格式**。
    #[default]
    Parquet,
    /// gzip 压缩 NDJSON（Parquet 失败时的回落格式）。
    NdjsonGzip,
    /// 未压缩 NDJSON（排障用，体积大）。
    Ndjson,
}

impl ColdFormat {
    /// 对象键后缀。
    #[must_use]
    pub const fn extension(&self) -> &'static str {
        match self {
            Self::Parquet => "parquet",
            Self::NdjsonGzip => "ndjson.gz",
            Self::Ndjson => "ndjson",
        }
    }

    /// HTTP 内容类型。
    #[must_use]
    pub const fn content_type(&self) -> &'static str {
        match self {
            Self::Parquet => "application/vnd.apache.parquet",
            Self::NdjsonGzip => "application/gzip",
            Self::Ndjson => "application/x-ndjson",
        }
    }

    /// 是否已实现（三种格式全部落地）。
    #[must_use]
    pub const fn is_implemented(&self) -> bool {
        true
    }

    /// 配置文本（`AGF_ARCHIVE_FORMAT` 的取值）。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Parquet => "parquet",
            Self::NdjsonGzip => "ndjson-gzip",
            Self::Ndjson => "ndjson",
        }
    }

    /// 解析配置文本（不区分大小写；`gzip`/`ndjson.gz` 视为 `ndjson-gzip`）。
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let normalized: String = text.trim().to_ascii_lowercase().chars().filter(char::is_ascii_alphanumeric).collect();
        match normalized.as_str() {
            "parquet" | "pq" => Some(Self::Parquet),
            "ndjsongzip" | "ndjsongz" | "gzip" | "gz" => Some(Self::NdjsonGzip),
            "ndjson" | "jsonlines" => Some(Self::Ndjson),
            _ => None,
        }
    }

    /// 按 `AGF_ARCHIVE_FORMAT` 解析（缺省/非法值 ⇒ 默认 Parquet + warn，绝不让进程起不来）。
    #[must_use]
    pub fn from_env() -> Self {
        match std::env::var("AGF_ARCHIVE_FORMAT") {
            Ok(text) if !text.trim().is_empty() => match Self::parse(&text) {
                Some(format) => format,
                None => {
                    warn!(
                        value = %text,
                        "AGF_ARCHIVE_FORMAT 取值非法（支持 parquet / ndjson-gzip / ndjson），按默认 parquet 继续"
                    );
                    Self::Parquet
                }
            },
            _ => Self::Parquet,
        }
    }

    /// 按**内容魔数**判定格式（读取侧用；回落生成的对象也不会被误判）。
    #[must_use]
    pub fn sniff(bytes: &[u8]) -> Option<Self> {
        if bytes.starts_with(&[0x1f, 0x8b]) {
            return Some(Self::NdjsonGzip);
        }
        if bytes.starts_with(b"PAR1") && bytes.ends_with(b"PAR1") && bytes.len() > 8 {
            return Some(Self::Parquet);
        }
        if bytes.is_empty() {
            return None;
        }
        Some(Self::Ndjson)
    }
}

/// 归档配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColdArchiveConfig {
    /// 对象键前缀（桶内目录），如 `agf-events`。
    pub prefix: String,
    /// 热层保留天数。
    pub hot_days: u32,
    /// 冷层保留天数。
    pub cold_days: u32,
    /// 落地格式。
    pub format: ColdFormat,
    /// 单批最大事件数（超过直接拒绝，由调用方切批）。
    pub max_batch: usize,
}

impl Default for ColdArchiveConfig {
    fn default() -> Self {
        Self {
            prefix: "agf-events".to_string(),
            hot_days: 30,
            cold_days: 365,
            format: ColdFormat::default(),
            max_batch: 10_000,
        }
    }
}

/// 保留策略计划（运维可直接照着做，也可交给生命周期规则自动执行）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPlan {
    /// 热层天数。
    pub hot_days: u32,
    /// 冷层天数。
    pub cold_days: u32,
    /// 热层介质。
    pub hot_backend: String,
    /// 冷层介质。
    pub cold_backend: String,
    /// 热层分区键。
    pub hot_partition: String,
    /// 冷层对象键模板。
    pub cold_key_template: String,
    /// 建议的落地对象存储生命周期规则。
    pub lifecycle_rule: String,
    /// 执行步骤（人读）。
    pub steps: Vec<String>,
    /// 是否支持列式 Parquet（**当前 `true`**：默认格式即 Parquet）。
    pub parquet_supported: bool,
    /// 备注。
    pub note: String,
}

/// 生成保留策略计划。
#[must_use]
pub fn retention_plan(hot_days: u32, cold_days: u32) -> RetentionPlan {
    RetentionPlan {
        hot_days,
        cold_days,
        hot_backend: "clickhouse|timescaledb".to_string(),
        cold_backend: "object-storage(oss|s3|minio)".to_string(),
        hot_partition: "按 (tenant_id, toDate(time)) 分区 + 按 time 建 BRIN/索引".to_string(),
        cold_key_template: "agf-events/dt=YYYY-MM-DD/hour=HH/events-<uuid>.parquet".to_string(),
        lifecycle_rule: format!(
            "对象存储生命周期：{hot_days} 天后由热层转储，{cold_days} 天后转 IA/归档，{cold_days}+ 天过期删除"
        ),
        steps: vec![
            format!("1. 热层保留 {hot_days} 天：ClickHouse/TimescaleDB 按天分区，过期分区 DETACH"),
            format!(
                "2. 归档作业每日扫描 [now-{hot_days}d-1d, now-{hot_days}d) 的事件，调用 ColdArchiver::archive_batch 落对象存储"
            ),
            "3. 归档成功后校验对象 content_hash 与事件条数，再删除热层分区（先归档后删除）".to_string(),
            format!("4. 冷层保留 {cold_days} 天：到期由对象存储生命周期规则删除，并写审计记录"),
            "5. 归档清单写入 `archive_manifest`（对象键 → 时间范围 → 条数 → 哈希），支持按需回灌".to_string(),
        ],
        parquet_supported: true,
        note: "冷归档默认列式 Parquet（SNAPPY，parquet crate 不开 arrow）；\
               Parquet 编码失败自动回落 gzip NDJSON 并 warn（对象键后缀随内容切换，不会名不符实）"
            .to_string(),
    }
}

// ---------------------------------------------------------------------------
// 归档指标
// ---------------------------------------------------------------------------
