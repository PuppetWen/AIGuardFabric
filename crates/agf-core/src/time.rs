//! 时间类型与工具。
//!
//! 平台统一使用 UTC；对外展示时由前端按租户时区渲染。所有落库时间均为 `TIMESTAMPTZ`。

use chrono::{DateTime, Duration, NaiveDate, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};

/// 统一时间戳（UTC，毫秒精度序列化为 RFC 3339）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Timestamp(DateTime<Utc>);

impl Timestamp {
    /// 当前时间。
    #[must_use]
    pub fn now() -> Self {
        Self(Utc::now())
    }

    /// 由 `DateTime<Utc>` 构造。
    #[must_use]
    pub const fn from_datetime(value: DateTime<Utc>) -> Self {
        Self(value)
    }

    /// 由 Unix 秒构造。
    ///
    /// # Errors
    /// 秒数超出 `DateTime` 表示范围时报错。
    pub fn from_unix_secs(secs: i64) -> Result<Self, String> {
        DateTime::from_timestamp(secs, 0).map(Self).ok_or_else(|| format!("时间戳越界: {secs}"))
    }

    /// 由 Unix 毫秒构造。
    ///
    /// # Errors
    /// 毫秒数超出表示范围时报错。
    pub fn from_unix_millis(millis: i64) -> Result<Self, String> {
        let secs = millis.div_euclid(1000);
        let nanos = u32::try_from(millis.rem_euclid(1000) * 1_000_000).map_err(|e| e.to_string())?;
        DateTime::from_timestamp(secs, nanos).map(Self).ok_or_else(|| format!("时间戳越界: {millis}"))
    }

    /// 解析 RFC 3339 字符串。
    ///
    /// # Errors
    /// 格式非法时报错。
    pub fn parse_rfc3339(value: &str) -> Result<Self, String> {
        DateTime::parse_from_rfc3339(value)
            .map(|v| Self(v.with_timezone(&Utc)))
            .map_err(|e| format!("rfc3339 解析失败: {e}"))
    }

    /// 内部 `DateTime<Utc>`。
    #[must_use]
    pub const fn as_datetime(&self) -> DateTime<Utc> {
        self.0
    }

    /// Unix 秒。
    #[must_use]
    pub const fn unix_secs(&self) -> i64 {
        self.0.timestamp()
    }

    /// Unix 毫秒。
    #[must_use]
    pub const fn unix_millis(&self) -> i64 {
        self.0.timestamp_millis()
    }

    /// 加/减时长（秒）。
    #[must_use]
    pub fn offset_secs(&self, secs: i64) -> Self {
        Self(self.0 + Duration::seconds(secs))
    }

    /// 格式化 RFC 3339（毫秒精度，统一 `Z` 后缀）。
    #[must_use]
    pub fn to_rfc3339(&self) -> String {
        self.0.to_rfc3339_opts(SecondsFormat::Millis, true)
    }

    /// 是否早于另一时间。
    #[must_use]
    pub fn is_before(&self, other: &Self) -> bool {
        self.0 < other.0
    }

    /// 距今时长（秒，可能为负）。
    #[must_use]
    pub fn age_secs(&self) -> i64 {
        (Utc::now() - self.0).num_seconds()
    }

    /// 相对另一时间点的差值（秒）：`self - other`，可能为负。
    ///
    /// **强烈建议**在"超时/静默/心跳"判定中使用本方法而不是
    /// `self.age_secs() - other.age_secs()`：后者每次调用都重新取 `now()`，
    /// 两次取值的微小差异会让边界判定变得不确定（差 1 秒），
    /// 在测试里表现为偶发失败。
    #[must_use]
    pub fn since_secs(&self, other: &Self) -> i64 {
        (self.0 - other.0).num_seconds()
    }

    /// 是否晚于/等于另一时间点。
    #[must_use]
    pub fn is_at_or_after(&self, other: &Self) -> bool {
        self.0 >= other.0
    }
}

impl Default for Timestamp {
    fn default() -> Self {
        Self::now()
    }
}

impl std::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_rfc3339())
    }
}

/// 时间窗口（闭开区间 `[from, to)`），关联分析与报表大量使用。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeRange {
    /// 起始（含）。
    pub from: Timestamp,
    /// 结束（不含）。
    pub to: Timestamp,
}

impl TimeRange {
    /// 构造窗口；若 `from >= to` 则自动交换，避免上层产生空窗口。
    #[must_use]
    pub fn new(from: Timestamp, to: Timestamp) -> Self {
        if from <= to { Self { from, to } } else { Self { from: to, to: from } }
    }

    /// 最近 `secs` 秒到现在。
    #[must_use]
    pub fn last_secs(secs: i64) -> Self {
        let now = Timestamp::now();
        Self { from: now.offset_secs(-secs), to: now }
    }

    /// 最近 24 小时。
    #[must_use]
    pub fn last_day() -> Self {
        Self::last_secs(86_400)
    }

    /// 窗口时长（秒）。
    #[must_use]
    pub fn duration_secs(&self) -> i64 {
        (self.to.as_datetime() - self.from.as_datetime()).num_seconds()
    }

    /// 是否包含某时间点。
    #[must_use]
    pub fn contains(&self, at: &Timestamp) -> bool {
        *at >= self.from && *at < self.to
    }
}

/// 日期（UTC，报表按天聚合使用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Date(NaiveDate);

impl Date {
    /// 今天（UTC）。
    #[must_use]
    pub fn today() -> Self {
        Self(Utc::now().date_naive())
    }

    /// 解析 `YYYY-MM-DD`。
    ///
    /// # Errors
    /// 格式非法时报错。
    pub fn parse(value: &str) -> Result<Self, String> {
        NaiveDate::parse_from_str(value, "%Y-%m-%d").map(Self).map_err(|e| format!("日期解析失败: {e}"))
    }

    /// 内部 `NaiveDate`。
    #[must_use]
    pub const fn as_naive(&self) -> NaiveDate {
        self.0
    }

    /// `YYYY-MM-DD`。
    #[must_use]
    pub fn to_iso(&self) -> String {
        self.0.format("%Y-%m-%d").to_string()
    }
}

impl std::fmt::Display for Date {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_iso())
    }
}

/// 把 `humantime` 风格时长（`30s`、`5m`、`2h`、`7d`）解析为秒。
///
/// # Errors
/// 无法识别的格式返回错误描述。
pub fn parse_duration_secs(value: &str) -> Result<i64, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("时长不能为空".to_string());
    }
    let (num, unit) = trimmed.split_at(trimmed.len().saturating_sub(1));
    let n: i64 = num.trim().parse().map_err(|_| format!("时长数值非法: {value}"))?;
    let mult = match unit {
        "s" | "S" => 1,
        "m" | "M" => 60,
        "h" | "H" => 3_600,
        "d" | "D" => 86_400,
        "w" | "W" => 604_800,
        _ => return Err(format!("未知时长单位: {value}")),
    };
    n.checked_mul(mult).ok_or_else(|| format!("时长溢出: {value}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_roundtrip_millis() {
        let ts = Timestamp::now();
        let parsed = Timestamp::from_unix_millis(ts.unix_millis());
        assert_eq!(parsed.map(|v| v.unix_millis()), Ok(ts.unix_millis()));
    }

    #[test]
    fn timestamp_rfc3339_ends_with_z() {
        assert!(Timestamp::now().to_rfc3339().ends_with('Z'));
    }

    #[test]
    fn time_range_swaps_when_inverted() {
        let a = Timestamp::now();
        let b = a.offset_secs(-60);
        let r = TimeRange::new(a, b);
        assert_eq!(r.from, b);
        assert_eq!(r.to, a);
        assert_eq!(r.duration_secs(), 60);
        assert!(r.contains(&b));
        assert!(!r.contains(&a));
    }

    #[test]
    fn duration_parsing() {
        assert_eq!(parse_duration_secs("30s"), Ok(30));
        assert_eq!(parse_duration_secs("5m"), Ok(300));
        assert_eq!(parse_duration_secs("2h"), Ok(7_200));
        assert_eq!(parse_duration_secs("7d"), Ok(604_800));
        assert!(parse_duration_secs("7y").is_err());
        assert!(parse_duration_secs("").is_err());
    }

    #[test]
    fn date_roundtrip() {
        let d = Date::parse("2026-03-01");
        assert!(d.is_ok());
        assert_eq!(d.map(|v| v.to_iso()), Ok("2026-03-01".to_string()));
        assert!(Date::parse("2026/03/01").is_err());
    }
}
