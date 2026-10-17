//! 平台任务使用五段 UTC 日历；保留显式 interval 模式用于开发及兼容部署。
use super::*;
use agf_core::{
    cron::Cron,
    error::{DomainError, DomainResult},
    time::Timestamp,
};

pub(crate) enum Timer {
    Calendar(Cron),
    Interval(Duration),
}
pub(crate) fn default_cron(name: &str) -> Option<&'static str> {
    match name {
        "asset-inventory" => Some("0 2 * * *"),
        "log-pull" => Some("*/10 * * * *"),
        "redteam-cruise" => Some("0 3 * * MON"),
        "rule-hot-reload" => Some("*/5 * * * *"),
        "report-generate" => Some("0 7 * * *"),
        "cold-archive" => Some("0 4 1 * *"),
        _ => None,
    }
}
impl Timer {
    pub(crate) fn from_env(name: &str, period: Duration) -> DomainResult<Self> {
        let key = format!("AGF_SCHEDULER_{}_CRON", task_env_prefix(name));
        let custom = optional_env(&[&key]);
        if let Some(source) = custom {
            return Cron::parse(&source).map(Self::Calendar);
        }
        match env_or("AGF_SCHEDULER_TIMING", "calendar").as_str() {
            "calendar" => {
                default_cron(name).map_or(Ok(Self::Interval(period)), |source| Cron::parse(source).map(Self::Calendar))
            }
            "interval" => Ok(Self::Interval(period)),
            _ => Err(DomainError::Config("AGF_SCHEDULER_TIMING 须为 calendar 或 interval".into())),
        }
    }
    pub(crate) fn poll_period(&self) -> Duration {
        match self {
            Self::Calendar(_) => Duration::from_secs(10),
            Self::Interval(period) => *period,
        }
    }
    pub(crate) fn bucket(&self, at: Timestamp) -> Option<i64> {
        match self {
            Self::Calendar(cron) => cron.matches(at).then_some(at.unix_secs() / 60),
            Self::Interval(period) => Some(at.unix_secs() / i64::try_from(period.as_secs()).unwrap_or(5).max(5)),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn calendar_does_not_run_hourly_or_duplicate_seconds_in_a_minute() {
        let timer = Timer::Calendar(Cron::parse(default_cron("asset-inventory").unwrap()).unwrap());
        let at = |hour, minute, second| {
            Timestamp::from_unix_secs(
                chrono::NaiveDate::from_ymd_opt(2026, 9, 20)
                    .unwrap()
                    .and_hms_opt(hour, minute, second)
                    .unwrap()
                    .and_utc()
                    .timestamp(),
            )
            .unwrap()
        };
        assert_eq!(timer.bucket(at(1, 0, 0)), None);
        assert!(timer.bucket(at(2, 0, 0)).is_some());
        assert_eq!(timer.bucket(at(2, 0, 0)), timer.bucket(at(2, 0, 59)));
        assert_eq!(timer.bucket(at(2, 1, 0)), None);
    }
}
