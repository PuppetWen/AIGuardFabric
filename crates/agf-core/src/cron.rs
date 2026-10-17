//! Five-field UTC cron. Numeric lists, ranges, steps and month/weekday names.
use crate::error::{DomainError, DomainResult};
use chrono::{Datelike, Timelike};

/// Five-field UTC cron expression, including named months and weekdays.
#[derive(Debug)]
pub struct Cron {
    fields: Vec<Vec<u32>>,
    day_any: bool,
    weekday_any: bool,
}

impl Cron {
    /// Validate a five-field cron expression.
    pub fn parse(source: &str) -> DomainResult<Self> {
        let parts: Vec<_> = source.split_whitespace().collect();
        if parts.len() != 5 {
            return Err(invalid());
        }
        let bounds = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 7)];
        let fields = parts
            .iter()
            .enumerate()
            .map(|(index, part)| {
                let (min, max) = bounds[index];
                parse_field(part, min, max, index)
            })
            .collect::<DomainResult<Vec<_>>>()?;
        Ok(Self { fields, day_any: parts[2].starts_with('*'), weekday_any: parts[4].starts_with('*') })
    }

    /// Whether this UTC instant belongs to the configured calendar minute.
    pub fn matches(&self, at: crate::time::Timestamp) -> bool {
        let date = at.as_datetime();
        let day = self.fields[2].contains(&date.day());
        let weekday = self.fields[4].contains(&date.weekday().num_days_from_sunday());
        let days = if self.day_any || self.weekday_any { day && weekday } else { day || weekday };
        self.fields[0].contains(&date.minute())
            && self.fields[1].contains(&date.hour())
            && self.fields[3].contains(&date.month())
            && days
    }
}

fn invalid() -> DomainError {
    DomainError::Validation("cron 须为 5 段 UTC 时间（分 时 日 月 周），数值必须在合法范围，步长不能为零".into())
}

fn number(text: &str, field: usize) -> DomainResult<u32> {
    let names: &[&str] = match field {
        3 => &["JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"],
        4 => &["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"],
        _ => &[],
    };
    if let Some(index) = names.iter().position(|name| text.eq_ignore_ascii_case(name)) {
        return Ok(u32::try_from(index).map_err(|_| invalid())? + u32::from(field == 3));
    }
    text.parse().map_err(|_| invalid())
}

fn parse_field(source: &str, min: u32, max: u32, field: usize) -> DomainResult<Vec<u32>> {
    let mut values = Vec::new();
    for item in source.split(',') {
        let (span, step) = item.split_once('/').map_or(Ok((item, 1)), |(span, step)| {
            Ok::<_, DomainError>((span, step.parse::<u32>().map_err(|_| invalid())?))
        })?;
        if step == 0 || step > max + 1 {
            return Err(invalid());
        }
        let (start, end) = if span == "*" {
            (min, max)
        } else if let Some((start, end)) = span.split_once('-') {
            (number(start, field)?, number(end, field)?)
        } else {
            let start = number(span, field)?;
            (start, if item.contains('/') { max } else { start })
        };
        if start < min || end > max || start > end {
            return Err(invalid());
        }
        for value in start..=end {
            if (value - start) % step == 0 {
                values.push(if field == 4 { value % 7 } else { value });
            }
        }
    }
    values.sort_unstable();
    values.dedup();
    if values.is_empty() {
        return Err(invalid());
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::Timestamp;
    #[test]
    fn rejects_invalid_ranges_and_accepts_names_steps_and_day_or() -> Result<(), Box<dyn std::error::Error>> {
        for raw in ["60 * * * *", "* 24 * * *", "*/0 * * * *", "* * 0 * *", "* * * foo *", "* * * * 8"] {
            assert!(Cron::parse(raw).is_err(), "{raw}");
        }
        let sunday = Timestamp::parse_rfc3339("2026-09-20T08:15:00Z")?;
        assert!(Cron::parse("*/15 8 * SEP SUN")?.matches(sunday));
        assert!(Cron::parse("15 8 1 * SUN")?.matches(sunday));
        assert!(!Cron::parse("15 8 * * MON-FRI")?.matches(sunday));
        Ok(())
    }
}
