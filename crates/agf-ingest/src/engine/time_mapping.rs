//! 时间字段解析（多种格式 / Unix 秒与毫秒）与字段映射落地：severity / category / action / time 归一与默认值。

use super::*;

/// 解析时间字段（多格式回退）。
///
/// 支持 `format_hint` 为 `unix` / `unix_millis`（Unix 秒/毫秒，支持小数秒）、
/// strftime 风格格式，以及自动识别的 RFC3339、`YYYY-MM-DD HH:MM:SS`、`YYYY-MM-DD`、
/// syslog 的 `Mmm dd HH:MM:SS`（补当前年份）、Unix 秒/毫秒。
#[must_use]
pub fn parse_time_value(value: &str, format_hint: Option<&str>) -> Option<Timestamp> {
    let v = value.trim();
    if v.is_empty() {
        return None;
    }
    if let Some(fmt) = format_hint {
        match fmt.trim().to_ascii_lowercase().as_str() {
            "unix" | "epoch" | "unix_secs" | "unix_seconds" => return parse_unix_text(v, false),
            "unix_millis" | "unix_ms" | "epoch_millis" => return parse_unix_text(v, true),
            _ => {}
        }
        if let Some(t) = parse_with_format(v, fmt) {
            return Some(t);
        }
    }
    if let Ok(t) = Timestamp::parse_rfc3339(v) {
        return Some(t);
    }
    for fmt in [
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S%.f%z",
        "%Y-%m-%dT%H:%M:%S%.f%:z",
        "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d",
    ] {
        if let Some(t) = parse_with_format(v, fmt) {
            return Some(t);
        }
    }
    // syslog 风格 `Mmm dd HH:MM:SS`（补当前年份；RFC3164 本身不带年份）
    let with_year = format!("{} {v}", chrono::Utc::now().format("%Y"));
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(&with_year, "%Y %b %e %H:%M:%S") {
        return Some(Timestamp::from_datetime(naive.and_utc()));
    }
    parse_unix_text(v, false).or_else(|| parse_unix_text(v, true))
}

/// 按单个 strftime 格式尝试解析（日期时间 / 纯日期两种）。
fn parse_with_format(value: &str, fmt: &str) -> Option<Timestamp> {
    if let Ok(dt) = chrono::DateTime::parse_from_str(value, fmt) {
        return Some(Timestamp::from_datetime(dt.with_timezone(&chrono::Utc)));
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(value, fmt) {
        return Some(Timestamp::from_datetime(naive.and_utc()));
    }
    if let Ok(date) = chrono::NaiveDate::parse_from_str(value, fmt) {
        let naive = date.and_hms_opt(0, 0, 0)?;
        return Some(Timestamp::from_datetime(naive.and_utc()));
    }
    None
}

/// Unix 时间戳文本 → [`Timestamp`]（仅接受 >= 1e9 的取值，避免把端口当时间）。
fn parse_unix_text(value: &str, millis: bool) -> Option<Timestamp> {
    let n: f64 = value.trim().parse().ok()?;
    let seconds = if millis { n / 1000.0 } else { n };
    if seconds < 1.0e9 {
        return None;
    }
    parse_unix_number(seconds, false)
}

/// Unix 秒（可含小数）→ [`Timestamp`]。
pub(super) fn parse_unix_number(seconds: f64, millis: bool) -> Option<Timestamp> {
    let total = if millis { seconds / 1000.0 } else { seconds };
    if !total.is_finite() || total < 1.0e9 {
        return None;
    }
    let whole = total.trunc();
    #[allow(clippy::cast_possible_truncation)]
    let secs = whole as i64;
    let frac = total - whole;
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let nanos = (frac * 1.0e9).round() as u32;
    chrono::DateTime::from_timestamp(secs, nanos.min(999_999_999)).map(Timestamp::from_datetime)
}

// ---------------------------------------------------------------------------
// 字段映射
// ---------------------------------------------------------------------------

/// 把扁平字段按 [`FieldMapping`] 归一化到 ECS 路径。
///
/// 取的是**引用**：`flat` 同时是"必需字段校验"（[`required_fields_satisfied`]）与
/// "样本打分"（[`sample_match_score`]）的依据，调用方（[`parse_core`]）仍需持有它，
/// 因此这里不夺走所有权（内部本来也是逐字段克隆，改成引用不增加任何拷贝）。
///
/// 未命中映射表但本身已是 ECS 路径的键（如引擎直出的 `source.ip`）原样保留在
/// [`ParseOutcome::fields`]；其余进 [`ParseOutcome::extra`]（由 `normalize` 决定
/// 是否落入 `Event::extra`，绝不丢弃）。
#[must_use]
pub fn apply_mapping(def: &ParserDefinition, flat: &BTreeMap<String, Value>) -> ParseOutcome {
    let m: &FieldMapping = &def.mapping;
    let mut fields: BTreeMap<String, Value> = BTreeMap::new();
    let mut extra: BTreeMap<String, Value> = BTreeMap::new();
    let mut action_raw: Option<String> = None;

    for (k, v) in flat {
        if let Some(target) = m.map.get(k) {
            apply_target(&mut fields, target, v, m);
            continue;
        }
        if m.severity_field.as_deref() == Some(k.as_str()) {
            fields.insert("event.severity".to_string(), map_severity(m, v));
            continue;
        }
        if m.action_field.as_deref() == Some(k.as_str()) {
            if let Some(raw) = value_to_text(v) {
                action_raw = Some(raw);
            }
            fields.insert("event.action".to_string(), map_action(v));
            continue;
        }
        if m.time_field.as_deref() == Some(k.as_str()) {
            fields.insert("event.time".to_string(), map_time(v, m.time_format.as_deref()));
            continue;
        }
        if is_ecs_path(k) {
            fields.entry(k.clone()).or_insert_with(|| v.clone());
            continue;
        }
        extra.insert(k.clone(), v.clone());
    }

    if let Some(raw) = &action_raw {
        fields.entry("event.action_raw".to_string()).or_insert_with(|| Value::from(raw.clone()));
    }

    // defaults 是模板作者的显式声明，优先级高于后面按 category_map 推断出的类别
    for (path, value) in &m.defaults {
        fields.entry(path.clone()).or_insert_with(|| value.clone());
    }

    // category_map：依次按 event.category_raw → rule.id → 动作原值 查找
    if !m.category_map.is_empty() {
        let candidates = [
            fields.get("event.category_raw").and_then(value_to_text),
            fields.get("rule.id").and_then(value_to_text),
            action_raw,
        ];
        for candidate in candidates.into_iter().flatten() {
            if let Some(category) = m.category_map.get(&candidate) {
                fields.entry("event.category".to_string()).or_insert_with(|| Value::from(category.clone()));
                break;
            }
        }
    }

    let mut fields = fields;
    let derived_errors = crate::cel::apply_derived(def, &mut fields, &extra);
    let mut outcome = ParseOutcome::hit(def.key.clone(), fields);
    outcome.extra = extra;
    outcome.derived_errors = derived_errors;
    outcome
}

/// 应用单条映射目标（兼容 `severity` 与 `event.severity` 两种写法）。
fn apply_target(fields: &mut BTreeMap<String, Value>, target: &str, value: &Value, m: &FieldMapping) {
    match target {
        "severity" | "event.severity" => {
            fields.insert("event.severity".to_string(), map_severity(m, value));
        }
        "category" | "event.category" => {
            fields.insert("event.category".to_string(), map_category(m, value));
        }
        "action" | "event.action" => {
            fields.insert("event.action".to_string(), map_action(value));
        }
        "time" | "event.time" => {
            fields.insert("event.time".to_string(), map_time(value, m.time_format.as_deref()));
        }
        other => {
            fields.insert(other.to_string(), value.clone());
        }
    }
}

fn map_severity(mapping: &FieldMapping, value: &Value) -> Value {
    let raw = value_to_text(value).unwrap_or_else(|| value.to_string());
    if let Some(mapped) = mapping.severity_map.get(&raw) {
        return Value::from(mapped.as_str());
    }
    if let Some(s) = infer_severity(&raw) {
        return Value::from(s.as_str());
    }
    value.clone()
}

fn map_category(mapping: &FieldMapping, value: &Value) -> Value {
    let raw = value_to_text(value).unwrap_or_else(|| value.to_string());
    if let Some(mapped) = mapping.category_map.get(&raw) {
        return Value::from(mapped.clone());
    }
    value.clone()
}

fn map_action(value: &Value) -> Value {
    let raw = value_to_text(value).unwrap_or_else(|| value.to_string());
    Value::from(normalize_action(&raw))
}

fn map_time(value: &Value, format_hint: Option<&str>) -> Value {
    let Some(text) = value_to_text(value) else {
        return value.clone();
    };
    parse_time_value(&text, format_hint).map_or_else(|| value.clone(), |t| Value::from(t.to_rfc3339()))
}

/// 值 → 文本（数字/布尔按字面量，数组/对象返回 `None`）。
#[must_use]
pub fn value_to_text(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// 依据厂商原始等级字符串推断平台等级。
#[must_use]
pub fn infer_severity(raw: &str) -> Option<Severity> {
    let v = raw.trim().to_ascii_lowercase();
    let s = match v.as_str() {
        "critical" | "fatal" | "emergency" | "emerg" | "alert" | "紧急" | "严重" => Severity::Critical,
        "high" | "error" | "err" | "高" | "错误" => Severity::High,
        "medium" | "warning" | "warn" | "中" | "警告" => Severity::Medium,
        "low" | "notice" | "低" | "注意" => Severity::Low,
        "info" | "information" | "informational" | "debug" | "信息" => Severity::Info,
        _ => return None,
    };
    Some(s)
}
