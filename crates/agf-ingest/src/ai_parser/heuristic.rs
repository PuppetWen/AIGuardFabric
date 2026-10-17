//! 离线启发式推断的落地细节：JSON/KV 形状识别、ECS 路径猜测、严重度取值表与字段映射猜测。

use super::*;

/// 抽取 JSON 顶层及一层嵌套键（`rule.level` 形式），保持出现顺序。
pub(super) fn flatten_json_keys(sample: &str) -> Option<Vec<String>> {
    let doc: Value = serde_json::from_str(sample).ok()?;
    let obj = doc.as_object()?;
    let mut keys = Vec::new();
    for (k, v) in obj {
        match v {
            Value::Object(inner) if !inner.is_empty() => {
                for inner_key in inner.keys() {
                    keys.push(format!("{k}.{inner_key}"));
                }
            }
            _ => keys.push(k.clone()),
        }
    }
    Some(keys)
}

/// 抽取 KV 报文的键名。
pub(super) fn kv_keys(sample: &str) -> Vec<String> {
    crate::engine::parse_kv_extension(sample).into_iter().map(|(k, _)| k).collect()
}

/// JSON 形态的 JSONPath 规格（`字段名=$.路径`）。
pub(super) fn json_pattern(keys: &[String]) -> String {
    keys.iter().map(|k| format!("{}=$.{}", sanitize(k), k)).collect::<Vec<_>>().join("\n")
}

pub(super) fn base_def(engine: ParserEngine, pattern: String, vendor: &str) -> ParserDefinition {
    ParserDefinition {
        key: HEURISTIC_KEY.to_string(),
        name: "AI 启发式推断解析器".to_string(),
        vendor: if vendor.is_empty() { "unknown".to_string() } else { vendor.to_string() },
        product: "inferred".to_string(),
        protocols: Vec::new(),
        engine,
        pattern,
        fallback_patterns: Vec::new(),
        mapping: FieldMapping::default(),
        derived: BTreeMap::new(),
        required_fields: Vec::new(),
        version: 1,
        builtin: false,
        ai_inferred: true,
        description: "由日志样本离线启发式推断生成（未接 LLM；人工确认后可固化为正式模板）".to_string(),
        sample_fixture: String::new(),
    }
}

/// KV 形态模板（Mock 提供方与形态识别共用）。
pub(super) fn kv_definition(vendor_hint: Option<&str>) -> ParserDefinition {
    base_def(ParserEngine::Kv, "=".to_string(), vendor_hint.unwrap_or(""))
}

/// 字段名 → 模式中的安全标识符。
pub(super) fn sanitize(name: &str) -> String {
    name.chars().map(|c| if c.is_alphanumeric() || c == '_' || c == '.' { c } else { '_' }).collect()
}

/// 字段名 → AGF-ECS 路径（按语义关键词匹配；无把握时返回 `None`，宁可进 `extra`）。
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn guess_ecs_path(field: &str) -> Option<&'static str> {
    // 点号与下划线视为同一分隔符，便于 `rule.level` 与 `rule_level` 走同一套关键词
    let f = field.to_lowercase().replace('.', "_");
    let has = |keys: &[&str]| keys.iter().any(|k| f.contains(k));
    let dst = has(&["dst", "dest", "destination", "server", "resp"]);

    if has(&["timestamp", "time", "occur"]) || f == "ts" {
        return Some("event.time");
    }
    if has(&["severity", "severityname", "risk", "level", "priority"]) {
        return Some("event.severity");
    }
    if has(&["action", "disposition", "verdict"]) || f == "act" {
        return Some("event.action");
    }
    if has(&["hostname", "host_name", "devname", "computername", "agent_name", "host"]) {
        return Some("host.name");
    }
    if has(&["user", "account", "who", "suser"]) {
        return Some("user.name");
    }
    // 裸的 src/dst（无 ip/port 后缀）也是地址字段：`src=10.0.0.9` / `dst=1.2.3.4`
    // 注意只做**精确名**匹配：`id.resp_p` 这类靠 `dst` 关键字会误判成 IP
    if matches!(f.as_str(), "src" | "source" | "client" | "remote" | "orig" | "caller") {
        return Some("source.ip");
    }
    if matches!(f.as_str(), "dst" | "dest" | "destination" | "server" | "target") {
        return Some("destination.ip");
    }
    if f.contains("ip") || f.ends_with("_addr") || f.ends_with("addr") {
        if dst {
            return Some("destination.ip");
        }
        return Some("source.ip");
    }
    if f == "dpt" || has(&["dstport", "dest_port", "destination_port"]) || (has(&["port"]) && dst) {
        return Some("network.destination_port");
    }
    if f == "spt" || has(&["srcport", "source_port"]) || has(&["port"]) {
        return Some("source.port");
    }
    if f.ends_with("_p") {
        return Some(if dst { "network.destination_port" } else { "source.port" });
    }
    if has(&["proto", "transport"]) {
        return Some("network.transport");
    }
    if has(&["method"]) {
        return Some("http.request.method");
    }
    if f == "status" || f == "code" || has(&["status_code", "http_status"]) {
        return Some("http.response.status_code");
    }
    if has(&["uri", "url", "path"]) {
        return Some("url.path");
    }
    if has(&["fqdn"]) {
        return Some("network.domain");
    }
    if has(&["msg", "message", "detail", "description", "full_log"]) {
        return Some("message");
    }
    if has(&["rule", "signature", "policy", "alertname", "detect"]) {
        return Some("rule.name");
    }
    if has(&["file"]) {
        return Some("file.path");
    }
    if has(&["proc", "process", "command", "cmdline"]) {
        return Some("process.command_line");
    }
    if has(&["malware", "threat"]) {
        return Some("threat.software.name");
    }
    None
}

/// 数值等级 → 平台等级。
///
/// 启发式：0-7 按 syslog 语义；8-15 按 Wazuh `rule.level` 的常见分档（8-9 中、10-12 高、13+ 严重）。
#[must_use]
pub const fn numeric_level_severity(code: u8) -> Severity {
    match code {
        0..=2 => Severity::Critical,
        3 => Severity::High,
        4 => Severity::Medium,
        5 => Severity::Low,
        6..=7 => Severity::Info,
        8..=9 => Severity::Medium,
        10..=12 => Severity::High,
        _ => Severity::Critical,
    }
}

/// 依据等级字段名与样例值猜出取值映射（数字按 [`numeric_level_severity`]，文本按常见枚举）。
#[must_use]
pub fn guess_severity_map(field: &str, sample_value: &str) -> BTreeMap<String, Severity> {
    let mut map = BTreeMap::new();
    let lower = field.to_lowercase();
    let trimmed = sample_value.trim();
    if (lower.contains("level") || lower.contains("severity") || lower.contains("risk"))
        && !trimmed.is_empty()
        && let Ok(code) = trimmed.parse::<u8>()
    {
        map.insert(trimmed.to_string(), numeric_level_severity(code));
        return map;
    }
    for (key, severity) in [
        ("critical", Severity::Critical),
        ("severe", Severity::Critical),
        ("high", Severity::High),
        ("error", Severity::High),
        ("err", Severity::High),
        ("medium", Severity::Medium),
        ("warn", Severity::Medium),
        ("warning", Severity::Medium),
        ("low", Severity::Low),
        ("notice", Severity::Low),
        ("info", Severity::Info),
        ("informational", Severity::Info),
        ("debug", Severity::Info),
    ] {
        map.insert(key.to_string(), severity);
    }
    map
}

/// 从样例中取某字段的值（JSON 走点号路径，KV 走键值对；其他形态返回 `None`）。
pub(super) fn sample_value(sample: &str, key: &str) -> Option<String> {
    if sample.trim_start().starts_with('{') {
        let doc: Value = serde_json::from_str(sample).ok()?;
        let mut cur = &doc;
        for part in key.split('.') {
            cur = cur.get(part)?;
        }
        return match cur {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            Value::Bool(b) => Some(b.to_string()),
            _ => None,
        };
    }
    crate::engine::parse_kv_extension(sample).into_iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

/// 把猜出来的字段路径写进 `mapping`（时间/等级/动作字段同时登记，并按其样例值猜等级映射）。
pub(super) fn apply_field_guesses(def: &mut ParserDefinition, keys: &[String], sample: &str) {
    let mut map = BTreeMap::new();
    let mut severity_field = None;
    let mut action_field = None;
    let mut time_field = None;
    for key in keys {
        let Some(path) = guess_ecs_path(key) else { continue };
        match path {
            // 三者交给 severity_field/action_field/time_field 处理，可同时保留原始值与归一值
            "event.severity" => {
                if severity_field.is_none() {
                    severity_field = Some(key.clone());
                }
            }
            "event.action" => {
                if action_field.is_none() {
                    action_field = Some(key.clone());
                }
            }
            "event.time" => {
                if time_field.is_none() {
                    time_field = Some(key.clone());
                }
            }
            other => {
                map.entry(key.clone()).or_insert_with(|| other.to_string());
            }
        }
    }
    let severity_map = severity_field
        .as_deref()
        .and_then(|field| sample_value(sample, field).map(|value| guess_severity_map(field, &value)))
        .unwrap_or_default();
    def.mapping = FieldMapping {
        map,
        time_field,
        time_format: None,
        severity_field,
        severity_map,
        category_map: BTreeMap::new(),
        action_field,
        defaults: BTreeMap::new(),
    };
}
