//! CEF / LEEF 引擎：头字段切分、扩展键值解析（含转义与空格保留）与厂商键重写。

use super::*;

/// CEF 严重等级（0-10）→ 平台等级。
///
/// 依据 CEF 规范：0-3 低、4-6 中、7-8 高、9-10 很高（映射为 Critical）。
#[must_use]
pub fn cef_severity(raw: &str) -> Option<Severity> {
    let v = raw.trim();
    if let Ok(n) = v.parse::<u32>() {
        return Some(match n {
            0..=3 => Severity::Low,
            4..=6 => Severity::Medium,
            7..=8 => Severity::High,
            _ => Severity::Critical,
        });
    }
    infer_severity(v)
}

pub(super) fn parse_cef(raw: &str) -> Result<BTreeMap<String, Value>, String> {
    let (env, _) = strip_syslog_envelope(raw);
    let mut out = envelope_fields(&env);
    let start = raw.find("CEF:").ok_or_else(|| "未找到 CEF 头".to_string())?;
    let parts = split_cef(&raw[start + 4..]);
    if parts.len() < 7 {
        return Err(format!("CEF 字段数不足（{} < 7）", parts.len()));
    }
    out.insert("cef.version".to_string(), Value::from(parts[0].clone()));
    out.insert("observer.vendor".to_string(), Value::from(parts[1].clone()));
    out.insert("observer.product".to_string(), Value::from(parts[2].clone()));
    out.insert("observer.version".to_string(), Value::from(parts[3].clone()));
    out.insert("rule.id".to_string(), Value::from(parts[4].clone()));
    out.insert("rule.name".to_string(), Value::from(parts[5].clone()));
    out.insert("cef.severity_raw".to_string(), Value::from(parts[6].clone()));
    if let Some(sev) = cef_severity(&parts[6]) {
        out.insert("event.severity".to_string(), Value::from(sev.as_str()));
    }
    if let Some(ext) = parts.get(7) {
        rewrite_vendor_keys(parse_cef_extension(ext), "cef", &mut out);
    }
    Ok(out)
}

/// CEF 头 7 段的分割：头 7 段各自独立，第 8 段（扩展键值对）整体保留，
/// 因为扩展值里允许出现 `|`。
pub(super) fn split_cef(body: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    for c in body.chars() {
        if escaped {
            // CEF 规范：`\|` 与 `\\` 还原为字面量
            current.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' => escaped = true,
            // 只切前 7 个 `|`，其后的内容（扩展段）原样保留
            '|' if parts.len() < 7 => parts.push(std::mem::take(&mut current)),
            _ => current.push(c),
        }
    }
    parts.push(current);
    parts
}

/// CEF 扩展段解析：`key=value` 以空格分隔，但 **value 可以含空格**
/// （value 结束于下一个 ` key=` 出现处），因此不能用普通正则切分。
#[must_use]
pub fn parse_cef_extension(ext: &str) -> Vec<(String, String)> {
    let bytes = ext.as_bytes();
    let mut out: Vec<(String, String)> = Vec::new();
    let mut cur_key: Option<String> = None;
    let mut val_start = 0_usize;
    let mut i = 0_usize;
    while i < bytes.len() {
        let at_boundary = i == 0 || bytes[i - 1].is_ascii_whitespace();
        if at_boundary {
            if let Some((key, after)) = match_key_eq(ext, i) {
                if let Some(prev) = cur_key.take() {
                    out.push((prev, ext[val_start..i].trim().to_string()));
                }
                cur_key = Some(key);
                val_start = after;
                i = after;
                continue;
            }
        }
        i += 1;
    }
    if let Some(prev) = cur_key {
        out.push((prev, ext[val_start..].trim().to_string()));
    }
    out
}

/// 在 `s[from..]` 处尝试匹配 `key=`，返回（键名，`=` 之后的位置）。
fn match_key_eq(s: &str, from: usize) -> Option<(String, usize)> {
    let bytes = s.as_bytes();
    let mut i = from;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_alphanumeric() || c == b'_' {
            i += 1;
        } else {
            break;
        }
    }
    if i == from || i >= bytes.len() || bytes[i] != b'=' {
        return None;
    }
    Some((s[from..i].to_string(), i + 1))
}

pub(super) fn parse_leef(raw: &str) -> Result<BTreeMap<String, Value>, String> {
    let (env, _) = strip_syslog_envelope(raw);
    let mut out = envelope_fields(&env);
    let start = raw.find("LEEF:").ok_or_else(|| "未找到 LEEF 头".to_string())?;
    let body = &raw[start + 5..];
    let mut fields = body.split('|');
    let version = fields.next().unwrap_or_default().trim().to_string();
    let vendor = fields.next().unwrap_or_default().trim().to_string();
    let product = fields.next().unwrap_or_default().trim().to_string();
    let product_version = fields.next().unwrap_or_default().trim().to_string();
    let event_id = fields.next().unwrap_or_default().trim().to_string();
    if version.is_empty() || vendor.is_empty() {
        return Err("LEEF 头部字段缺失".to_string());
    }
    let rest: Vec<&str> = fields.collect();
    out.insert("leef.version".to_string(), Value::from(version.clone()));
    out.insert("observer.vendor".to_string(), Value::from(vendor));
    out.insert("observer.product".to_string(), Value::from(product));
    out.insert("observer.version".to_string(), Value::from(product_version));
    out.insert("rule.id".to_string(), Value::from(event_id));

    // LEEF 2.0：第 6 段是分隔符（如 `^`），第 7 段起是扩展；
    // LEEF 1.0/1.1：第 6 段起就是扩展，分隔符固定为制表符。
    let (delimiter, extension) = if version.starts_with('2') && rest.len() >= 2 {
        let d = rest[0].trim().chars().next().unwrap_or('\t');
        (d, rest[1..].join("|"))
    } else {
        ('\t', rest.join("|"))
    };
    rewrite_vendor_keys(parse_delimited_kv(&extension, delimiter), "leef", &mut out);
    Ok(out)
}

/// 分隔符分隔的键值对（LEEF 扩展段；值中允许空格）。
#[must_use]
pub fn parse_delimited_kv(text: &str, delimiter: char) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for token in text.split(delimiter) {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        if let Some((k, v)) = token.split_once('=') {
            let k = k.trim();
            if !k.is_empty() {
                out.push((k.to_string(), v.trim().trim_matches(|c| c == '"' || c == '\'').to_string()));
            }
        }
    }
    out
}

/// 把厂商键值对改写为 AGF-ECS：标准键改写、动作/类别/等级归一化，
/// 同时保留 `<前缀>.<原键>` 便于排障（模板仍可按原键名映射，如 `cs1`/`ruleId`）。
fn rewrite_vendor_keys(pairs: Vec<(String, String)>, prefix: &str, out: &mut BTreeMap<String, Value>) {
    for (key, value) in pairs {
        out.insert(format!("{prefix}.{key}"), Value::from(value.clone()));
        let lower = key.to_ascii_lowercase();
        // 动作：既给归一值也给原值（审计需要厂商原文）
        if matches!(lower.as_str(), "act" | "action" | "acttype") {
            out.insert("event.action".to_string(), Value::from(normalize_action(&value)));
            out.insert("event.action_raw".to_string(), Value::from(value.clone()));
        }
        // 等级：LEEF 的 sev 与 CEF 头同为 0-10 分档
        if matches!(lower.as_str(), "sev" | "severity") {
            if let Some(s) = cef_severity(&value) {
                out.insert("event.severity".to_string(), Value::from(s.as_str()));
            }
        }
        // LEEF 原始时间（无年份时由模板的 time_format 解析）
        if matches!(lower.as_str(), "devtime" | "devicetime" | "rt" | "receipttime") {
            out.entry("event.time_raw".to_string()).or_insert_with(|| Value::from(value.clone()));
        }
        if let Some((_, ecs)) = CEF_LEEF_KEYS.iter().find(|(k, _)| *k == key) {
            out.insert((*ecs).to_string(), Value::from(value.clone()));
            continue;
        }
        if matches!(lower.as_str(), "username" | "usrname" | "user") {
            out.insert("user.name".to_string(), Value::from(value.clone()));
            continue;
        }
        // 非标准键保留原键名（模板的 `mapping.map` 按它匹配）
        out.insert(key, Value::from(value));
    }
}
