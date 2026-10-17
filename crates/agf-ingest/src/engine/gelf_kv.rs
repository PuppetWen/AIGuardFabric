//! GELF / CSV / KV 引擎：JSON 载荷、分隔符表头映射与多种键值写法解析。

use super::*;

pub(super) fn parse_gelf(raw: &str) -> Result<BTreeMap<String, Value>, String> {
    // GELF 的 TCP 形态是 NUL 分隔的 JSON
    let cleaned = raw.trim_matches(|c: char| c == '\0' || c == '\n' || c == '\r');
    let value: Value = serde_json::from_str(cleaned).map_err(|e| format!("GELF 载荷不是合法 JSON: {e}"))?;
    let Some(obj) = value.as_object() else {
        return Err("GELF 载荷不是 JSON 对象".to_string());
    };
    let mut out = BTreeMap::new();
    if let Some(h) = obj.get("host").and_then(Value::as_str) {
        out.insert("host.name".to_string(), Value::from(h.to_string()));
    }
    if let Some(s) = obj.get("short_message").and_then(Value::as_str) {
        out.insert("message".to_string(), Value::from(s.to_string()));
    }
    if let Some(l) = obj.get("level").and_then(Value::as_i64) {
        out.insert("gelf.level".to_string(), Value::from(l));
    }
    if let Some(ts) = obj.get("timestamp").and_then(Value::as_f64) {
        if let Some(t) = parse_unix_number(ts, false) {
            out.insert("event.time".to_string(), Value::from(t.to_rfc3339()));
        }
    }
    for (k, v) in obj {
        if !matches!(k.as_str(), "host" | "short_message" | "level" | "timestamp" | "version") {
            out.insert(format!("gelf.{k}"), v.clone());
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// CSV / KV
// ---------------------------------------------------------------------------

/// CSV/TSV：按表头或未加引号的数据分隔符识别格式，表头按索引对齐。
pub(super) fn parse_csv(pattern: &str, raw: &str) -> Result<BTreeMap<String, Value>, String> {
    let headers: Vec<&str> = pattern.split([',', '\t']).map(str::trim).filter(|s| !s.is_empty()).collect();
    if headers.is_empty() {
        return Err("CSV 表头为空".to_string());
    }
    let (env, body) = strip_syslog_envelope(raw);
    let mut out = envelope_fields(&env);
    let line = body
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .ok_or_else(|| "CSV 无数据行".to_string())?;
    let delimiter = csv_delimiter(pattern, line);
    let values = csv_values(line, delimiter)?;
    for (i, h) in headers.iter().enumerate() {
        if let Some(v) = values.get(i) {
            out.insert((*h).to_string(), Value::from(v.clone()));
        }
    }
    Ok(out)
}

/// Quoted commas or tabs are data and must not change the record's delimiter.
fn csv_delimiter(pattern: &str, line: &str) -> char {
    if pattern.contains('\t') {
        return '\t';
    }
    let (mut commas, mut tabs, mut quoted) = (false, false, false);
    let mut chars = line.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '"' {
            if quoted && chars.peek() == Some(&'"') {
                chars.next();
            } else {
                quoted = !quoted;
            }
        } else if !quoted {
            commas |= ch == ',';
            tabs |= ch == '\t';
        }
    }
    if tabs && !commas { '\t' } else { ',' }
}

/// Read one CSV/TSV record, preserving quoted separators and doubled quotes.
/// Unterminated quotes or text after a closing quote reject the record.
fn csv_values(line: &str, delimiter: char) -> Result<Vec<String>, String> {
    let mut values = Vec::new();
    let mut field = String::new();
    let mut chars = line.chars().peekable();
    let (mut quoted, mut closed) = (false, false);
    while let Some(ch) = chars.next() {
        if quoted {
            if ch != '"' {
                field.push(ch);
            } else if chars.peek() == Some(&'"') {
                chars.next();
                field.push('"');
            } else {
                quoted = false;
                closed = true;
            }
        } else if ch == delimiter {
            values.push(if closed { field.clone() } else { field.trim().to_owned() });
            field.clear();
            closed = false;
        } else if closed {
            if !ch.is_whitespace() {
                return Err("CSV closing quote must be followed by a delimiter".to_owned());
            }
        } else if ch == '"' {
            if !field.trim().is_empty() {
                return Err("CSV quote must start a field".to_owned());
            }
            field.clear();
            quoted = true;
        } else {
            field.push(ch);
        }
    }
    if quoted {
        return Err("CSV quoted field is not terminated".to_owned());
    }
    values.push(if closed { field } else { field.trim().to_owned() });
    Ok(values)
}

/// KV 引擎：通用键值对（`k=v` / `k:"v"` / `k='v'`）+ syslog 信封。
pub(super) fn parse_kv_engine(raw: &str) -> BTreeMap<String, Value> {
    let (env, body) = strip_syslog_envelope(raw);
    let mut out = envelope_fields(&env);
    for (k, v) in parse_kv_extension(&body) {
        out.insert(k, Value::from(v));
    }
    out
}

/// 键值对解析：支持 `k=v`、`k:"v"`、`k="v"`、`k='v'`，以及空格/逗号/分号/制表符分隔。
#[must_use]
pub fn parse_kv_extension(raw: &str) -> Vec<(String, String)> {
    parse_kv_delims(raw, &[' ', ',', ';', '\t'])
}

/// 指定分隔符的键值对解析（通用路径；值以空白/逗号/分号为界）。
#[must_use]
pub fn parse_kv_delims(raw: &str, delimiters: &[char]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let pattern = r#"(?x)
        (?P<key>[A-Za-z_][A-Za-z0-9_.\-]*)
        \s*[:=]\s*
        (?P<val>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s,;]+)
    "#;
    if let Ok(re) = Regex::new(pattern) {
        for caps in re.captures_iter(raw) {
            let key = caps.name("key").map_or("", |m| m.as_str());
            let val = caps.name("val").map_or("", |m| m.as_str());
            if key.is_empty() {
                continue;
            }
            out.push((key.to_string(), val.trim_matches(|c| c == '"' || c == '\'').to_string()));
        }
    }
    // 兜底：正则一行都没抓到（例如键以数字开头）时按分隔符切
    if out.is_empty() {
        for token in raw.split(|c| delimiters.contains(&c)) {
            if let Some((k, v)) = token.split_once('=') {
                let k = k.trim();
                if !k.is_empty() {
                    out.push((k.to_string(), v.trim().trim_matches('"').to_string()));
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// 时间解析
// ---------------------------------------------------------------------------
