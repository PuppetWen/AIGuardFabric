//! 纯逻辑：`k=v` 日志行 → AGF-ECS 风格 JSON。**本模块没有任何 `unsafe`。**

use serde_json::Map;
use serde_json::Value;
use serde_json::json;

use crate::PLUGIN_VERSION;

/// 解析 `k=v k2="quoted value" k3=42` 形态的键值对。
///
/// * 值可用双引号包裹，引号内支持 `\"` 与 `\\` 转义，并可含空格；
/// * 没有 `=` 的孤立 token 会被丢弃；
/// * 键为空（`=v`）的片段也会被丢弃。
#[must_use]
pub fn parse_kv(line: &str) -> Vec<(String, String)> {
    let chars: Vec<char> = line.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;

    while i < chars.len() {
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }
        if i >= chars.len() {
            break;
        }

        let key_start = i;
        while i < chars.len() && !chars[i].is_whitespace() && chars[i] != '=' {
            i += 1;
        }
        if i >= chars.len() || chars[i] != '=' {
            // 没有 '='：丢掉这个 token，继续找下一个。
            while i < chars.len() && !chars[i].is_whitespace() {
                i += 1;
            }
            continue;
        }
        let key: String = chars[key_start..i].iter().collect();
        i += 1; // 跳过 '='

        let mut value = String::new();
        if i < chars.len() && chars[i] == '"' {
            i += 1;
            while i < chars.len() {
                match chars[i] {
                    '\\' if i + 1 < chars.len() => {
                        value.push(chars[i + 1]);
                        i += 2;
                    }
                    '"' => {
                        i += 1;
                        break;
                    }
                    other => {
                        value.push(other);
                        i += 1;
                    }
                }
            }
        } else {
            while i < chars.len() && !chars[i].is_whitespace() {
                value.push(chars[i]);
                i += 1;
            }
        }

        if !key.is_empty() {
            out.push((key, value));
        }
    }
    out
}

/// 把 `k=v` 日志行归一化成 AGF-ECS 风格 JSON 文本。
///
/// 字段映射（键大小写不敏感）：
///
/// | 输入键 | 输出位置 |
/// |---|---|
/// | `ts` / `timestamp` / `@timestamp` | `@timestamp` |
/// | `src` / `src_ip` / `source_ip` | `source.ip` |
/// | `spt` / `src_port` / `source_port` | `source.port`（数字，非数字落到 `labels`） |
/// | `dst` / `dst_ip` / `destination_ip` | `destination.ip` |
/// | `dpt` / `dst_port` / `destination_port` | `destination.port`（数字） |
/// | `action` | `event.action` |
/// | `rule` | `event.rule` |
/// | `sev` / `severity` | `event.severity`（数字） |
/// | `msg` / `message` | `message` |
/// | 其它 | `labels.<原键>` |
///
/// 认不出任何已知字段时返回 `Err`（宿主会把它转成插件的业务失败，而不是静默产出空对象）。
pub fn normalize_line(line: &str) -> Result<String, String> {
    let fields = parse_kv(line);
    if fields.is_empty() {
        return Err("输入里没有任何 k=v 字段".to_string());
    }

    let mut root = Map::new();
    let mut source = Map::new();
    let mut destination = Map::new();
    let mut event = Map::new();
    let mut labels = Map::new();
    let mut recognized = 0_u32;

    for (key, value) in &fields {
        let lowered = key.to_ascii_lowercase();
        match lowered.as_str() {
            "ts" | "timestamp" | "@timestamp" => {
                root.insert("@timestamp".to_string(), Value::String(value.clone()));
                recognized += 1;
            }
            "src" | "src_ip" | "source_ip" => {
                source.insert("ip".to_string(), Value::String(value.clone()));
                recognized += 1;
            }
            "spt" | "src_port" | "source_port" => {
                recognized += 1;
                insert_port(&mut source, value, key, &mut labels);
            }
            "dst" | "dst_ip" | "destination_ip" => {
                destination.insert("ip".to_string(), Value::String(value.clone()));
                recognized += 1;
            }
            "dpt" | "dst_port" | "destination_port" => {
                recognized += 1;
                insert_port(&mut destination, value, key, &mut labels);
            }
            "action" => {
                event.insert("action".to_string(), Value::String(value.clone()));
                recognized += 1;
            }
            "rule" => {
                event.insert("rule".to_string(), Value::String(value.clone()));
                recognized += 1;
            }
            "sev" | "severity" => {
                recognized += 1;
                if let Ok(number) = value.parse::<i64>() {
                    event.insert("severity".to_string(), json!(number));
                } else {
                    labels.insert(key.clone(), Value::String(value.clone()));
                }
            }
            "msg" | "message" => {
                root.insert("message".to_string(), Value::String(value.clone()));
                recognized += 1;
            }
            _ => {
                labels.insert(key.clone(), Value::String(value.clone()));
            }
        }
    }

    if recognized == 0 {
        return Err(format!(
            "没有识别出任何已知字段（已知：ts/timestamp、src、spt、dst、dpt、action、rule、sev、msg）；收到 {} 个字段",
            fields.len()
        ));
    }

    if !source.is_empty() {
        root.insert("source".to_string(), Value::Object(source));
    }
    if !destination.is_empty() {
        root.insert("destination".to_string(), Value::Object(destination));
    }
    if !event.is_empty() {
        root.insert("event".to_string(), Value::Object(event));
    }
    if !labels.is_empty() {
        root.insert("labels".to_string(), Value::Object(labels));
    }
    root.insert(
        "agf".to_string(),
        json!({
            "plugin": crate::PLUGIN_NAME,
            "plugin_version": PLUGIN_VERSION,
            "parser": "kv-access-log",
            "recognized_fields": recognized,
            "timestamp_missing": !root.contains_key("@timestamp"),
        }),
    );

    serde_json::to_string(&Value::Object(root)).map_err(|err| format!("JSON 序列化失败：{err}"))
}

/// 端口字段：能解析成 `u16` 就写数字，否则原样落到 `labels`（不丢数据、不猜）。
fn insert_port(target: &mut Map<String, Value>, value: &str, raw_key: &str, labels: &mut Map<String, Value>) {
    if let Ok(port) = value.parse::<u16>() {
        target.insert("port".to_string(), json!(port));
    } else {
        labels.insert(raw_key.to_string(), Value::String(value.to_string()));
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn parses_quoted_and_bare_values() {
        let fields = parse_kv(r#"ts=2026-02-21T10:00:00Z src=10.1.2.3 msg="SQL injection \"attempt\" now" dpt=443"#);
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[2].0, "msg");
        assert_eq!(fields[2].1, r#"SQL injection "attempt" now"#);
        assert_eq!(fields[3], ("dpt".to_string(), "443".to_string()));
    }

    #[test]
    fn drops_tokens_without_equals() {
        let fields = parse_kv("junk ts=1 morejunk k=2");
        assert_eq!(fields, vec![("ts".to_string(), "1".to_string()), ("k".to_string(), "2".to_string())]);
    }

    #[test]
    fn normalizes_known_fields_into_ecs_shape() {
        let json = normalize_line("ts=2026-02-21T10:00:00Z src=10.1.2.3 dst=10.9.9.9 dpt=443 action=block rule=WAF-1001 msg=\"SQL injection attempt\"")
            .unwrap();
        let value: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["@timestamp"], "2026-02-21T10:00:00Z");
        assert_eq!(value["source"]["ip"], "10.1.2.3");
        assert_eq!(value["destination"]["ip"], "10.9.9.9");
        assert_eq!(value["destination"]["port"], 443);
        assert_eq!(value["event"]["action"], "block");
        assert_eq!(value["event"]["rule"], "WAF-1001");
        assert_eq!(value["message"], "SQL injection attempt");
        assert_eq!(value["agf"]["timestamp_missing"], false);
    }

    #[test]
    fn unknown_fields_go_to_labels_and_bad_ports_are_kept() {
        let json = normalize_line("src=10.0.0.1 dpt=not-a-port tenant=acme").unwrap();
        let value: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["labels"]["dpt"], "not-a-port");
        assert_eq!(value["labels"]["tenant"], "acme");
        assert!(value["destination"].is_null());
    }

    #[test]
    fn unrecognized_input_is_a_business_error() {
        let err = normalize_line("foo=1 bar=2").unwrap_err();
        assert!(err.contains("没有识别出任何已知字段"));
        assert!(normalize_line("   ").is_err());
    }

    #[test]
    fn missing_timestamp_is_flagged_not_faked() {
        let json = normalize_line("src=10.0.0.1").unwrap();
        let value: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["agf"]["timestamp_missing"], true);
        assert!(value["@timestamp"].is_null());
    }
}
