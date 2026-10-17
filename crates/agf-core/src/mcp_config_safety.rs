//! MCP 配置发现的共享脱敏规则。终端与 Git 扫描只上报定位信息，不存原始凭据。

use serde_json::{Map, Value};
use url::Url;

/// 判断配置键名是否可能承载凭据。
#[must_use]
pub fn is_sensitive_key(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    ["API_KEY", "APIKEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "ACCESS_KEY", "PRIVATE_KEY", "CREDENTIAL"]
        .iter()
        .any(|needle| upper.contains(needle))
}

/// 判断配置值是否是需要提示的明文凭据；短值和占位符不触发。
#[must_use]
pub fn looks_like_plaintext_secret(key: &str, value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() < 16 || crate::secret::is_placeholder(trimmed) {
        return false;
    }
    is_sensitive_key(key) || !crate::secret::scan_credentials(trimmed, &[]).is_empty()
}

/// 只保留可定位的 HTTP 地址；去除用户信息、查询串及片段，路径含已知密钥时拒绝上报。
/// 第二个返回值表示已发现疑似私密字段，而不是普通查询参数。
#[must_use]
pub fn safe_report_url(raw: &str) -> Option<(String, bool)> {
    let mut parsed = Url::parse(raw.trim()).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return None;
    }
    let query_secret = parsed.query_pairs().any(|(key, value)| {
        let normalized = key.to_ascii_lowercase().replace('-', "_");
        let sensitive_name = is_sensitive_key(&normalized)
            || matches!(normalized.as_str(), "key" | "sig" | "signature" | "auth" | "authorization" | "code");
        sensitive_name && !value.is_empty() && !crate::secret::is_placeholder(&value)
    });
    let fragment_secret = parsed.fragment().is_some_and(|part| !crate::secret::scan_credentials(part, &[]).is_empty());
    let private = !parsed.username().is_empty() || parsed.password().is_some() || query_secret || fragment_secret;
    if !crate::secret::scan_credentials(parsed.path(), &[]).is_empty() {
        return None;
    }
    parsed.set_username("").ok()?;
    parsed.set_password(None).ok()?;
    parsed.set_query(None);
    parsed.set_fragment(None);
    Some((parsed.to_string(), private))
}

/// 遮盖命令参数中的密钥选项、认证头和 URL 私密字段。
#[must_use]
pub fn redact_arguments(args: Vec<String>) -> (Vec<String>, bool) {
    let mut sanitized = Vec::with_capacity(args.len());
    let mut redacted = false;
    let mut redact_next = false;
    for arg in args {
        if redact_next {
            sanitized.push("<redacted>".to_string());
            redacted = true;
            redact_next = false;
            continue;
        }
        let key = arg.split_once('=').map_or(arg.as_str(), |(left, _)| left);
        let normalized = key.trim_start_matches('-').replace('-', "_").to_ascii_lowercase();
        if is_sensitive_key(&normalized) || matches!(normalized.as_str(), "h" | "header" | "authorization") {
            if arg.contains('=') {
                sanitized.push(format!("{key}=<redacted>"));
            } else {
                sanitized.push(arg);
                redact_next = true;
            }
            redacted = true;
            continue;
        }
        if let Some((flag, value)) = arg.split_once('=') {
            if let Some((safe, had_private_parts)) = safe_report_url(value) {
                sanitized.push(format!("{flag}={safe}"));
                redacted |= had_private_parts;
                continue;
            }
            if value.starts_with("http://") || value.starts_with("https://") {
                sanitized.push(format!("{flag}=<redacted>"));
                redacted = true;
                continue;
            }
        }
        if let Some((safe, had_private_parts)) = safe_report_url(&arg) {
            sanitized.push(safe);
            redacted |= had_private_parts;
            continue;
        }
        if arg.starts_with("http://")
            || arg.starts_with("https://")
            || arg.to_ascii_lowercase().starts_with("authorization:")
            || !crate::secret::scan_credentials(&arg, &[]).is_empty()
        {
            sanitized.push("<redacted>".to_string());
            redacted = true;
            continue;
        }
        sanitized.push(arg);
    }
    (sanitized, redacted)
}

/// 保留普通可执行文件路径，遮盖内嵌命令行凭据或认证头的命令字符串。
#[must_use]
pub fn safe_report_command(raw: &str) -> (String, bool) {
    let lower = raw.to_ascii_lowercase();
    let sensitive = raw.contains('=')
        || lower.contains("authorization")
        || lower.contains("bearer ")
        || lower.contains("--api-key")
        || lower.contains("--token")
        || !crate::secret::scan_credentials(raw, &[]).is_empty();
    (if sensitive { "<redacted-command>" } else { raw }.to_string(), sensitive)
}

fn auth_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase().replace('-', "_");
    matches!(
        normalized.as_str(),
        "authorization"
            | "proxy_authorization"
            | "cookie"
            | "x_api_key"
            | "api_key"
            | "access_token"
            | "x_auth_token"
            | "token"
            | "key"
            | "sig"
            | "signature"
            | "auth"
            | "code"
    )
}

/// 判断 HTTP MCP 配置是否显式提供认证信息，绝不返回认证值。
#[must_use]
pub fn has_auth_settings(entry: &Map<String, Value>) -> bool {
    if entry.get("headers").and_then(Value::as_object).is_some_and(|headers| {
        headers.iter().any(|(key, value)| auth_key(key) && value.as_str().is_some_and(|text| !text.trim().is_empty()))
    }) {
        return true;
    }
    entry.get("url").and_then(Value::as_str).is_some_and(url_has_auth_settings)
}

/// 判断 HTTP URL 中是否配置了用户信息或常见认证查询参数。
#[must_use]
pub fn url_has_auth_settings(raw: &str) -> bool {
    Url::parse(raw).ok().is_some_and(|url| {
        !url.username().is_empty()
            || url.password().is_some()
            || url.query_pairs().any(|(key, value)| auth_key(&key) && !value.is_empty())
    })
}

/// 在接入和入库前净化旧版或不可信 Agent 的 MCP 发现项。
pub fn sanitize_detected_mcp(mcp: &mut crate::agent::DetectedMcp) {
    let auth_from_url = mcp.url.as_deref().is_some_and(url_has_auth_settings);
    let raw_url = mcp.url.take();
    let (safe_url, url_sensitive) = raw_url
        .as_deref()
        .and_then(safe_report_url)
        .map_or((None, raw_url.is_some()), |(safe, sensitive)| (Some(safe), sensitive));
    mcp.url = safe_url;
    let (safe_command, command_sensitive) = mcp
        .command
        .take()
        .map(|raw| safe_report_command(&raw))
        .map_or((None, false), |(safe, sensitive)| (Some(safe), sensitive));
    mcp.command = safe_command;
    let (safe_args, args_sensitive) = redact_arguments(std::mem::take(&mut mcp.args));
    mcp.args = safe_args;
    let had_invalid_env_key = mcp.env_keys.iter().any(|key| {
        key.len() > 128 || key.is_empty() || !key.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    });
    mcp.env_keys.retain(|key| {
        !key.is_empty() && key.len() <= 128 && key.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    });
    mcp.has_plaintext_secret |= url_sensitive || command_sensitive || args_sensitive || had_invalid_env_key;
    mcp.auth_configured |= auth_from_url;
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn safe_url_and_arguments_drop_private_components() {
        assert_eq!(
            safe_report_url("https://user:password@example.invalid/mcp?token=private#fragment"),
            Some(("https://example.invalid/mcp".to_string(), true))
        );
        assert_eq!(
            safe_report_url("https://example.invalid/v1?api-version=2026-01-01"),
            Some(("https://example.invalid/v1".to_string(), false))
        );
        let (args, sensitive) = redact_arguments(vec!["--api-key".into(), "private-key".into()]);
        assert_eq!(args, ["--api-key", "<redacted>"]);
        assert!(sensitive);
        assert_eq!(safe_report_command("node").0, "node");
        assert_eq!(safe_report_command("node --token=private").0, "<redacted-command>");
    }

    #[test]
    fn auth_settings_ignore_non_auth_metadata() {
        let auth = json!({"headers": {"Authorization": "Bearer private"}});
        assert!(auth.as_object().is_some_and(has_auth_settings));
        let benign = json!({"url": "https://example.invalid/mcp?api-version=2026#token=private"});
        assert!(!benign.as_object().is_some_and(has_auth_settings));
    }
}
