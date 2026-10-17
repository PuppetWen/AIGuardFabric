//! 模型端点配置扫描（Windows/Linux/macOS 共用实现）。
//!
//! 扫描来源：MCP/IDE 配置文件 + 进程环境变量（`*_BASE_URL` / `*_API_BASE` / `*_ENDPOINT`）。
//! 只上报**地址与厂商标识推断**，不读取也不上报任何密钥明文。
//!
//! ## 降级行为
//!
//! | 情况 | 行为 |
//! |---|---|
//! | 配置中的 URL 不是模型端点（如文档链接） | 按主机名白名单过滤，不上报 |
//! | 同名端点重复出现 | 按 `(来源文件, 键名, URL)` 去重 |
//! | 文件不可读/超大 | 记 warning 跳过 |
//! | Linux/macOS | 读取对应用户目录；Linux 容器已验证，macOS 待真机验证 |
//! | 地址含用户信息、查询串或片段 | 上报前去除；仅保留是否含敏感配置的布尔值 |

use std::path::Path;

use serde_json::Value;

use super::{CollectContext, CollectorOutcome, read_text, scan_text_secrets, url_safety::safe_report_url};
use crate::collector::looks_like_plaintext_secret;
use crate::payload::DetectedModelEndpoint;

/// 采集器名。
pub const NAME: &str = "model-endpoints";

/// 端点键名（不区分大小写匹配）。
pub const ENDPOINT_KEYS: [&str; 8] = [
    "base_url",
    "baseurl",
    "base_uri",
    "api_base",
    "apibase",
    "openai_base_url",
    "azure_openai_endpoint",
    "model_endpoint",
];

/// 已知模型厂商主机名 → 标识。
pub const PROVIDER_HOSTS: [(&str, &str); 12] = [
    ("api.openai.com", "openai"),
    ("openai.azure.com", "azure-openai"),
    ("api.anthropic.com", "anthropic"),
    ("generativelanguage.googleapis.com", "gemini"),
    ("dashscope.aliyuncs.com", "dashscope"),
    ("open.bigmodel.cn", "zhipu"),
    ("api.moonshot.cn", "moonshot"),
    ("api.deepseek.com", "deepseek"),
    ("api.minimax.chat", "minimax"),
    ("ark.cn-beijing.volces.com", "ark"),
    ("api.hunyuan.cloud.tencent.com", "hunyuan"),
    ("localhost", "local"),
];

/// 由 URL 推断厂商标识。
#[must_use]
pub fn provider_hint(url: &str) -> Option<String> {
    let parsed = reqwest::Url::parse(url).ok()?;
    let host = parsed.host_str()?.to_ascii_lowercase();
    for (host, provider) in PROVIDER_HOSTS {
        if parsed.host_str().is_some_and(|name| {
            name.eq_ignore_ascii_case(host)
                || (host != "localhost" && name.to_ascii_lowercase().ends_with(&format!(".{host}")))
        }) {
            return Some(provider.to_string());
        }
    }
    if parsed.port() == Some(11434) || host.contains("ollama") {
        return Some("ollama".to_string());
    }
    if host.contains("vllm") || (parsed.port() == Some(8000) && parsed.path().starts_with("/v1")) {
        return Some("vllm".to_string());
    }
    None
}

/// 判断键名是否像模型端点键。
#[must_use]
pub fn is_endpoint_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    ENDPOINT_KEYS.contains(&lower.as_str())
        || lower.ends_with("_base")
        || (lower.contains("url") && (lower.contains("base") || lower.contains("api")))
}

/// 判断字符串是否像模型端点 URL。
#[must_use]
pub fn looks_like_endpoint(url: &str) -> bool {
    let Some((safe, _)) = safe_report_url(url) else { return false };
    let Ok(parsed) = reqwest::Url::parse(&safe) else { return false };
    let path = parsed.path().to_ascii_lowercase();
    provider_hint(&safe).is_some()
        || path.contains("/v1")
        || path.contains("/api/")
        || path.contains("chat/completions")
}

/// 递归扫描 JSON，提取端点（纯函数）。
#[must_use]
pub fn scan_value(source_file: &str, value: &Value) -> Vec<DetectedModelEndpoint> {
    let mut out = Vec::new();
    walk(source_file, value, &mut out, 0);
    out.sort_by(|a, b| {
        (a.source_file.as_str(), a.key.as_str(), a.url.as_str()).cmp(&(
            b.source_file.as_str(),
            b.key.as_str(),
            b.url.as_str(),
        ))
    });
    out.dedup_by(|a, b| a.source_file == b.source_file && a.key == b.key && a.url == b.url);
    out
}

fn walk(source_file: &str, value: &Value, out: &mut Vec<DetectedModelEndpoint>, depth: usize) {
    if depth > 8 {
        return;
    }
    match value {
        Value::Object(map) => {
            let has_plaintext_key =
                map.iter().any(|(k, v)| v.as_str().is_some_and(|s| looks_like_plaintext_secret(k, s)));
            for (key, item) in map {
                if is_endpoint_key(key) {
                    if let Some(url) = item.as_str() {
                        if looks_like_endpoint(url) {
                            let Some((safe_url, had_private_parts)) = safe_report_url(url) else {
                                continue;
                            };
                            out.push(DetectedModelEndpoint {
                                source_file: source_file.to_string(),
                                key: key.clone(),
                                url: safe_url,
                                provider_hint: provider_hint(url),
                                has_plaintext_key: has_plaintext_key || had_private_parts,
                            });
                        }
                    }
                }
                walk(source_file, item, out, depth + 1);
            }
        }
        Value::Array(items) => {
            for item in items {
                walk(source_file, item, out, depth + 1);
            }
        }
        _ => {}
    }
}

/// 扫描环境变量中的端点（`*_BASE_URL` / `*_API_BASE` / `*_ENDPOINT`）。
#[must_use]
pub fn scan_pairs(pairs: &[(String, String)]) -> Vec<DetectedModelEndpoint> {
    let mut out = Vec::new();
    for (key, value) in pairs {
        if !is_endpoint_key(key) && !key.to_ascii_uppercase().ends_with("_ENDPOINT") {
            continue;
        }
        if !looks_like_endpoint(value) {
            continue;
        }
        let Some((safe_url, had_private_parts)) = safe_report_url(value) else { continue };
        out.push(DetectedModelEndpoint {
            source_file: format!("env:{key}"),
            key: key.clone(),
            url: safe_url,
            provider_hint: provider_hint(value),
            has_plaintext_key: had_private_parts,
        });
    }
    out.sort_by(|a, b| (a.source_file.as_str(), a.url.as_str()).cmp(&(b.source_file.as_str(), b.url.as_str())));
    out.dedup_by(|a, b| a.source_file == b.source_file && a.url == b.url);
    out
}

/// 候选配置文件（与 MCP 采集重叠，这里只关心端点字段）。
#[must_use]
pub fn candidate_paths(home: &Path) -> Vec<std::path::PathBuf> {
    crate::collector::mcp_config::candidate_paths(home)
}

/// 执行采集。
#[must_use]
pub fn collect(ctx: &CollectContext) -> CollectorOutcome<DetectedModelEndpoint> {
    if crate::platform::current() == crate::platform::HostPlatform::Other {
        return CollectorOutcome::unsupported(NAME, "模型端点采集不支持当前平台".to_string());
    }
    let started = std::time::Instant::now();
    let mut outcome = CollectorOutcome {
        name: NAME,
        items: Vec::new(),
        credential_hits: Vec::new(),
        scope: vec!["env:process".to_string()],
        warnings: Vec::new(),
        level: crate::platform::SupportLevel::Implemented,
        elapsed_ms: 0,
        error: None,
    };
    let env_pairs: Vec<(String, String)> = std::env::vars()
        .filter(|(k, _)| {
            let upper = k.to_ascii_uppercase();
            upper.contains("URL") || upper.contains("ENDPOINT") || upper.contains("API_BASE")
        })
        .collect();
    outcome.items.extend(scan_pairs(&env_pairs));

    let mut paths = candidate_paths(&ctx.home);
    paths.extend(crate::collector::project_paths::candidate_paths(&ctx.project_roots));
    paths.sort();
    paths.dedup();
    for path in paths {
        if !path.is_file() {
            continue;
        }
        let label = path.display().to_string();
        outcome.scope.push(label.clone());
        let text = match read_text(&path, ctx.max_file_bytes) {
            Ok(text) => text,
            Err(reason) => {
                outcome.warnings.push(format!("{label}: {reason}"));
                continue;
            }
        };
        match serde_json::from_str::<Value>(&text) {
            Ok(value) => outcome.items.extend(scan_value(&label, &value)),
            Err(error) => outcome.warnings.push(format!("{label}: 非法 JSON: {error}")),
        }
        outcome.credential_hits.extend(scan_text_secrets(&label, &text));
    }
    outcome.items.sort_by(|a, b| {
        (a.source_file.as_str(), a.key.as_str(), a.url.as_str()).cmp(&(
            b.source_file.as_str(),
            b.key.as_str(),
            b.url.as_str(),
        ))
    });
    outcome.items.dedup_by(|a, b| a.source_file == b.source_file && a.key == b.key && a.url == b.url);
    outcome.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn provider_hint_covers_known_hosts() {
        assert_eq!(provider_hint("https://api.openai.com/v1"), Some("openai".to_string()));
        assert_eq!(provider_hint("https://dashscope.aliyuncs.com/compatible-mode/v1"), Some("dashscope".to_string()));
        assert_eq!(provider_hint("http://localhost:11434/v1"), Some("local".to_string()));
        assert_eq!(provider_hint("https://internal-gw.example.invalid/v1"), None);
        assert_eq!(provider_hint("https://api.openai.com.evil.invalid/v1"), None);
    }

    #[test]
    fn endpoint_url_filter_rejects_docs_and_plain_hosts() {
        assert!(looks_like_endpoint("https://api.openai.com/v1"));
        assert!(looks_like_endpoint("http://127.0.0.1:8000/v1"));
        assert!(!looks_like_endpoint("https://example.invalid/docs"));
        assert!(!looks_like_endpoint("ftp://api.openai.com/v1"));
        assert!(!looks_like_endpoint(""));
    }

    #[test]
    fn scans_nested_json_config() {
        let value = json!({
            "providers": {
                "openai": {"base_url": "https://api.openai.com/v1", "api_key": "sk-abcdefghijklmnopqrstuvwxyz012345"},
                "local": {"baseUrl": "http://localhost:8000/v1"}
            },
            "notes": {"homepage": "https://example.invalid/docs"}
        });
        let endpoints = scan_value("~/.continue/config.json", &value);
        assert_eq!(endpoints.len(), 2, "只应命中端点键: {endpoints:?}");
        let openai = endpoints.iter().find(|e| e.key == "base_url").expect("openai 端点");
        assert_eq!(openai.provider_hint.as_deref(), Some("openai"));
        assert!(openai.has_plaintext_key, "同处发现明文 key 必须标记");
        let local = endpoints.iter().find(|e| e.key == "baseUrl").expect("local 端点");
        assert_eq!(local.provider_hint.as_deref(), Some("local"));
        assert!(!local.has_plaintext_key);
    }

    #[test]
    fn scans_environment_style_pairs() {
        let pairs: Vec<(String, String)> = vec![
            ("OPENAI_BASE_URL".into(), "https://api.openai.com/v1".into()),
            ("ANTHROPIC_API_BASE".into(), "https://api.anthropic.com".into()),
            ("PATH".into(), "/usr/bin".into()),
            ("RANDOM_URL".into(), "https://example.invalid/x".into()),
        ];
        let endpoints = scan_pairs(&pairs);
        assert_eq!(endpoints.len(), 2, "{endpoints:?}");
        assert!(endpoints.iter().any(|e| e.source_file == "env:OPENAI_BASE_URL"));
        assert!(endpoints.iter().any(|e| e.provider_hint.as_deref() == Some("anthropic")));
    }

    #[test]
    fn endpoint_inventory_never_copies_url_credentials() {
        let raw = "https://sample-user:sample-password@api.openai.com/v1?token=sample-secret#private";
        let endpoints = scan_pairs(&[("OPENAI_BASE_URL".into(), raw.into())]);
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].url, "https://api.openai.com/v1");
        assert!(endpoints[0].has_plaintext_key);
        let nested = scan_value("config.json", &json!({"base_url": raw}));
        assert_eq!(nested[0].url, "https://api.openai.com/v1");
        assert!(nested[0].has_plaintext_key);
    }

    #[test]
    fn collect_uses_temp_home_samples() {
        let dir = tempfile::tempdir().expect("临时目录");
        let cursor = dir.path().join(".cursor");
        std::fs::create_dir_all(&cursor).expect("建目录");
        std::fs::write(
            cursor.join("mcp.json"),
            r#"{"mcpServers":{"gw":{"command":"npx","env":{"OPENAI_BASE_URL":"https://api.openai.com/v1","OPENAI_API_KEY":"sk-abcdefghijklmnopqrstuvwxyz012345"}}}}"#,
        )
        .expect("写样本");
        let ctx = CollectContext::for_current_user().with_home(dir.path());
        let outcome = collect(&ctx);
        assert!(outcome.is_ok());
        assert!(outcome.items.iter().any(|e| e.url.contains("api.openai.com")), "{:?}", outcome.items);
        assert!(!outcome.credential_hits.is_empty(), "同文件中的明文 key 必须被记录");
        assert!(outcome.scope.iter().any(|s| s.contains("mcp.json")));
    }

    #[test]
    fn explicit_project_root_exposes_model_endpoint_without_scanning_other_projects() {
        let base = tempfile::tempdir().expect("临时目录");
        let project = base.path().join("project");
        std::fs::create_dir_all(&project).expect("工作区");
        std::fs::write(project.join(".mcp.json"), r#"{"base_url":"https://api.openai.com/v1"}"#).expect("配置样本");
        let ctx = CollectContext::for_current_user()
            .with_home(base.path().join("empty-home"))
            .with_project_roots(vec![project]);
        let outcome = collect(&ctx);
        assert!(outcome.is_ok());
        assert_eq!(outcome.items.len(), 1);
        assert_eq!(outcome.items[0].provider_hint.as_deref(), Some("openai"));
    }

    #[test]
    fn endpoint_key_detection() {
        assert!(is_endpoint_key("BASE_URL"));
        assert!(is_endpoint_key("openai_base_url"));
        assert!(is_endpoint_key("apiBase"));
        assert!(!is_endpoint_key("description"));
        assert!(!is_endpoint_key("homepage"));
    }
}
