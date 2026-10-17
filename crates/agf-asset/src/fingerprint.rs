//! 资产指纹与暴露面评分（纯函数，便于属性测试与离线校验）。
//!
//! ## 指纹的意义
//!
//! 同一个 MCP Server 可能被 10 个终端 Agent 上报、又被网段扫描发现一次、
//! 还被 Git 扫描发现一次。指纹把这些"同一实体"的不同观测收敛成一条台账记录：
//! `fingerprint = f(资产类型, 归属标识)`，其中归属标识按类型取不同维度——
//!
//! | 类型 | 归属标识 |
//! |---|---|
//! | MCP Server | 传输方式 + 命令/URL 的规范化 |
//! | Agent | `flavor + host + os_user` |
//! | 模型端点 | `provider + base_url + model` |
//! | 凭据 | `kind + fingerprint`（不可逆指纹） |
//! | 其他 | 归一化 endpoint 或名称 |
//!
//! 选择"稳定且与安全语义相关"的字段，避免因展示名变化、版本升级导致台账重复。

use agf_core::asset::ExposureInput;
use agf_core::enums::{AssetKind, DataClass, DiscoverySource, LifecycleState, Protocol};
use agf_core::ids::{Id, NS_ASSET, deterministic_id};
use agf_core::mcp::McpTransport;
use agf_core::secret::content_hash;

/// 构造资产指纹字符串（确定性、可读、可排障）。
///
/// # Examples
///
/// ```
/// use agf_asset::fingerprint::asset_fingerprint;
/// use agf_core::enums::AssetKind;
///
/// let fp = asset_fingerprint(AssetKind::McpServer, &["mcp-http", "https://mcp.example.com/mcp"]);
/// assert!(fp.starts_with("mcp-server|"));
/// ```
#[must_use]
pub fn asset_fingerprint(kind: AssetKind, parts: &[&str]) -> String {
    let normalized: Vec<String> = parts.iter().map(|p| normalize_component(p)).filter(|p| !p.is_empty()).collect();
    format!("{}|{}", kind.as_str(), normalized.join("|"))
}

/// 由指纹推导**确定性资产 id**（同一指纹永远映射到同一 UUID，便于跨环境复现）。
#[must_use]
pub fn asset_id_from_fingerprint(fingerprint: &str) -> Id {
    deterministic_id(NS_ASSET, fingerprint)
}

/// 组件归一化：去空白、统一小写、折叠重复分隔符、去尾部斜杠。
#[must_use]
pub fn normalize_component(value: &str) -> String {
    let lowered = value.trim().to_lowercase();
    // 折叠空白与连续斜杠
    let mut out = String::with_capacity(lowered.len());
    let mut prev_slash = false;
    let mut prev_space = false;
    for c in lowered.chars() {
        match c {
            '/' => {
                if !prev_slash {
                    out.push('/');
                }
                prev_slash = true;
                prev_space = false;
            }
            c if c.is_whitespace() => {
                if !prev_space && !out.is_empty() {
                    out.push(' ');
                }
                prev_space = true;
                prev_slash = false;
            }
            _ => {
                out.push(c);
                prev_slash = false;
                prev_space = false;
            }
        }
    }
    out.trim().trim_end_matches('/').to_string()
}

/// 依据端点字符串推断资产类型（被动识别的第一步）。
///
/// 规则保守：只有明确的信号才给出类型，无法判断时返回 [`AssetKind::Other`]，
/// 避免把 MySQL 误判成 MCP Server 造成台账噪声。
#[must_use]
pub fn infer_kind_from_endpoint(endpoint: &str) -> AssetKind {
    let e = endpoint.to_lowercase();
    if e.starts_with("stdio:") || e.contains("mcp") && (e.contains("sse") || e.contains("/mcp")) {
        return AssetKind::McpServer;
    }
    if e.contains("openai") || e.contains("/v1/chat/completions") || e.contains("anthropic") || e.contains("dashscope")
    {
        return AssetKind::ModelEndpoint;
    }
    if e.contains("ollama") || e.contains("vllm") || e.contains(":11434") || e.contains(":8000") {
        return AssetKind::ModelEndpoint;
    }
    if e.contains("vector")
        || e.contains("qdrant")
        || e.contains("milvus")
        || e.contains("weaviate")
        || e.contains(":19530")
    {
        return AssetKind::VectorStore;
    }
    if e.contains("postgres") || e.contains("mysql") || e.contains("redis") || e.contains("mongodb") {
        return AssetKind::DataSource;
    }
    AssetKind::Other
}

/// 依据协议推断资产类型。
#[must_use]
pub fn infer_kind_from_protocol(protocol: Protocol) -> AssetKind {
    match protocol {
        Protocol::McpStdio | Protocol::McpSse | Protocol::McpHttp => AssetKind::McpServer,
        Protocol::OpenAiCompat | Protocol::Anthropic | Protocol::Gemini => AssetKind::ModelEndpoint,
        Protocol::A2a => AssetKind::Agent,
        _ => AssetKind::Other,
    }
}

/// 由资产的已知信息推导暴露面评分输入。
///
/// 判定规则（可解释，控制台直接展示扣分项）：
/// - `publicly_reachable`：端点为公网地址，或监听 `0.0.0.0` / 非私网 IP；
/// - `plaintext`：协议为 MCP SSE/HTTP 但端点不是 https；
/// - `unauthenticated`：MCP 未要求认证；
/// - `write_capable` / `touches_restricted_data`：由调用方传入的能力布尔量决定。
#[must_use]
pub fn exposure_input_from_asset(
    kind: AssetKind,
    protocol: Option<Protocol>,
    endpoint: Option<&str>,
    has_plaintext_secret: bool,
    requires_auth: bool,
    write_capable_tools: u32,
    critical_findings: u32,
    high_findings: u32,
    unreviewed: bool,
) -> ExposureInput {
    let endpoint_str = endpoint.unwrap_or_default();
    let publicly_reachable = is_public_endpoint(endpoint_str);
    let plaintext = protocol.is_some_and(|p| {
        matches!(p, Protocol::McpSse | Protocol::McpHttp | Protocol::Http) && !endpoint_str.starts_with("https://")
    });
    let touches_restricted = has_plaintext_secret
        || matches!(kind, AssetKind::DataSource | AssetKind::VectorStore | AssetKind::RagKb)
        || !matches!(kind, AssetKind::IdePlugin | AssetKind::ComputeNode);
    ExposureInput {
        publicly_reachable,
        unauthenticated: !requires_auth && matches!(kind, AssetKind::McpServer | AssetKind::ModelEndpoint),
        plaintext,
        write_capable: write_capable_tools > 0,
        touches_restricted_data: touches_restricted,
        critical_findings,
        high_findings,
        known_vulnerable_version: false,
        unreviewed,
    }
}

/// 判断端点是否为公网可达（非私网 IP / localhost / unix socket）。
#[must_use]
pub fn is_public_endpoint(endpoint: &str) -> bool {
    let e = endpoint.trim().to_lowercase();
    if e.is_empty() || e.starts_with("stdio:") || e.starts_with("unix:") {
        return false;
    }
    // 监听全部接口 = 暴露面最大
    if e.contains("0.0.0.0") || e.contains("[::]") {
        return true;
    }
    if e.contains("localhost") || e.contains("127.0.0.1") || e.contains("[::1]") {
        return false;
    }
    // 提取 host 部分
    let host = extract_host(&e);
    if host.is_empty() {
        return false;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => !is_private_ip(&ip),
        // 域名：内网后缀视为非公网
        Err(_) => {
            !(host.ends_with(".local")
                || host.ends_with(".internal")
                || host.ends_with(".lan")
                || host.ends_with(".corp")
                || !host.contains('.'))
        }
    }
}

/// 判断 IP 是否属于私网/保留地址。
#[must_use]
pub fn is_private_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified() || v4.is_broadcast()
        }
        std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

/// 从端点字符串里提取 host。
#[must_use]
pub fn extract_host(endpoint: &str) -> String {
    // 非 URL 形式（如 `stdio:npx`、`unix:/tmp/x.sock`）没有 host 概念，返回空串
    let Some((_, after_scheme)) = endpoint.split_once("://") else {
        return String::new();
    };
    let host_port = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    // 去掉 userinfo
    let host_port = host_port.rsplit('@').next().unwrap_or(host_port);
    if let Some(rest) = host_port.strip_prefix('[') {
        // IPv6 字面量
        return rest.split(']').next().unwrap_or("").to_string();
    }
    host_port.split(':').next().unwrap_or("").to_string()
}

/// 由 MCP 配置构造指纹（终端上报与 Git 扫描共用同一规则，保证两条路径归并）。
#[must_use]
pub fn mcp_fingerprint(transport: McpTransport, command: Option<&str>, url: Option<&str>, server_name: &str) -> String {
    let identity = match transport {
        McpTransport::Stdio => command.unwrap_or(server_name).to_string(),
        _ => url.unwrap_or(server_name).to_string(),
    };
    asset_fingerprint(AssetKind::McpServer, &[transport.as_str(), &identity])
}

/// 由 Agent 检测项构造指纹。
#[must_use]
pub fn agent_fingerprint(flavor: &str, host: &str, os_user: Option<&str>) -> String {
    asset_fingerprint(AssetKind::Agent, &[flavor, host, os_user.unwrap_or("-")])
}

/// 由模型端点构造指纹。
#[must_use]
pub fn model_endpoint_fingerprint(provider: &str, base_url: &str, model: &str) -> String {
    asset_fingerprint(AssetKind::ModelEndpoint, &[provider, base_url, model])
}

/// 资产内容哈希（用于基线快照与变更检测）。
///
/// 只包含"安全相关"字段，避免展示名/时间戳变化造成假变更。
#[must_use]
pub fn asset_content_hash(
    kind: AssetKind,
    endpoint: Option<&str>,
    protocol: Option<Protocol>,
    version: Option<&str>,
    vendor: Option<&str>,
    data_class: DataClass,
    lifecycle: LifecycleState,
    dependencies: &[Id],
    discovery_source: DiscoverySource,
) -> String {
    let canonical = serde_json::json!({
        "kind": kind.as_str(),
        "endpoint": endpoint,
        "protocol": protocol.map(|p| p.as_str()),
        "version": version,
        "vendor": vendor,
        "data_class": data_class.as_str(),
        "lifecycle": lifecycle.as_str(),
        "dependencies": dependencies.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "discovery_source": discovery_source.as_str(),
    });
    content_hash(&canonical.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_deterministic_and_type_scoped() {
        let a = asset_fingerprint(AssetKind::McpServer, &["mcp-http", "https://x.example.com/mcp"]);
        let b = asset_fingerprint(AssetKind::McpServer, &["mcp-http", "https://x.example.com/mcp"]);
        let c = asset_fingerprint(AssetKind::Agent, &["mcp-http", "https://x.example.com/mcp"]);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.starts_with("mcp-server|"));
    }

    #[test]
    fn fingerprint_normalizes_noise() {
        let a = asset_fingerprint(AssetKind::ModelEndpoint, &["OpenAI", "https://API.OpenAI.com/v1/", "gpt-4o"]);
        let b = asset_fingerprint(AssetKind::ModelEndpoint, &["openai", "https://api.openai.com/v1", "gpt-4o"]);
        assert_eq!(a, b, "大小写/尾斜杠差异不应产生新资产");
    }

    #[test]
    fn deterministic_id_is_stable() {
        let fp = asset_fingerprint(AssetKind::McpServer, &["stdio", "npx -y filesystem"]);
        let id1 = asset_id_from_fingerprint(&fp);
        let id2 = asset_id_from_fingerprint(&fp);
        assert_eq!(id1, id2);
        assert_ne!(id1, asset_id_from_fingerprint("other"));
    }

    #[test]
    fn normalize_component_collapses_separators() {
        assert_eq!(normalize_component("  HTTP://A//B/  "), "http:/a/b");
        assert_eq!(normalize_component("a   b"), "a b");
        assert_eq!(normalize_component(""), "");
    }

    #[test]
    fn infer_kind_from_endpoint_recognizes_ai_services() {
        assert_eq!(infer_kind_from_endpoint("stdio:claude"), AssetKind::McpServer);
        assert_eq!(infer_kind_from_endpoint("https://api.openai.com/v1"), AssetKind::ModelEndpoint);
        assert_eq!(infer_kind_from_endpoint("http://127.0.0.1:11434"), AssetKind::ModelEndpoint);
        assert_eq!(infer_kind_from_endpoint("http://127.0.0.1:19530"), AssetKind::VectorStore);
        assert_eq!(infer_kind_from_endpoint("postgres://db:5432"), AssetKind::DataSource);
        assert_eq!(infer_kind_from_endpoint("https://intranet.example.com/app"), AssetKind::Other);
    }

    #[test]
    fn infer_kind_from_protocol_cases() {
        assert_eq!(infer_kind_from_protocol(Protocol::McpStdio), AssetKind::McpServer);
        assert_eq!(infer_kind_from_protocol(Protocol::Anthropic), AssetKind::ModelEndpoint);
        assert_eq!(infer_kind_from_protocol(Protocol::A2a), AssetKind::Agent);
        assert_eq!(infer_kind_from_protocol(Protocol::Syslog), AssetKind::Other);
    }

    #[test]
    fn public_endpoint_detection() {
        assert!(is_public_endpoint("http://0.0.0.0:8080"));
        assert!(is_public_endpoint("https://api.example.com/v1"));
        assert!(is_public_endpoint("http://8.8.8.8:80"));
        assert!(!is_public_endpoint("http://127.0.0.1:8080"));
        assert!(!is_public_endpoint("http://localhost:8080"));
        assert!(!is_public_endpoint("http://10.1.2.3:8080"));
        assert!(!is_public_endpoint("http://192.168.1.5:8080"));
        assert!(!is_public_endpoint("http://172.20.0.5:8080"));
        assert!(!is_public_endpoint("stdio:npx"));
        assert!(!is_public_endpoint(""));
        assert!(!is_public_endpoint("http://mcp.internal:8080"));
        assert!(!is_public_endpoint("http://myhost:8080"), "无点号主机名视为内网");
    }

    #[test]
    fn private_ip_detection() {
        use std::net::IpAddr;
        for ip in ["10.0.0.1", "172.16.0.1", "192.168.0.1", "127.0.0.1", "169.254.1.1", "0.0.0.0"] {
            assert!(is_private_ip(&ip.parse::<IpAddr>().unwrap_or_else(|_| unreachable!())), "{ip} 应为私网");
        }
        for ip in ["8.8.8.8", "1.1.1.1", "203.0.113.5"] {
            assert!(!is_private_ip(&ip.parse::<IpAddr>().unwrap_or_else(|_| unreachable!())), "{ip} 应为公网");
        }
        assert!(is_private_ip(&"::1".parse::<IpAddr>().unwrap_or_else(|_| unreachable!())));
        assert!(is_private_ip(&"fd00::1".parse::<IpAddr>().unwrap_or_else(|_| unreachable!())));
    }

    #[test]
    fn host_extraction() {
        assert_eq!(extract_host("https://api.openai.com/v1"), "api.openai.com");
        assert_eq!(extract_host("http://127.0.0.1:11434"), "127.0.0.1");
        assert_eq!(extract_host("http://user:pass@host.example.com:8080/x"), "host.example.com");
        assert_eq!(extract_host("http://[::1]:8080/x"), "::1");
        assert_eq!(extract_host("stdio:npx"), "", "非 URL 端点没有 host");
    }

    #[test]
    fn mcp_fingerprint_stable_across_paths() {
        let from_agent = mcp_fingerprint(McpTransport::Stdio, Some("npx -y @mcp/server-fs"), None, "filesystem");
        let from_git = mcp_fingerprint(McpTransport::Stdio, Some("npx -y @mcp/server-fs"), None, "fs-mcp");
        assert_eq!(from_agent, from_git, "同一命令的不同配置名应归并为同一资产");
        let remote_a = mcp_fingerprint(McpTransport::Http, None, Some("https://mcp.example.com/mcp"), "a");
        let remote_b = mcp_fingerprint(McpTransport::Http, None, Some("https://mcp.example.com/mcp"), "b");
        assert_eq!(remote_a, remote_b);
    }

    #[test]
    fn agent_and_model_fingerprints() {
        let a = agent_fingerprint("claude-code", "host1", Some("alice"));
        assert!(a.starts_with("agent|claude-code|host1|alice"));
        let m = model_endpoint_fingerprint("openai", "https://api.openai.com/v1", "gpt-4o");
        assert!(m.starts_with("model-endpoint|openai|"));
    }

    #[test]
    fn exposure_input_reflects_exposure() {
        let input = exposure_input_from_asset(
            AssetKind::McpServer,
            Some(Protocol::McpHttp),
            Some("http://0.0.0.0:8080"),
            true,
            false,
            3,
            1,
            2,
            true,
        );
        assert!(input.publicly_reachable);
        assert!(input.plaintext);
        assert!(input.unauthenticated);
        assert!(input.write_capable);
        assert!(input.touches_restricted_data);
        assert!(input.unreviewed);
        assert_eq!(input.critical_findings, 1);
        assert_eq!(input.high_findings, 2);

        let internal = exposure_input_from_asset(
            AssetKind::IdePlugin,
            Some(Protocol::McpStdio),
            Some("stdio:npx"),
            false,
            true,
            0,
            0,
            0,
            false,
        );
        assert!(!internal.publicly_reachable);
        assert!(!internal.plaintext);
        assert!(!internal.unauthenticated);

        // 评分函数本身在 agf-core 已测；这里验证组合后的分值合理
        let (score, items) = agf_core::asset::score_exposure(&input);
        assert!(score > 50, "高暴露资产评分应偏高: {score}");
        assert!(!items.is_empty());
    }

    #[test]
    fn content_hash_ignores_display_name() {
        let a = asset_content_hash(
            AssetKind::McpServer,
            Some("https://x/mcp"),
            Some(Protocol::McpHttp),
            Some("1.0"),
            Some("acme"),
            DataClass::Internal,
            LifecycleState::Production,
            &[],
            DiscoverySource::AgentReport,
        );
        let b = asset_content_hash(
            AssetKind::McpServer,
            Some("https://x/mcp"),
            Some(Protocol::McpHttp),
            Some("1.0"),
            Some("acme"),
            DataClass::Internal,
            LifecycleState::Production,
            &[],
            DiscoverySource::AgentReport,
        );
        assert_eq!(a, b);
        let c = asset_content_hash(
            AssetKind::McpServer,
            Some("https://evil/mcp"),
            Some(Protocol::McpHttp),
            Some("1.0"),
            Some("acme"),
            DataClass::Internal,
            LifecycleState::Production,
            &[],
            DiscoverySource::AgentReport,
        );
        assert_ne!(a, c, "端点变化必须改变内容哈希");
    }
}
