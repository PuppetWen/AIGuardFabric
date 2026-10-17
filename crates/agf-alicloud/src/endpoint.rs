//! 云服务地址来自官方 endpoint 快照；显式覆盖必须是 HTTPS 根地址，本机测试允许 HTTP。
//! VPC 服务接入点与客户创建的 PrivateLink 终端节点不同，不能按域名后缀猜测连通性。

use std::collections::BTreeMap;

use agf_core::cloud::CloudIntegration;
use agf_core::enums::AliCloudService;
use agf_core::error::{DomainError, DomainResult};

/// Endpoint 风格。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EndpointStyle {
    /// 公网域名。
    Public,
    /// PrivateLink / VPC 私网域名。
    Private,
}

impl EndpointStyle {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
        }
    }

    /// 是否私网。
    #[must_use]
    pub const fn is_private(&self) -> bool {
        matches!(self, Self::Private)
    }
}

/// 一个服务的解析结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedEndpoint {
    /// 服务。
    pub service: AliCloudService,
    /// 地域。
    pub region: String,
    /// 主机名（不含 scheme）。
    pub host: String,
    /// URL scheme（`"https"` 默认；指向本机 http 模拟 OpenAPI 时为 `"http"`）。
    ///
    /// **默认行为不变**：没有显式配置时一律 `https`。只有两种情况会变成 `http`：
    /// 1. `endpoints` 覆盖值本身带 `http://` 前缀（客户显式填的就是 http）；
    /// 2. 显式设置 `AGF_ALIYUN_ENDPOINT_SCHEME=http`（本机模拟/联调用）。
    pub scheme: &'static str,
    /// 风格。
    pub style: EndpointStyle,
    /// 来源说明（排障用：`override` / `privatelink` / `public`）。
    pub origin: &'static str,
}

impl ResolvedEndpoint {
    /// 完整 URL。
    #[must_use]
    pub fn url(&self, path: &str) -> String {
        let path = if path.starts_with('/') { path.to_string() } else { format!("/{path}") };
        format!("{}://{}{path}", self.scheme, self.host)
    }

    /// 是否私网。
    #[must_use]
    pub const fn is_private(&self) -> bool {
        self.style.is_private()
    }

    /// 是否明文 http（**只应出现在本机模拟/联调**；生产走 TLS）。
    #[must_use]
    pub fn is_plaintext(&self) -> bool {
        self.scheme == "http"
    }
}

/// 默认 scheme：`AGF_ALIYUN_ENDPOINT_SCHEME` 显式指定时按其取值，否则 `https`。
///
/// 显式开关的意义：本机模拟的 OpenAPI 只能是 `http://127.0.0.1:<port>`，
/// 而 `normalize_host()` 会剥掉 scheme —— 没有这个开关，Rust 侧永远打不到模拟器。
#[must_use]
pub fn default_scheme() -> &'static str {
    match std::env::var("AGF_ALIYUN_ENDPOINT_SCHEME") {
        Ok(v) if v.trim().eq_ignore_ascii_case("http") => "http",
        _ => "https",
    }
}

/// 从覆盖值里识别 scheme（`http://` → `http`；否则用默认值）。
#[must_use]
fn scheme_of(raw: &str, fallback: &'static str) -> &'static str {
    if raw.trim().to_ascii_lowercase().starts_with("http://") {
        "http"
    } else if raw.trim().to_ascii_lowercase().starts_with("https://") {
        "https"
    } else {
        fallback
    }
}

/// 各服务的 endpoint 子域。
///
/// 当前六种服务使用地域接入点，实际支持地域由官方快照或显式覆盖决定。
#[must_use]
pub const fn service_subdomain(service: AliCloudService) -> &'static str {
    match service {
        AliCloudService::Cms => "metrics",
        AliCloudService::Apig => "apig",
        AliCloudService::Mse => "mse",
        AliCloudService::Privatelink => "privatelink",
        AliCloudService::SchedulerX3 => "schedulerx3",
        AliCloudService::AgentTeams => "agentteams",
    }
}

/// 服务是否使用地域化 endpoint。
#[must_use]
pub const fn is_regional_endpoint(_service: AliCloudService) -> bool {
    true
}

/// 配置里用于覆盖 endpoint 的键名（小写下划线风格，与 `settings` 一致）。
#[must_use]
pub const fn service_key(service: AliCloudService) -> &'static str {
    match service {
        AliCloudService::Cms => "cms",
        AliCloudService::Apig => "apig",
        AliCloudService::Mse => "mse",
        AliCloudService::Privatelink => "privatelink",
        AliCloudService::SchedulerX3 => "schedulerx3",
        AliCloudService::AgentTeams => "agentteams",
    }
}

/// 内置地域清单（用于地域合法性提示；**不拒绝**未知地域，只标注）。
pub const KNOWN_REGIONS: &[&str] = &[
    "cn-hangzhou",
    "cn-shanghai",
    "cn-beijing",
    "cn-shenzhen",
    "cn-zhangjiakou",
    "cn-qingdao",
    "cn-chengdu",
    "cn-guangzhou",
    "cn-wulanchabu",
    "cn-hongkong",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-southeast-3",
    "ap-southeast-5",
    "ap-northeast-1",
    "ap-south-1",
    "us-west-1",
    "us-east-1",
    "eu-west-1",
    "eu-central-1",
    "me-east-1",
];

/// 地域是否在内置清单中（不在清单中不视为错误，只提示运维确认）。
#[must_use]
pub fn is_known_region(region: &str) -> bool {
    KNOWN_REGIONS.iter().any(|r| r.eq_ignore_ascii_case(region))
}

/// 校验地域格式（`xx-yyyy-n`，允许 `cn-hangzhou` 这类两段）。
///
/// # Errors
/// 空 / 含非法字符（只允许小写字母、数字、连字符）时返回 [`DomainError::Config`]。
pub fn validate_region(region: &str) -> DomainResult<()> {
    let r = region.trim();
    if r.is_empty() {
        return Err(DomainError::Config("地域（region_id）不能为空".to_string()));
    }
    if r.len() > 64 {
        return Err(DomainError::Config(format!("地域过长: {r}")));
    }
    if !r.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
        return Err(DomainError::Config(format!("地域含非法字符（只允许小写字母/数字/连字符）: {r}")));
    }
    if r.starts_with('-') || r.ends_with('-') || r.contains("--") {
        return Err(DomainError::Config(format!("地域格式非法: {r}")));
    }
    Ok(())
}

/// 解析结果集合（一个集成的全部服务）。
#[derive(Debug, Clone)]
pub struct EndpointTable {
    /// 服务 → 解析结果。
    pub entries: BTreeMap<String, ResolvedEndpoint>,
}

impl EndpointTable {
    /// 取某服务。
    #[must_use]
    pub fn get(&self, service: AliCloudService) -> Option<&ResolvedEndpoint> {
        self.entries.get(service_key(service))
    }

    /// 是否全部走私网（自检页的"公网暴露"断言）。
    #[must_use]
    pub fn all_private(&self) -> bool {
        !self.entries.is_empty() && self.entries.values().all(ResolvedEndpoint::is_private)
    }

    /// 走私网的服务数。
    #[must_use]
    pub fn private_count(&self) -> usize {
        self.entries.values().filter(|e| e.is_private()).count()
    }
}

/// 解析单个服务的 endpoint。
///
/// # Errors
/// 地域非法时返回 [`DomainError::Config`]。
pub fn resolve(
    service: AliCloudService,
    region: &str,
    style: EndpointStyle,
    overrides: &BTreeMap<String, String>,
) -> DomainResult<ResolvedEndpoint> {
    resolve_with_scheme(service, region, style, overrides, default_scheme())
}

/// 同 [`resolve`]，但显式指定默认 scheme（测试与显式配置用）。
///
/// # Errors
/// 地域非法时返回 [`DomainError::Config`]。
pub fn resolve_with_scheme(
    service: AliCloudService,
    region: &str,
    style: EndpointStyle,
    overrides: &BTreeMap<String, String>,
    scheme: &'static str,
) -> DomainResult<ResolvedEndpoint> {
    validate_region(region)?;
    let region = region.trim().to_ascii_lowercase();

    if let Some(raw) = overrides.get(service_key(service)).map(|v| v.trim()).filter(|v| !v.is_empty()) {
        // 覆盖值自带 scheme 时以它为准（`http://127.0.0.1:19443` 必须原样走 http）
        let scheme = scheme_of(raw, scheme);
        let host = validated_host(raw, scheme)?;
        let inferred =
            if host.contains("privatelink") || host.contains("-vpc.") { EndpointStyle::Private } else { style };
        return Ok(ResolvedEndpoint { service, region, host, scheme, style: inferred, origin: "override" });
    }

    let table: serde_json::Value = serde_json::from_str(include_str!("openapi/contracts/endpoints.json"))?;
    let key = if style.is_private() { "vpc" } else { "public" };
    let host = table
        .get(service_key(service))
        .and_then(serde_json::Value::as_array)
        .and_then(|regions| regions.iter().find(|entry| entry["regionId"] == region))
        .and_then(|entry| entry.get(key))
        .and_then(serde_json::Value::as_str)
        .filter(|host| !host.is_empty())
        .ok_or_else(|| {
            DomainError::Config(format!(
                "{} 在 {region} 没有已登记的 {key} 地址，请填写厂商提供的 endpoint",
                service.as_str()
            ))
        })?;
    let host = validated_host(host, scheme)?;
    let origin = if style.is_private() { "privatelink" } else { "public" };
    Ok(ResolvedEndpoint { service, region, host, scheme, style, origin })
}

/// 归一化主机名：去掉 scheme 与结尾斜杠，避免拼出 `https://https://...`。
#[must_use]
pub fn normalize_host(raw: &str) -> String {
    let trimmed = raw.trim();
    let without_scheme =
        trimmed.strip_prefix("https://").or_else(|| trimmed.strip_prefix("http://")).unwrap_or(trimmed);
    without_scheme.trim_end_matches('/').to_string()
}

fn validated_host(raw: &str, scheme: &str) -> DomainResult<String> {
    let raw = if raw.contains("://") { raw.to_string() } else { format!("{scheme}://{raw}") };
    let url = url::Url::parse(&raw).map_err(|_| DomainError::Config("云 API 地址格式无效".into()))?;
    let local = url.host_str().is_some_and(|host| {
        host == "localhost"
            || host.trim_matches(['[', ']']).parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
    });
    if (url.scheme() != "https" && !(url.scheme() == "http" && local))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
        || url.host_str().is_none()
    {
        return Err(DomainError::Config("云 API 地址必须是 HTTPS 服务根地址；HTTP 仅限本机回环测试".into()));
    }
    Ok(url[url::Position::BeforeHost..url::Position::AfterPort].into())
}

/// 由集成配置解析全部服务的 endpoint。
///
/// 风格来自 `settings` 的 `endpoint_style`（由调用方传入），
/// 因为 `CloudIntegration` 本身没有该字段（它由适配器配置承载）。
///
/// # Errors
/// 任一服务地域非法时返回错误（地域对全部服务共享，因此实际只需校验一次）。
pub fn resolve_all(
    integration: &CloudIntegration,
    services: &[AliCloudService],
    style: EndpointStyle,
) -> DomainResult<EndpointTable> {
    let mut entries = BTreeMap::new();
    for service in services {
        let resolved = resolve(*service, &integration.region_id, style, &integration.endpoints)?;
        entries.insert(service_key(*service).to_string(), resolved);
    }
    Ok(EndpointTable { entries })
}

/// 私网化建议：给出把某服务切到 PrivateLink 需要的动作（自检页与文档共用）。
#[must_use]
pub fn privatelink_advice(service: AliCloudService, region: &str) -> String {
    let endpoint = resolve(service, region, EndpointStyle::Private, &BTreeMap::new());
    let host = endpoint.as_ref().map_or_else(|_| "<地域非法>".to_string(), |e| e.host.clone());
    format!(
        "在可达 VPC 中使用 {} 服务接入点 {host}；跨 VPC 场景配置 PrivateLink/路由与 DNS，安全组白名单仅开放所需端口",
        service_key(service)
    )
}

#[cfg(test)]
#[path = "endpoint_tests.rs"]
mod tests;
