//! 采集器上行的 **mTLS 证书身份**：头部契约、主体映射（证书 → 角色/租户）与门禁开关。
//!
//! ## 证书从哪里来
//!
//! `agf-server` 自身**不终结 TLS**（与既有部署口径一致：TLS/mTLS 由入口网关承担，
//! 见 `docs/deployment.md`）。网关校验客户端证书后把证书透传给应用，本模块消费两种头部：
//!
//! | 头部 | 含义 | 谁写入 |
//! |---|---|---|
//! | `X-SSL-Client-Verify` | `SUCCESS` = 网关已校验通过 | 入口网关（nginx/Envoy 标准约定） |
//! | `X-SSL-Client-Cert` | 客户端证书 **PEM**（可 percent-encoded） | 入口网关 |
//! | `X-AGF-Client-Cert-Der` | 客户端证书 **DER** 的 base64 | 本仓库自带的 `agf-mtls-terminator` |
//!
//! **这两条头部本身不可信**：只应在"应用只接受来自网关的流量"的网络拓扑下启用，
//! 因此默认关闭，必须显式打开（[`ENV_TRUST_PROXY`]）。字节级解析见 [`super::agent_cert`]。
//!
//! ## 与既有 RBAC 的关系（**不默认全权**）
//!
//! 证书主体（CN/O/OU/SAN）经 [`PrincipalMap`] 显式映射到 **角色 + 租户**，
//! 再走与 Bearer/JWT 完全相同的 `Principal::require` 权限判定
//! （本端点要求 `sources:write`）。**没有映射 ⇒ 403 拒绝**，不会退化成"有证书就放行"。
//!
//! 映射表（[`ENV_MAP`]；**`;` 分隔**多条规则，`subject-pattern=role@tenant-uuid`）：
//!
//! ```text
//! AGF_AGENT_MTLS_MAP=CN=agf-collector*=tenant-admin@11111111-1111-1111-1111-111111111111;*.corp.example=soc-analyst
//! AGF_AGENT_MTLS_DEFAULT_ROLE=viewer       # 提供默认**无权限**角色（可选）
//! AGF_AGENT_MTLS_DEFAULT_TENANT=<uuid>     # 默认租户（可选）
//! AGF_AGENT_MTLS_REQUIRED=1                # 只接受证书身份（Bearer 一律 401）
//! ```
//!
//! **为什么用 `;` 而不是 `,`**：X.500 subject 本身就是逗号分隔的（`CN=a,OU=b,O=c`），
//! 用逗号做条目分隔就再也写不出"整串 subject"的规则。
//!
//! 模式匹配：`*` 通配（`CN=agf-collector*` / `*.corp.example`），大小写不敏感；
//! **无 `*` 即全等**；逐条匹配**命中即停**，命中顺序 = 配置顺序（把更具体的规则写前面）。
//!
//! 解析细节：每条规则按**最后一个 `=`** 切分（subject 自己就带 `=`），右侧再按 `@` 切出
//! `role@tenant`；格式不完整的条目**被忽略**（不会静默放行：忽略只会让映射更严）。

use std::collections::BTreeMap;

use agf_core::ids::TenantId;

/// 入口网关写入的"证书校验结果"头部（nginx `$ssl_client_verify`）。
pub const HEADER_CLIENT_VERIFY: &str = "x-ssl-client-verify";
/// 入口网关写入的客户端证书 PEM 头部（nginx `$ssl_client_escaped_cert`）。
pub const HEADER_CLIENT_CERT: &str = "x-ssl-client-cert";
/// 客户端证书 **DER** 的 base64 头部（本仓库自带的 `agf-mtls-terminator` 用这种形态，
/// 因为 DER 是握手产物、无需再编码成 PEM）。
pub const HEADER_CLIENT_CERT_DER: &str = "x-agf-client-cert-der";
/// 是否信任上述代理头部（默认**关闭**）。
pub const ENV_TRUST_PROXY: &str = "AGF_AGENT_MTLS_TRUST_PROXY";
/// 主体映射表。
pub const ENV_MAP: &str = "AGF_AGENT_MTLS_MAP";
/// 映射未命中时的默认角色（可选；缺省 = 不映射）。
pub const ENV_DEFAULT_ROLE: &str = "AGF_AGENT_MTLS_DEFAULT_ROLE";
/// 默认租户（可选）。
pub const ENV_DEFAULT_TENANT: &str = "AGF_AGENT_MTLS_DEFAULT_TENANT";
/// 是否强制只接受证书身份（Bearer/API Key 一律拒绝）。
pub const ENV_REQUIRED: &str = "AGF_AGENT_MTLS_REQUIRED";

/// 证书身份信息（**由证书本身派生**，不采信任何"自述"字段）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CertInfo {
    /// RFC 4514 形式的 subject（如 `CN=agf-collector-01,OU=collectors,O=agf`）。
    pub subject: String,
    /// CN（可空）。
    pub common_name: Option<String>,
    /// O（可空）。
    pub organization: Option<String>,
    /// OU 列表（证书里可能有多个）。
    pub organizational_units: Vec<String>,
    /// SAN 条目（DNS/IP/URI/email 的文本形式）。
    pub san: Vec<String>,
    /// 证书 SHA-256 指纹（小写 hex，**不含冒号**）。
    pub fingerprint_sha256: String,
    /// 主体串（`subject` 为空时退化为指纹），用于映射匹配与审计展示。
    pub identity: String,
}

impl CertInfo {
    /// 匹配用的候选串：subject、identity 与每个 SAN 条目。
    #[must_use]
    pub fn match_candidates(&self) -> Vec<&str> {
        let mut out = vec![self.subject.as_str(), self.identity.as_str()];
        out.extend(self.san.iter().map(String::as_str));
        out
    }
}

/// 解析后的主体映射（由端点装配，随请求读取）。
#[derive(Debug, Clone, Default)]
pub struct PrincipalMap {
    /// 是否有任何映射来源（映射表 / 默认角色 / 默认租户）。
    pub configured: bool,
    /// `subject-pattern` → `role`。
    pub rules: Vec<(String, String)>,
    /// 默认角色（映射未命中时使用；为空 ⇒ 映射未命中即拒绝）。
    pub default_role: Option<String>,
    /// 默认租户（为空 ⇒ 取默认租户；逐条租户留待多租户映射时启用）。
    pub default_tenant: Option<TenantId>,
}

impl PrincipalMap {
    /// 从环境读取。
    #[must_use]
    pub fn from_env() -> Self {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// 从键值查找函数读取（单测注入，避免并发写进程环境）。
    #[must_use]
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        let raw = lookup(ENV_MAP).unwrap_or_default();
        let mut rules: Vec<(String, String)> = Vec::new();
        for entry in raw.split(';').map(str::trim).filter(|e| !e.is_empty()) {
            // subject 自己含 `=`（如 `CN=agf-collector`），因此按**最后一个** `=` 切分；
            // 右侧再按 `@` 切出 `role@tenant`。
            if let Some((pattern, target)) = entry.rsplit_once('=') {
                let pattern = pattern.trim();
                let role = target.split('@').next().unwrap_or_default().trim();
                if !pattern.is_empty() && !role.is_empty() {
                    rules.push((pattern.to_ascii_lowercase(), role.to_string()));
                }
            }
        }
        let default_role = lookup(ENV_DEFAULT_ROLE).map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
        let default_tenant = lookup(ENV_DEFAULT_TENANT)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .and_then(|v| TenantId::parse(&v).ok());
        Self {
            configured: !rules.is_empty() || default_role.is_some() || default_tenant.is_some(),
            rules,
            default_role,
            default_tenant,
        }
    }

    /// 解析主体 → （角色，租户）。映射未命中且无默认角色 ⇒ `None`（**拒绝**）。
    #[must_use]
    pub fn resolve(&self, cert: &CertInfo) -> Option<(String, TenantId)> {
        let tenant = self.default_tenant.unwrap_or_else(TenantId::default_tenant);
        for (pattern, role) in &self.rules {
            if cert.match_candidates().iter().any(|candidate| pattern_matches(pattern, candidate)) {
                return Some((role.clone(), tenant));
            }
        }
        self.default_role.clone().map(|role| (role, tenant))
    }
}

/// 通配匹配（`*` = 任意串；大小写不敏感；其余字符按字面量比较）。
///
/// 语义：模式被 `*` 分段后，**首段必须前缀匹配、末段必须后缀匹配**，中间段按顺序出现。
/// 没有 `*` 时退化为全等比较——注意"唯一一段同时是首段与末段"的情况不能被要求既前缀又后缀。
#[must_use]
pub fn pattern_matches(pattern: &str, candidate: &str) -> bool {
    if pattern.is_empty() {
        return false;
    }
    let pattern = pattern.to_ascii_lowercase();
    let candidate = candidate.to_ascii_lowercase();
    if !pattern.contains('*') {
        return pattern == candidate;
    }
    let parts: Vec<&str> = pattern.split('*').collect();
    let mut rest = candidate.as_str();
    // ① 首段：前缀匹配（模式以 `*` 开头时首段为空，跳过）
    if let Some(first) = parts.first().filter(|part| !part.is_empty()) {
        let Some(stripped) = rest.strip_prefix(first) else { return false };
        rest = stripped;
    }
    // ② 末段：后缀匹配（`parts` 长度 ≥ 2，且与首段不是同一段）
    let last = parts[parts.len() - 1];
    if !last.is_empty() && !rest.ends_with(last) {
        return false;
    }
    // ③ 中间段：按顺序出现（末段已由 ② 兜底，这里只看中间）
    for part in parts.iter().skip(1).take(parts.len().saturating_sub(2)) {
        if part.is_empty() {
            continue;
        }
        match rest.find(part) {
            Some(position) => rest = &rest[position + part.len()..],
            None => return false,
        }
    }
    true
}

/// 是否信任代理头部（默认关闭；只有显式开启时才读取 `X-SSL-Client-*`）。
#[must_use]
pub fn trust_proxy_from_env() -> bool {
    trust_proxy(|key| std::env::var(key).ok())
}

/// 从键值查找函数判断是否信任代理头部。
#[must_use]
pub fn trust_proxy(lookup: impl Fn(&str) -> Option<String>) -> bool {
    lookup(ENV_TRUST_PROXY)
        .is_some_and(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
}

/// 是否强制只接受证书身份。
#[must_use]
pub fn required_from_env() -> bool {
    required(|key| std::env::var(key).ok())
}

/// 从键值查找函数判断是否强制证书身份。
#[must_use]
pub fn required(lookup: impl Fn(&str) -> Option<String>) -> bool {
    lookup(ENV_REQUIRED).is_some_and(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
}

/// 映射表的只读视图（运维/排障用；**不含任何凭据**，只有规则条数与默认值）。
#[must_use]
pub fn mapping_summary(map: &PrincipalMap) -> BTreeMap<&'static str, String> {
    let mut out = BTreeMap::new();
    out.insert("configured", map.configured.to_string());
    out.insert("rules", map.rules.len().to_string());
    out.insert("default_role", map.default_role.clone().unwrap_or_else(|| "<none>".to_string()));
    out.insert("default_tenant", map.default_tenant.map_or_else(|| "<default>".to_string(), |t| t.to_string()));
    out
}
