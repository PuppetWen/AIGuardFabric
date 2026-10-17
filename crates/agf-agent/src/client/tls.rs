//! 采集器客户端 **mTLS**：配置解析、运行模式映射、PEM 装配（rustls）与健康画像。
//!
//! ## 环境变量（唯一配置来源，与 `.env.example` 的 `AGF_COLLECTOR_*` 口径对齐）
//!
//! | 变量 | 含义 | 缺省 |
//! |---|---|---|
//! | `AGF_AGENT_TLS_CERT` | 客户端证书链（PEM，mTLS 身份） | 未配置 |
//! | `AGF_AGENT_TLS_KEY` | 客户端私钥（PEM，PKCS#8/PKCS#1/SEC1） | 未配置 |
//! | `AGF_AGENT_TLS_CA` | 校验服务端的 CA 证书（PEM） | 内置公共根（`webpki-roots`） |
//! | `AGF_AGENT_TLS_INSECURE_SKIP_VERIFY` | 跳过服务端证书链校验（**仅排障**） | `false` |
//! | `AGF_ENV` | 环境名（`dev` 是跳过校验的必要条件之一） | 未配置 |
//! | `AGF_AGENT_TLS_ALLOW_INSECURE` | 显式允许跳过校验（除 `AGF_ENV=dev` 之外的第二把钥匙） | `false` |
//!
//! ## 三种 TLS 模式（由配置**确定地**推导，不做猜测）
//!
//! | 模式 | 条件 | 传输行为 |
//! |---|---|---|
//! | [`TlsMode::Plaintext`] | `server_url` 是 `http://` | 不建 TLS 连接（**显式**，不是静默降级） |
//! | [`TlsMode::ServerAuth`] | `https://` 且未配置客户端证书/私钥 | 校验服务端，不提供客户端身份 |
//! | [`TlsMode::Mutual`] | `https://` 且证书 + 私钥**成对**配置 | 双向校验：客户端证书即主体身份 |
//!
//! ## 三条铁律
//!
//! 1. **绝不静默**：只给了证书或只给了私钥 ⇒ [`DomainError::Config`]；配置了客户端证书但
//!    明文 `http://` ⇒ 同样报错（否则密钥会在链路上明文出网）；
//! 2. **凭据绝不进日志/Debug/错误文本**：本模块的错误只携带**变量名**与**分类**，从不回显
//!    PEM 内容、私钥字节或文件内容；[`TlsMaterial`] 的 `Debug` 一律 `<PEM:REDACTED>`；
//! 3. **跳过校验必须显式且留痕**：仅当 `AGF_ENV=dev` **或** `AGF_AGENT_TLS_ALLOW_INSECURE=1`
//!    时生效，且生效时必然 `warn!`，并在健康画像里如实标注 `insecure_skip_verify=true`。

use std::path::PathBuf;

use agf_core::error::{DomainError, DomainResult};

use super::{ClientConfig, fmt};

/// 客户端证书链 PEM 路径。
pub const ENV_TLS_CERT: &str = "AGF_AGENT_TLS_CERT";
/// 客户端私钥 PEM 路径。
pub const ENV_TLS_KEY: &str = "AGF_AGENT_TLS_KEY";
/// 服务端校验 CA PEM 路径。
pub const ENV_TLS_CA: &str = "AGF_AGENT_TLS_CA";
/// 跳过服务端证书链校验（仅排障）。
pub const ENV_TLS_INSECURE_SKIP_VERIFY: &str = "AGF_AGENT_TLS_INSECURE_SKIP_VERIFY";
/// 环境名（`dev` 是跳过校验的必要条件之一）。
pub const ENV_ENV_NAME: &str = "AGF_ENV";
/// 显式允许跳过校验（`AGF_ENV=dev` 之外的第二把钥匙）。
pub const ENV_TLS_ALLOW_INSECURE: &str = "AGF_AGENT_TLS_ALLOW_INSECURE";
/// 真实 mTLS 上行实现（替换 `HttpTransportNotImplemented` 里的 TODO 锚点）。
pub const TLS_IMPLEMENTED_ANCHOR: &str = "agent-mtls";

/// "客户端证书缺失"错误的固定前缀（分类依赖它，**不要改**）。
pub const CLIENT_CERT_MISSING_PREFIX: &str = "mTLS 客户端证书缺失";

/// TLS 运行模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TlsMode {
    /// 明文 HTTP（`http://`，不建 TLS）。
    Plaintext,
    /// 单向 TLS：校验服务端，客户端不提供证书。
    ServerAuth,
    /// 双向 TLS：客户端证书即主体身份。
    Mutual,
}

impl TlsMode {
    /// 文本形式（健康/排障用）。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Plaintext => "plaintext",
            Self::ServerAuth => "server-auth",
            Self::Mutual => "mutual",
        }
    }

    /// 是否真正建立 TLS 连接。
    #[must_use]
    pub const fn is_tls(&self) -> bool {
        !matches!(self, Self::Plaintext)
    }

    /// 是否双向认证（客户端出示证书）。
    #[must_use]
    pub const fn is_mutual(&self) -> bool {
        matches!(self, Self::Mutual)
    }
}

/// 错误分类（**不含任何凭据内容**，可安全进日志/健康画像）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TlsErrorKind {
    /// 配置组合非法（证书/私钥不成对、明文配了客户端证书、跳过校验未获授权）。
    Config,
    /// PEM 文件不存在或不可读。
    MissingFile,
    /// PEM 内容非法（没有证书 / 没有私钥 / 解析失败）。
    BadPem,
    /// 证书与私钥不匹配。
    KeyMismatch,
    /// TLS 握手失败（证书被拒、主机名不符、协议不兼容）。
    Handshake,
    /// 服务端要求客户端证书，而本端未配置（mTLS 配置漏项）。
    ClientCertMissing,
    /// 网络层失败（DNS/连接/读写）。
    Network,
    /// 服务端返回非 2xx。
    Http,
}

impl TlsErrorKind {
    /// 稳定文本（健康画像与日志用）。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::MissingFile => "missing-file",
            Self::BadPem => "bad-pem",
            Self::KeyMismatch => "key-mismatch",
            Self::Handshake => "handshake",
            Self::ClientCertMissing => "client-cert-missing",
            Self::Network => "network",
            Self::Http => "http",
        }
    }

    /// 由 [`DomainError`] 变体归类（错误文本里的凭据不会进入分类）。
    ///
    /// `ClientCertMissing` 与 `Handshake` 在上游都是 `Unauthenticated`/`Forbidden`，
    /// 因此这里用**我们自己的固定前缀**区分——前缀由本模块生成，不依赖 rustls 的错误文案。
    #[must_use]
    pub fn of(error: &DomainError) -> Self {
        match error {
            DomainError::Config(_) => Self::Config,
            DomainError::Validation(_) | DomainError::Parse(_) => Self::BadPem,
            DomainError::Timeout(_) | DomainError::DependencyUnavailable { .. } => Self::Network,
            DomainError::Unauthenticated(text) | DomainError::Forbidden(text) => {
                if text.starts_with(CLIENT_CERT_MISSING_PREFIX) { Self::ClientCertMissing } else { Self::Handshake }
            }
            _ => Self::Network,
        }
    }
}

/// TLS 配置（**只持有路径**，真正读盘在 [`TlsConfig::load`]）。
///
/// 刻意**不派生 `Debug`**：路径本身要出现在健康画像与日志里（`describe()`），但把整个结构
/// 结构体打印出来容易连带打印相邻字段；`describe()` / [`TlsHealth`] 是唯一的展示入口。
#[derive(Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TlsConfig {
    /// 客户端证书链（PEM 路径）。
    pub client_cert_pem: Option<PathBuf>,
    /// 客户端私钥（PEM 路径）。
    pub client_key_pem: Option<PathBuf>,
    /// 服务端校验 CA（PEM 路径）；`None` ⇒ 用内置公共根证书。
    pub ca_pem: Option<PathBuf>,
    /// 跳过服务端证书链校验**实际生效值**（构造 rustls 配置前必须已通过门禁）。
    ///
    /// `Debug` 刻意**不打印**这个字段：它的取值本身不是秘密，但会诱导排障时只看它而不看
    /// [`TlsHealth`]；健康画像才是唯一权威的可观测面。
    pub insecure_skip_verify: bool,
    /// 跳过校验是否已获授权（`AGF_ENV=dev` 或显式 `AGF_AGENT_TLS_ALLOW_INSECURE=1`）。
    pub insecure_allowed: bool,
    /// 环境变量是否**请求过**跳过校验（无论是否获授权；用于"明确报错"而不是静默忽略）。
    pub insecure_requested: bool,
    /// 环境名（`AGF_ENV`，排障用）。
    pub env_name: Option<String>,
}

impl TlsConfig {
    /// 从进程环境读取。
    #[must_use]
    pub fn from_env() -> Self {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// 从任意键值查找函数读取（单测注入用，避免并发写环境变量）。
    #[must_use]
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        let env_name = lookup(ENV_ENV_NAME).map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
        let explicit_allow = flag(&lookup, ENV_TLS_ALLOW_INSECURE);
        let dev = env_name.as_deref().is_some_and(|v| v.eq_ignore_ascii_case("dev"))
            || env_name.as_deref().is_some_and(|v| v.eq_ignore_ascii_case("development"));
        let insecure_allowed = explicit_allow || dev;
        let requested = flag(&lookup, ENV_TLS_INSECURE_SKIP_VERIFY);
        Self {
            client_cert_pem: path(&lookup, ENV_TLS_CERT),
            client_key_pem: path(&lookup, ENV_TLS_KEY),
            ca_pem: path(&lookup, ENV_TLS_CA),
            // 未获授权时**实际值置 false**：既不放行也不静默——`validate` 会据 `insecure_denied()` 明确报错。
            insecure_skip_verify: requested && insecure_allowed,
            insecure_allowed,
            insecure_requested: requested,
            env_name,
        }
    }

    /// 是否配置了客户端证书（mTLS 身份）。
    #[must_use]
    pub const fn has_client_cert(&self) -> bool {
        self.client_cert_pem.is_some()
    }

    /// 证书/私钥是否成对。
    #[must_use]
    pub const fn keypair_complete(&self) -> bool {
        self.client_cert_pem.is_some() == self.client_key_pem.is_some()
    }

    /// 是否配置了 TLS 相关材料（任一）。
    #[must_use]
    pub const fn is_configured(&self) -> bool {
        self.client_cert_pem.is_some()
            || self.client_key_pem.is_some()
            || self.ca_pem.is_some()
            || self.insecure_skip_verify
    }

    /// 跳过校验是否被请求但未获授权（用于"明确报错"而不是静默忽略）。
    #[must_use]
    pub const fn insecure_denied(&self) -> bool {
        self.insecure_requested && !self.insecure_allowed
    }

    /// 由服务端地址推导 TLS 模式（纯函数，不做 IO）。
    #[must_use]
    pub fn mode_for(&self, server_url: Option<&str>) -> TlsMode {
        let https = server_url.is_some_and(|url| url.trim().to_ascii_lowercase().starts_with("https://"));
        if !https {
            return TlsMode::Plaintext;
        }
        if self.has_client_cert() { TlsMode::Mutual } else { TlsMode::ServerAuth }
    }

    /// 校验组合合法性（**缺什么就报什么，绝不静默降级**）。
    ///
    /// `server_url = None` 表示"只校验材料本身的组合"（读盘阶段用）：此时不做
    /// "客户端证书用于明文"的判定——那一判定需要真实的上行地址才能定性。
    ///
    /// # Errors
    /// - 只提供证书或只提供私钥 ⇒ `Config`；
    /// - 配置了客户端证书却用明文 `http://` ⇒ `Config`；
    /// - 请求了跳过校验但未获授权 ⇒ `Config`（`AGF_ENV=dev` 或显式开关）。
    pub fn validate(&self, server_url: Option<&str>) -> DomainResult<TlsMode> {
        if !self.keypair_complete() {
            return Err(DomainError::Config(format!(
                "mTLS 配置不完整：{ENV_TLS_CERT} 与 {ENV_TLS_KEY} 必须成对提供（当前只给了其中一个）；\
                 缺少的一方不会被静默忽略"
            )));
        }
        if self.insecure_denied() {
            return Err(DomainError::Config(format!(
                "{ENV_TLS_INSECURE_SKIP_VERIFY}=1 未获授权：仅当 {ENV_ENV_NAME}=dev 或 {ENV_TLS_ALLOW_INSECURE}=1 时允许"
            )));
        }
        let mode = match server_url {
            Some(url) => {
                let mode = self.mode_for(Some(url));
                if self.has_client_cert() && mode == TlsMode::Plaintext {
                    return Err(DomainError::Config(format!(
                        "已配置客户端证书（{ENV_TLS_CERT}）但服务端地址不是 https://：拒绝把证书用于明文上行"
                    )));
                }
                mode
            }
            None => TlsMode::ServerAuth,
        };
        if self.insecure_skip_verify {
            tracing::warn!(
                env = ?self.env_name,
                "{ENV_TLS_INSECURE_SKIP_VERIFY} 已生效：服务端证书链校验被关闭，仅可用于排障（生产必须关闭）"
            );
        }
        Ok(mode)
    }

    /// 人读描述（`/health` 与排障；**不含任何密钥内容**）。
    #[must_use]
    pub fn describe(&self, server_url: Option<&str>) -> String {
        let mode = self.mode_for(server_url);
        if mode == TlsMode::Plaintext {
            return "明文 HTTP（未启用 TLS）".to_string();
        }
        let trust = match &self.ca_pem {
            Some(path) => format!("CA={}", path.display()),
            None => "CA=内置公共根证书(webpki-roots)".to_string(),
        };
        let mtls = if mode.is_mutual() { "，mTLS=开启（出示客户端证书）" } else { "，mTLS=未配置" };
        let insecure = if self.insecure_skip_verify { "，**证书链校验已跳过**" } else { "，校验证书链" };
        format!("TLS（{trust}{mtls}{insecure}）")
    }
}

impl fmt::Display for TlsMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for TlsConfig {
    /// **只打印路径与开关，绝不打印任何 PEM 内容**；跳过校验的取值也刻意折叠为
    /// "已配置/未配置"，避免排障时误把它当成权威结论（权威面是 [`TlsHealth`]）。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsConfig")
            .field("client_cert_pem", &self.client_cert_pem)
            .field("client_key_pem", &self.client_key_pem)
            .field("ca_pem", &self.ca_pem)
            .field("insecure_skip_verify", &if self.insecure_skip_verify { "configured" } else { "off" })
            .field("insecure_allowed", &self.insecure_allowed)
            .field("insecure_requested", &self.insecure_requested)
            .field("env_name", &self.env_name)
            .finish()
    }
}

/// 布尔型环境开关（`1` / `true` / `yes` / `on`，大小写不敏感）。
fn flag(lookup: &impl Fn(&str) -> Option<String>, key: &str) -> bool {
    lookup(key).is_some_and(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
}

/// 路径型环境变量（空串视为未配置）。
fn path(lookup: &impl Fn(&str) -> Option<String>, key: &str) -> Option<PathBuf> {
    lookup(key).map(|v| v.trim().to_string()).filter(|v| !v.is_empty()).map(PathBuf::from)
}

/// TLS 健康画像（进 [`super::DeliveryOutcome`] 之外的健康检查；**不含凭据**）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TlsHealth {
    /// 推导出的 TLS 模式。
    pub mode: TlsMode,
    /// 是否配置了客户端证书。
    pub client_cert_configured: bool,
    /// 是否配置了客户端私钥。
    pub client_key_configured: bool,
    /// 是否配置了自定义 CA。
    pub ca_configured: bool,
    /// 是否跳过服务端证书链校验。
    pub insecure_skip_verify: bool,
    /// 是否已授权跳过校验。
    pub insecure_allowed: bool,
    /// 环境名（`AGF_ENV`）。
    pub env_name: Option<String>,
    /// 材料是否可用（证书/私钥成对且已读盘成功）。
    pub material_ready: bool,
    /// 不健康原因分类（`None` = 配置自洽，不代表握手一定成功）。
    pub error_kind: Option<TlsErrorKind>,
    /// 人读说明（不含凭据）。
    pub detail: String,
}

impl TlsHealth {
    /// 是否处于"配置正确且材料可用"的健康态。
    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        self.error_kind.is_none() && self.material_ready
    }
}

impl ClientConfig {
    /// 由环境装配 TLS 配置（`ClientConfig::from_env` 会调用）。
    #[must_use]
    pub fn tls_from_env() -> TlsConfig {
        TlsConfig::from_env()
    }

    /// 链式设置 TLS 配置。
    #[must_use]
    pub fn with_tls(mut self, tls: TlsConfig) -> Self {
        self.tls = tls;
        self
    }

    /// TLS 模式（由 `server_url` + TLS 配置推导）。
    #[must_use]
    pub fn tls_mode(&self) -> TlsMode {
        self.tls.mode_for(self.server_url.as_deref())
    }

    /// TLS 健康画像（读盘成功与否都如实反映；**绝不回显凭据**）。
    #[must_use]
    pub fn tls_health(&self) -> TlsHealth {
        let mode = self.tls_mode();
        let mut health = TlsHealth {
            mode,
            client_cert_configured: self.tls.client_cert_pem.is_some(),
            client_key_configured: self.tls.client_key_pem.is_some(),
            ca_configured: self.tls.ca_pem.is_some(),
            insecure_skip_verify: self.tls.insecure_skip_verify,
            insecure_allowed: self.tls.insecure_allowed,
            env_name: self.tls.env_name.clone(),
            material_ready: false,
            error_kind: None,
            detail: self.tls.describe(self.server_url.as_deref()),
        };
        if !mode.is_tls() {
            // 明文模式：无 TLS 材料要装配，视为"就绪"（这不是降级，是配置本意）。
            health.material_ready = true;
            if self.tls.has_client_cert() {
                health.error_kind = Some(TlsErrorKind::Config);
                health.detail = format!("已配置 {ENV_TLS_CERT} 但地址不是 https://：拒绝明文上行（配置错误）");
            }
            return health;
        }
        match self.tls.validate(self.server_url.as_deref()).and_then(|_| self.tls.load().map(|_| ())) {
            Ok(()) => {
                health.material_ready = true;
            }
            Err(error) => {
                health.error_kind = Some(TlsErrorKind::of(&error));
                health.detail = error.to_string();
            }
        }
        health
    }
}
