//! 由 `credential.rs` 拆分：`CloudCredential`/`CredentialContext`/`CredentialOutcome`/`CredentialWarning`/`EnvResolver`/`MapSecretStore`/`StaticResolver` 的实现（纯搬移，逻辑不变）。
use super::*;

impl std::fmt::Debug for CloudCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudCredential")
            .field("access_key_id", &mask_default(&self.access_key_id))
            .field("access_key_secret", &"<redacted>")
            .field("security_token", &self.security_token.as_ref().map(|_| "<redacted>"))
            .field("expires_at", &self.expires_at)
            .field("kind", &self.kind)
            .finish()
    }
}

impl CloudCredential {
    /// 构造长期 AK 凭据（**不推荐**，仅供遗留环境与测试）。
    #[must_use]
    pub fn long_term(access_key_id: impl Into<String>, access_key_secret: impl Into<String>) -> Self {
        Self {
            access_key_id: access_key_id.into(),
            access_key_secret: access_key_secret.into(),
            security_token: None,
            expires_at: None,
            kind: CloudCredentialKind::LongTermAk,
        }
    }

    /// 构造 STS 临时凭据。
    #[must_use]
    pub fn sts(
        access_key_id: impl Into<String>,
        access_key_secret: impl Into<String>,
        security_token: impl Into<String>,
        expires_at: Timestamp,
        kind: CloudCredentialKind,
    ) -> Self {
        Self {
            access_key_id: access_key_id.into(),
            access_key_secret: access_key_secret.into(),
            security_token: Some(security_token.into()),
            expires_at: Some(expires_at),
            kind,
        }
    }

    /// 是否已过期（相对 `now`）。
    #[must_use]
    pub fn is_expired(&self, now: Timestamp) -> bool {
        self.expires_at.is_some_and(|e| e.since_secs(&now) <= 0)
    }

    /// 是否临近过期（默认 15 分钟内需要刷新）。
    #[must_use]
    pub fn is_expiring_soon(&self, now: Timestamp) -> bool {
        self.expires_at.is_some_and(|e| e.since_secs(&now) < REFRESH_THRESHOLD_SECS)
    }

    /// 是否长期密钥（风险项）。
    #[must_use]
    pub const fn is_long_lived(&self) -> bool {
        self.kind.is_long_lived()
    }

    /// 脱敏描述（可安全写日志）。
    #[must_use]
    pub fn masked(&self) -> String {
        format!("{}:{}", self.kind.as_str(), mask_default(&self.access_key_id))
    }

    /// 校验签名材料齐全（缺一不可）。
    ///
    /// # Errors
    /// AccessKeyId / Secret 为空时返回 [`DomainError::Config`]。
    pub fn validate(&self) -> DomainResult<()> {
        if self.access_key_id.trim().is_empty() {
            return Err(DomainError::Config("AccessKeyId 为空".to_string()));
        }
        if self.access_key_secret.is_empty() {
            return Err(DomainError::Config("AccessKeySecret 为空".to_string()));
        }
        Ok(())
    }
}

impl CredentialWarning {
    /// 依据凭据类型生成告警（长期 AK 才有）。
    #[must_use]
    pub fn for_kind(kind: CloudCredentialKind) -> Option<Self> {
        if kind.is_long_lived() {
            Some(Self {
                name: "credential:long-term-ak".to_string(),
                note: "检测到长期 AccessKey：违反 §5.3（禁止长期 AK 明文落盘），\
                       请改用实例 RAM Role / STS 临时凭据 / 跨账号 AssumeRole；\
                       当前凭据仅以密文形式保存，且已登记为风险项"
                    .to_string(),
                required: false,
            })
        } else {
            None
        }
    }

    /// 转换为自检项。
    ///
    /// 长期 AK 是"已知风险"，因此 `passed = false`（自检页标红）但 `required = false`（不阻断接入）。
    #[must_use]
    pub fn to_check(&self, now: Timestamp) -> agf_core::cloud::PermissionCheck {
        agf_core::cloud::PermissionCheck {
            name: self.name.clone(),
            passed: false,
            note: self.note.clone(),
            required: self.required,
            checked_at: now,
        }
    }
}

impl CredentialOutcome {
    /// 由凭据构造结果，自动补齐告警与风险标记。
    #[must_use]
    pub fn new(credential: CloudCredential) -> Self {
        let warnings = CredentialWarning::for_kind(credential.kind).into_iter().collect::<Vec<_>>();
        Self { long_lived_risk: credential.is_long_lived(), credential, warnings, resolved_at: Timestamp::now() }
    }
}

impl std::fmt::Debug for CredentialContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialContext")
            // secrets 是密文读取口，不打印其内部形态
            .field("secrets", &"<secret-lookup>")
            .field("mock", &self.mock)
            .field("now", &self.now)
            .finish()
    }
}

impl CredentialContext {
    /// 构造上下文。
    #[must_use]
    pub fn new(secrets: Arc<dyn SecretLookup>, mock: bool) -> Self {
        Self { secrets, mock, now: Timestamp::now() }
    }

    /// 指定时间基准（测试）。
    #[must_use]
    pub const fn with_now(mut self, now: Timestamp) -> Self {
        self.now = now;
        self
    }
}

impl MapSecretStore {
    /// 空表。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 插入一条。
    pub fn insert(&mut self, id: Id, secret: impl Into<String>) {
        self.values.insert(id, secret.into());
    }

    /// 构造并返回 `Arc` 句柄。
    #[must_use]
    pub fn shared(entries: &[(Id, String)]) -> Arc<Self> {
        let mut store = Self::new();
        for (id, value) in entries {
            store.insert(*id, value.clone());
        }
        Arc::new(store)
    }
}

impl SecretLookup for MapSecretStore {
    fn resolve_secret(&self, credential_ref: Id) -> DomainResult<String> {
        self.values
            .get(&credential_ref)
            .cloned()
            .ok_or_else(|| DomainError::NotFound { entity: "credential", id: credential_ref.to_string() })
    }
}

impl std::fmt::Debug for StaticResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticResolver").field("credential", &self.credential).finish()
    }
}

impl StaticResolver {
    /// 由凭据构造。
    #[must_use]
    pub const fn new(credential: CloudCredential) -> Self {
        Self { credential }
    }

    /// 便捷构造长期 AK（测试用）。
    #[must_use]
    pub fn long_term(ak: &str, sk: &str) -> Self {
        Self::new(CloudCredential::long_term(ak, sk))
    }
}

impl CredentialResolver for StaticResolver {
    fn name(&self) -> &'static str {
        "static"
    }

    fn resolve(&self, _integration: &CloudIntegration, _ctx: &CredentialContext) -> DomainResult<CredentialOutcome> {
        self.credential.validate()?;
        Ok(CredentialOutcome::new(self.credential.clone()))
    }
}

impl std::fmt::Debug for EnvResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnvResolver")
            .field("prefix", &self.prefix)
            // getter 是函数指针，无诊断价值
            .field("getter", &"<env-getter>")
            .finish()
    }
}

impl Default for EnvResolver {
    fn default() -> Self {
        Self { prefix: None, getter: Arc::new(|k| std::env::var(k).ok()) }
    }
}

impl EnvResolver {
    /// 默认前缀 + 进程环境的解析器。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 指定前缀。
    #[must_use]
    pub fn with_prefix(prefix: impl Into<String>) -> Self {
        Self { prefix: Some(prefix.into()), getter: Arc::new(|k| std::env::var(k).ok()) }
    }

    /// 注入自定义读取口（测试用）。
    #[must_use]
    pub fn with_getter(mut self, getter: EnvGetter) -> Self {
        self.getter = getter;
        self
    }

    pub(crate) fn key(&self, suffix: &str) -> String {
        format!("{}{suffix}", self.prefix.as_deref().unwrap_or(ENV_PREFIX))
    }

    pub(crate) fn read(&self, suffix: &str) -> Option<String> {
        (self.getter)(&self.key(suffix)).filter(|v| !v.trim().is_empty())
    }
}

impl CredentialResolver for EnvResolver {
    fn name(&self) -> &'static str {
        "env"
    }

    fn resolve(&self, integration: &CloudIntegration, ctx: &CredentialContext) -> DomainResult<CredentialOutcome> {
        let ak = self.read("ACCESS_KEY_ID");
        let sk = self.read("ACCESS_KEY_SECRET");
        let (Some(ak), Some(sk)) = (ak, sk) else {
            return Err(DomainError::Config(format!(
                "环境变量 {}ACCESS_KEY_ID / ACCESS_KEY_SECRET 未配置（账号 {}）",
                self.prefix.as_deref().unwrap_or(ENV_PREFIX),
                integration.account_id
            )));
        };
        let token = self.read("SECURITY_TOKEN");
        let kind = match token {
            Some(_) => CloudCredentialKind::StsToken,
            None => CloudCredentialKind::LongTermAk,
        };
        let expires_at = if token.is_some() {
            Some(
                self.read("SECURITY_TOKEN_EXPIRATION")
                    .map(|raw| {
                        Timestamp::parse_rfc3339(&raw)
                            .map_err(|_| DomainError::Config("SECURITY_TOKEN_EXPIRATION 必须是 RFC3339 时间".into()))
                    })
                    .transpose()?
                    .or(integration.sts_expires_at)
                    .ok_or_else(|| DomainError::Config("临时凭据必须提供真实的 SECURITY_TOKEN_EXPIRATION".into()))?,
            )
        } else {
            None
        };
        let credential =
            CloudCredential { access_key_id: ak, access_key_secret: sk, security_token: token, expires_at, kind };
        credential.validate()?;
        if credential.is_expired(ctx.now) {
            return Err(DomainError::Forbidden("环境临时凭据已过期".into()));
        }
        Ok(CredentialOutcome::new(credential))
    }
}
