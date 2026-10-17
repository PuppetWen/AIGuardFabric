//! 由 `credential.rs` 拆分：`impl_StsResolver`/`impl_StsResolver` 等 11 项（纯搬移，逻辑不变）。
use super::*;

impl Default for StsResolver {
    fn default() -> Self {
        Self { endpoint: "sts.aliyuncs.com".to_string(), allow_network: false }
    }
}

impl StsResolver {
    /// 默认（不联网）解析器。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 允许异步解析入口进行真实 STS 交换。
    #[must_use]
    pub fn allowing_network(mut self) -> Self {
        self.allow_network = true;
        self
    }
}

impl CredentialResolver for StsResolver {
    fn name(&self) -> &'static str {
        "sts"
    }

    fn resolve(&self, integration: &CloudIntegration, ctx: &CredentialContext) -> DomainResult<CredentialOutcome> {
        if ctx.mock || !self.allow_network {
            return Err(DomainError::DependencyUnavailable {
                dependency: "aliyun.sts.AssumeRole".to_string(),
                cause: format!(
                    "STS 解析需要访问 {}；当前 mock={} allow_network={}，已阻断真实调用",
                    self.endpoint, ctx.mock, self.allow_network
                ),
            });
        }
        Err(DomainError::DependencyUnavailable {
            dependency: "aliyun.sts".into(),
            cause: format!("账号 {} 的网络凭据交换需要调用 resolve_async", integration.account_id),
        })
    }
}

impl std::fmt::Debug for AssumeRoleResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AssumeRoleResolver")
            .field("source", &self.source.name())
            .field("endpoint", &self.endpoint)
            .field("allow_network", &self.allow_network)
            .finish()
    }
}

impl AssumeRoleResolver {
    /// 构造。
    #[must_use]
    pub fn new(source: Arc<dyn CredentialResolver>) -> Self {
        Self { source, endpoint: "sts.aliyuncs.com".to_string(), allow_network: false }
    }

    /// 允许联网（生产路径）。
    #[must_use]
    pub fn allowing_network(mut self) -> Self {
        self.allow_network = true;
        self
    }

    /// 校验集成是否声明了 Role ARN。
    ///
    /// # Errors
    /// 缺少 [`CloudIntegration::assume_role_arn`] 时返回 [`DomainError::Config`]。
    pub fn require_role_arn(integration: &CloudIntegration) -> DomainResult<&str> {
        integration
            .assume_role_arn
            .as_deref()
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| DomainError::Config(format!("跨账号集成 {} 未配置 assume_role_arn", integration.account_id)))
    }
}

impl CredentialResolver for AssumeRoleResolver {
    fn name(&self) -> &'static str {
        "assume-role"
    }

    fn resolve(&self, integration: &CloudIntegration, ctx: &CredentialContext) -> DomainResult<CredentialOutcome> {
        let arn = Self::require_role_arn(integration)?;
        // 源凭据先解析出来：即使不能联网，也能立刻暴露"源凭据都缺"这种配置问题。
        let _source = self.source.resolve(integration, ctx)?;
        if ctx.mock || !self.allow_network {
            return Err(DomainError::DependencyUnavailable {
                dependency: format!("aliyun.sts.AssumeRole@{arn}"),
                cause: format!(
                    "AssumeRole 需要访问 {}；当前 mock={} allow_network={}，已阻断真实调用",
                    self.endpoint, ctx.mock, self.allow_network
                ),
            });
        }
        Err(DomainError::DependencyUnavailable {
            dependency: "aliyun.sts.AssumeRole".into(),
            cause: format!("跨账号角色 {arn} 的网络交换需要调用 resolve_async"),
        })
    }
}

/// 会话名清洗：阿里云 RoleSessionName 只允许字母数字与 `.-_`，且长度 2-64。
#[must_use]
pub fn sanitize_session_name(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' { c } else { '-' })
        .collect();
    let trimmed = cleaned.trim_matches('-');
    let mut out = if trimmed.len() < 2 { format!("agf{trimmed}") } else { trimmed.to_string() };
    out.truncate(64);
    out
}

/// 自动选择解析器：按凭据类型给出"该用哪个解析器"的建议（自检页与文档共用）。
#[must_use]
pub fn recommended_resolver(kind: CloudCredentialKind) -> &'static str {
    match kind {
        CloudCredentialKind::InstanceRole => "instance-role（元数据服务，无需密钥）",
        CloudCredentialKind::StsToken => "sts",
        CloudCredentialKind::AssumeRole => "assume-role",
        CloudCredentialKind::WorkloadIdentity => "workload-identity（OIDC 换取 STS）",
        CloudCredentialKind::LongTermAk => "env / 静态（不推荐，请尽快迁移到 RAM Role）",
    }
}

impl std::fmt::Debug for RefreshableCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshableCredential")
            .field("resolver", &self.resolver.name())
            .field("cached", &self.cached.lock().map(|g| g.is_some()).unwrap_or(false))
            .finish()
    }
}

impl RefreshableCredential {
    /// 构造。
    #[must_use]
    pub fn new(resolver: Arc<dyn CredentialResolver>) -> Self {
        Self { resolver, cached: std::sync::Mutex::new(None) }
    }

    /// 当前缓存（若有）。
    ///
    /// # Errors
    /// 锁中毒时返回 [`DomainError::Internal`]。
    pub fn cached(&self) -> DomainResult<Option<CredentialOutcome>> {
        self.cached.lock().map(|g| g.clone()).map_err(|_| DomainError::Internal("凭据缓存锁中毒".to_string()))
    }

    /// 是否需要刷新（无缓存 / 已过期 / 临近过期）。
    ///
    /// # Errors
    /// 锁中毒时返回 [`DomainError::Internal`]。
    pub fn should_refresh(&self, now: Timestamp) -> DomainResult<bool> {
        let guard = self.cached.lock().map_err(|_| DomainError::Internal("凭据缓存锁中毒".to_string()))?;
        Ok(match guard.as_ref() {
            None => true,
            Some(outcome) => outcome.credential.is_expired(now) || outcome.credential.is_expiring_soon(now),
        })
    }

    /// 解析（必要时刷新）。
    ///
    /// # Errors
    /// 解析失败或锁中毒。
    pub fn resolve(&self, integration: &CloudIntegration, ctx: &CredentialContext) -> DomainResult<CredentialOutcome> {
        if !self.should_refresh(ctx.now)? {
            if let Some(existing) = self.cached()? {
                return Ok(existing);
            }
        }
        let fresh = self.resolver.resolve(integration, ctx)?;
        {
            let mut guard = self.cached.lock().map_err(|_| DomainError::Internal("凭据缓存锁中毒".to_string()))?;
            *guard = Some(fresh.clone());
        }
        Ok(fresh)
    }

    /// 主动失效缓存（凭据泄漏或权限变更后调用）。
    ///
    /// # Errors
    /// 锁中毒时返回 [`DomainError::Internal`]。
    pub fn invalidate(&self) -> DomainResult<()> {
        let mut guard = self.cached.lock().map_err(|_| DomainError::Internal("凭据缓存锁中毒".to_string()))?;
        *guard = None;
        Ok(())
    }
}

/// 安全提示：把凭据按"绝不明文落盘"的规则描述出来（控制台"接入管理"页展示）。
#[must_use]
pub fn storage_hint() -> String {
    format!(
        "凭据以 AES-256-GCM 密文存入 credentials 表（AAD 绑定租户 + 凭据 id）；\
         界面与日志仅显示 {} 形态的掩码；禁止写入配置文件或提交到仓库",
        mask_default("LTAI5tExample0000")
    )
}
