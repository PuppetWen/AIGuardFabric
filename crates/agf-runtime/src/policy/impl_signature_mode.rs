//! 由 `policy.rs` 拆分：`EvalErrorMode`/`HitSource`/`PolicyEngine`/`PolicyMatch`/`SignatureMode` 的实现（纯搬移，逻辑不变）。
use super::*;

impl SignatureMode {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Enforce => "enforce",
            Self::Warn => "warn",
            Self::Disabled => "disabled",
        }
    }

    /// 是否为"生产安全"的模式。
    #[must_use]
    pub const fn is_enforcing(&self) -> bool {
        matches!(self, Self::Enforce)
    }
}

impl EvalErrorMode {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::FailClosed => "fail-closed",
            Self::FailOpen => "fail-open",
        }
    }
}

impl HitSource {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::PolicyFirst => "policy-first",
            Self::FallbackDeny => "fallback-deny",
            Self::Annotate => "annotate",
            Self::Off => "off",
        }
    }

    /// 是否为"拆掉黑名单防线"的危险取值（自检据此记 FAIL）。
    #[must_use]
    pub const fn is_unsafe(&self) -> bool {
        matches!(self, Self::Off)
    }
}

impl PolicyMatch {
    /// 无命中。
    #[must_use]
    pub const fn none(evaluated: usize) -> Self {
        Self {
            policy_id: None,
            policy_name: None,
            backend_reason: None,
            backend_action: None,
            backend_redact: false,
            blocklist_hit: false,
            evaluated,
        }
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyEngine {
    /// 空引擎（无策略 ⇒ 全部请求默认放行，原因「无策略命中」）。
    #[must_use]
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
            signer: None,
            signature_mode: SignatureMode::default(),
            eval_error_mode: EvalErrorMode::default(),
            hit_source: HitSource::default(),
            rejected: Vec::new(),
            signature_warnings: Vec::new(),
        }
    }
    /// 设置签名器。
    #[must_use]
    pub fn with_signer(mut self, signer: PolicySigner) -> Self {
        self.signer = Some(signer);
        self
    }
    /// 设置签名校验模式。
    #[must_use]
    pub const fn with_signature_mode(mut self, mode: SignatureMode) -> Self {
        self.signature_mode = mode;
        self
    }
    /// 设置后端错误处理模式。
    #[must_use]
    pub const fn with_eval_error_mode(mut self, mode: EvalErrorMode) -> Self {
        self.eval_error_mode = mode;
        self
    }
    /// 设置黑名单命中参与方式。
    #[must_use]
    pub const fn with_hit_source(mut self, source: HitSource) -> Self {
        self.hit_source = source;
        self
    }
    /// 从内存策略集构造（离线模式主力入口）。
    ///
    /// # Errors
    /// 任一条 **Rego/CEL** 策略源码编译失败（含包名契约违规）即返回 [`DomainError::Parse`]。
    /// 签名问题**不**返回错误：`Enforce` 下被拒绝的策略进入 [`Self::rejected`]，
    /// `Warn` 下进入 [`Self::signature_warnings`]，便于控制台集中展示。
    pub fn from_policies(mut self, policies: Vec<Policy>) -> DomainResult<Self> {
        self.load(policies)?;
        Ok(self)
    }
    /// 批量装载/追加策略（会先对全部新策略做源码与签名校验，**全部通过才生效**）。
    ///
    /// # Errors
    /// 语法/契约错误返回 [`DomainError::Parse`]（此时引擎保持原有策略集不变）。
    pub fn load(&mut self, policies: Vec<Policy>) -> DomainResult<()> {
        let mut accepted: Vec<Policy> = Vec::with_capacity(policies.len());
        let mut rejected: Vec<(String, String)> = Vec::new();
        let mut warnings: Vec<String> = Vec::new();

        for p in policies {
            // 1) 源码校验（坏策略绝不进入热路径）
            Self::validate_source(&p)?;
            // 2) 签名校验
            match self.signature_mode {
                SignatureMode::Disabled => {}
                SignatureMode::Warn => match self.signature_state(&p) {
                    Some(state) if !state.is_valid() => {
                        warnings.push(format!("策略「{}」{}（Warn 模式放行，生产必须修复）", p.name, state.describe()));
                    }
                    None => warnings.push(format!("策略「{}」未配置签名密钥，无法校验（Warn 模式放行）", p.name)),
                    _ => {}
                },
                SignatureMode::Enforce => match self.signature_state(&p) {
                    Some(state) if state.is_valid() => {}
                    Some(state) => {
                        rejected.push((p.name.clone(), state.describe()));
                        continue;
                    }
                    None => {
                        rejected
                            .push((p.name.clone(), "引擎未配置策略签名密钥，无法在 Enforce 模式下校验".to_string()));
                        continue;
                    }
                },
            }
            accepted.push(p);
        }

        self.rejected = rejected;
        self.signature_warnings = warnings;
        for w in &self.signature_warnings {
            warn!("{w}");
        }
        for (name, reason) in &self.rejected {
            warn!(policy = %name, reason = %reason, "策略装载被拒绝");
        }
        self.policies.extend(accepted);
        self.resort();
        Ok(())
    }
    /// 用新策略集**整体替换**（热重载）。
    ///
    /// # Errors
    /// 同 [`Self::load`]；失败时旧策略集保持不变。
    pub fn replace(&mut self, policies: Vec<Policy>) -> DomainResult<()> {
        let mut candidate = Self::new()
            .with_signature_mode(self.signature_mode)
            .with_eval_error_mode(self.eval_error_mode)
            .with_hit_source(self.hit_source);
        if let Some(signer) = self.signer.clone() {
            candidate = candidate.with_signer(signer);
        }
        candidate.load(policies)?;
        self.policies = candidate.policies;
        self.rejected = candidate.rejected;
        self.signature_warnings = candidate.signature_warnings;
        self.resort();
        Ok(())
    }
    /// 校验策略源码（Rego 编译 / CEL 编译；`Structured` 直接通过）。
    ///
    /// **Rego 编译错误会在此处以 [`DomainError::Parse`] 抛出并携带策略名**，
    /// 因此调用方可在**下发/保存策略时**就拒绝坏策略，而不是等到线上拦截时才失败。
    ///
    /// # Errors
    /// 源码为空（Rego/CEL）或编译失败。
    pub fn validate_source(policy: &Policy) -> DomainResult<()> {
        match policy.language {
            PolicyLanguage::Structured => Ok(()),
            PolicyLanguage::Rego => {
                if policy.source.trim().is_empty() {
                    return Err(DomainError::Parse(format!("Rego 策略「{}」源码为空", policy.name)));
                }
                RegoBackend::compile(policy).map(|_| ())
            }
            PolicyLanguage::Cel => CelBackend::compile(policy).map(|_| ()),
        }
    }
    /// 查询某策略的签名状态（未配置签名器时返回 `None`）。
    #[must_use]
    pub fn signature_state(&self, policy: &Policy) -> Option<PolicySignatureState> {
        self.signer.as_ref().map(|s| s.state(policy))
    }
    /// 装载期被拒绝的策略（名称 + 原因）。
    #[must_use]
    pub fn rejected(&self) -> &[(String, String)] {
        &self.rejected
    }
    /// 装载期签名告警。
    #[must_use]
    pub fn signature_warnings(&self) -> &[String] {
        &self.signature_warnings
    }
    /// 生效策略数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.policies.len()
    }
    /// 是否没有任何生效策略。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
    }
    /// 生效策略快照。
    #[must_use]
    pub fn policies(&self) -> &[Policy] {
        &self.policies
    }
    /// 签名器（自检用）。
    #[must_use]
    pub fn signer(&self) -> Option<&PolicySigner> {
        self.signer.as_ref()
    }
    /// 签名校验模式。
    #[must_use]
    pub const fn signature_mode(&self) -> SignatureMode {
        self.signature_mode
    }
    /// 后端错误处理模式。
    #[must_use]
    pub const fn eval_error_mode(&self) -> EvalErrorMode {
        self.eval_error_mode
    }
    /// 黑名单命中参与方式。
    #[must_use]
    pub const fn hit_source(&self) -> HitSource {
        self.hit_source
    }
    /// 是否为"全部策略都 dry-run"（自检发现"等于没有拦截"时判 FAIL）。
    #[must_use]
    pub fn all_dry_run(&self) -> bool {
        !self.policies.is_empty() && self.policies.iter().all(|p| p.dry_run)
    }
    /// 已配置的拦截点集合（自检核对三个拦截点是否都被覆盖）。
    #[must_use]
    pub fn configured_intercept_points(&self) -> Vec<InterceptPoint> {
        let mut points: Vec<InterceptPoint> = Vec::new();
        for p in &self.policies {
            for point in &p.intercept_points {
                if !points.contains(point) {
                    points.push(*point);
                }
            }
        }
        points
    }
    /// 求值主入口。
    ///
    /// `hit` 为黑名单命中结果（由 [`crate::blocklist::Blocklist::evaluate`] 产出）。
    /// 传 `None` 时行为等价于"黑名单未命中"。
    ///
    /// # Errors
    /// - `EvalErrorMode::FailClosed` 下后端求值失败 ⇒ [`DomainError::PolicyDenied`]；
    /// - `EvalErrorMode::FailOpen` 下不返回错误（放行并记警告）。
    pub fn evaluate(
        &self,
        ctx: &PolicyContext,
        hit: Option<&crate::blocklist::RuleHit>,
    ) -> DomainResult<PolicyDecision> {
        self.evaluate_inner(ctx, hit).map(|(decision, _)| decision)
    }
    /// 求值并返回"是否需要脱敏"。
    ///
    /// 脱敏要求有三个来源，任一成立即需要脱敏（决策内的 `redact` 字段是其汇总）：
    /// 1. 策略动作是 `redact`；
    /// 2. Rego/CEL 的 `redact` 规则返回 `true`；
    /// 3. 结构化条件命中且策略动作本身就是 `redact`（同上，1 的子集）。
    ///
    /// # Errors
    /// 同 [`Self::evaluate`]。
    pub fn evaluate_for_redaction(
        &self,
        ctx: &PolicyContext,
        hit: Option<&crate::blocklist::RuleHit>,
    ) -> DomainResult<(PolicyDecision, bool)> {
        let decision = self.evaluate(ctx, hit)?;
        let needs = decision.needs_redaction();
        Ok((decision, needs))
    }
}
