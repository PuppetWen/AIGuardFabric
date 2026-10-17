//! 由 `vendor.rs` 拆分：`resolve_mode`/`impl_VendorAdapterImpl` 等 3 项（纯搬移，逻辑不变）。
use super::*;

/// 解析运行模式（纯函数）。
///
/// 优先级：显式 Mock / 环境 Mock → `Mocked`；配置齐全 → `Live`；否则 `Unconfigured`。
#[must_use]
pub fn resolve_mode<V: VendorSpec>(settings: &AdapterSettings, mock_env: bool) -> AdapterMode {
    if settings.mock || mock_env {
        return AdapterMode::Mocked;
    }
    if settings.is_configured() && V::is_configured(settings) { AdapterMode::Live } else { AdapterMode::Unconfigured }
}

impl<V: VendorSpec> fmt::Debug for VendorAdapterImpl<V> {
    /// 只输出适配器名、模式与熔断态；设置项经 [`AdapterSettings`] 的掩码 `Debug`。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VendorAdapter")
            .field("name", &V::NAME)
            .field("mode", &self.core.mode)
            .field("closed", &self.core.closed)
            .field("circuit", &self.circuit())
            .field("settings", &self.core.settings)
            .finish_non_exhaustive()
    }
}

impl<V: VendorSpec> VendorAdapterImpl<V> {
    /// 未配置形态（`init` 之前）。
    #[must_use]
    pub fn new() -> Self {
        Self::from_settings(V::default_settings(), false)
    }

    /// Mock 形态（**绝不联网**）。
    #[must_use]
    pub fn mocked() -> Self {
        let mut settings = V::default_settings();
        settings.mock = true;
        Self::from_settings(settings, true)
    }

    /// 由已构造的设置装配。
    #[must_use]
    pub fn from_settings(settings: AdapterSettings, mock_env: bool) -> Self {
        let mode = resolve_mode::<V>(&settings, mock_env);
        Self {
            core: AdapterCore {
                settings,
                mode,
                circuit: Mutex::new(CircuitSnapshot::default()),
                closed: false,
                mock_env,
                last: Mutex::new(super::LastCall::default()),
                windows: Mutex::new(BTreeMap::new()),
            },
            spec: PhantomData,
        }
    }

    /// 当前模式。
    #[must_use]
    pub const fn mode(&self) -> AdapterMode {
        self.core.mode
    }

    /// 当前设置（只读）。
    #[must_use]
    pub const fn settings(&self) -> &AdapterSettings {
        &self.core.settings
    }

    /// 是否已关闭。
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.core.closed
    }

    /// 熔断快照（拷贝；锁中毒时按"无失败"返回，不影响主流程）。
    #[must_use]
    pub fn circuit(&self) -> CircuitSnapshot {
        self.core.circuit.lock().map_or_else(|e| e.into_inner().clone(), |guard| guard.clone())
    }

    /// 写回熔断快照。
    pub(crate) fn store_circuit(&self, snapshot: CircuitSnapshot) {
        *self.core.circuit.lock().unwrap_or_else(PoisonError::into_inner) = snapshot;
    }

    /// 最近一次调用观测（拷贝）。
    #[must_use]
    fn last_call(&self) -> super::LastCall {
        let guard = self.core.last.lock().unwrap_or_else(PoisonError::into_inner);
        guard.clone()
    }

    /// 取增量窗口副本（不存在即空窗口 = 首轮全量）。
    #[must_use]
    pub(crate) fn pull_window(&self, resource: &str) -> IncrementalWindow {
        let guard = self.core.windows.lock().unwrap_or_else(PoisonError::into_inner);
        guard.get(resource).cloned().unwrap_or_default()
    }

    /// 写回增量窗口。
    pub(crate) fn store_pull_window(&self, resource: &str, window: IncrementalWindow) {
        let mut guard = self.core.windows.lock().unwrap_or_else(PoisonError::into_inner);
        guard.insert(resource.to_string(), window);
    }

    /// 构造候选设置（纯函数；**不修改自身**，失败即保持旧配置）。
    ///
    /// # Errors
    /// 配置存在但非法时返回 `DomainError::Config`。
    pub fn prepare_settings(&self, config: &AdapterConfig, lookup: &dyn SecretLookup) -> DomainResult<AdapterSettings> {
        let meta = V::metadata();
        let settings = AdapterSettings::from_config(&meta, config, lookup)?;
        let settings = settings.with_required_settings(V::REQUIRED_SETTINGS);
        V::validate_settings(&settings)?;
        Ok(settings)
    }

    /// 提交设置（不可失败）。
    pub fn commit_settings(&mut self, settings: AdapterSettings) {
        self.core.mode = resolve_mode::<V>(&settings, self.core.mock_env);
        self.core.settings = settings;
        self.core.closed = false;
        self.core.last = Mutex::new(super::LastCall::default());
    }

    /// 未配置错误（列出缺项，**不含凭据值**）。
    pub(crate) fn unconfigured_error(&self) -> DomainError {
        let missing = self.core.settings.missing_secrets();
        let missing_settings = self.core.settings.missing_settings();
        DomainError::Config(format!(
            "适配器 {} 未配置：缺少凭据 {:?} / 必需设置 {:?}；按降级行为不下发（{}）",
            V::NAME,
            missing,
            missing_settings,
            V::metadata().degradation
        ))
    }

    /// 健康记录。
    #[must_use]
    pub fn build_record(&self) -> AdapterHealthRecord {
        let meta = V::metadata();
        let circuit = self.circuit();
        let last = self.last_call();
        let status = evaluate_status(self.core.mode, V::REAL_TRANSPORT, circuit.state, circuit.consecutive_failures);
        AdapterHealthRecord {
            adapter: V::NAME.to_string(),
            status,
            configured: self.core.settings.is_configured() && V::is_configured(&self.core.settings),
            mocked: self.core.mode.is_mock(),
            requires_network: meta.requires_network,
            mode: self.core.mode,
            consecutive_failures: circuit.consecutive_failures,
            total_success: circuit.total_success,
            total_failure: circuit.total_failure,
            last_error: circuit.last_error.clone().or_else(|| last.error.clone()),
            latency_ms: last.latency_ms,
            last_attempts: last.attempts,
            circuit,
            capabilities: meta.capabilities.clone(),
            message: Some(self.status_message(&meta)),
            checked_at: Timestamp::now(),
        }
    }

    /// 面向运维的状态说明。
    pub(crate) fn status_message(&self, meta: &AdapterMetadata) -> String {
        match self.core.mode {
            AdapterMode::Mocked => MOCK_MESSAGE.to_string(),
            AdapterMode::Unconfigured => format!(
                "未配置：缺少凭据 {:?} / 必需设置 {:?}；降级行为——{}",
                self.core.settings.missing_secrets(),
                self.core.settings.missing_settings(),
                meta.degradation
            ),
            AdapterMode::Live => {
                if !V::REAL_TRANSPORT {
                    if V::TODO_ANCHOR.is_empty() {
                        format!("真实调用未实现：编码与契约已就绪，传输层待接入（{}）", meta.doc_anchor)
                    } else {
                        format!(
                            "真实调用未实现：TODO({})；编码与契约已就绪，传输层待接入（{}）",
                            V::TODO_ANCHOR,
                            meta.doc_anchor
                        )
                    }
                } else {
                    let circuit = self.circuit();
                    if circuit.state == agf_core::adapter::CircuitState::Open {
                        format!("熔断开路：{}", circuit.last_error.clone().unwrap_or_default())
                    } else {
                        format!("已启用真实调用通道（send + {} 语义）", semantics_summary(&meta.semantics))
                    }
                }
            }
        }
    }

    /// Mock 回执（确定性，不依赖任何真实配置）。
    pub(crate) fn mock_receipt(msg: &AdapterMessage, attempts: u32) -> AdapterReceipt {
        AdapterReceipt {
            adapter: V::NAME.to_string(),
            accepted: true,
            mocked: true,
            remote_id: Some(V::mock_remote_id(msg)),
            attempts,
            elapsed_ms: 0,
            origin: format!("mock://{}", V::NAME),
            delivered_at: Timestamp::now(),
        }
    }

    /// 统一包装：熔断检查 → 重试 → 计数（返回实际尝试次数）。
    ///
    /// 由 `&self` 承载：熔断快照**取副本 → 执行 → 写回**，锁不跨 `await`
    /// （因此 `Future` 仍是 `Send`，`async_trait` 的默认 `Send` 约束成立）。
    pub(crate) async fn invoke<T, F, Fut>(&self, op: F) -> (DomainResult<T>, u32)
    where
        F: FnMut(u32) -> Fut,
        Fut: Future<Output = DomainResult<T>>,
    {
        let breaker = self.core.settings.circuit;
        let retry = self.core.settings.retry;
        let mut snapshot = self.circuit();
        let counter = Arc::new(AtomicU32::new(0));
        let probe = Arc::clone(&counter);
        let mut op = op;
        let result = invoke_with_policy(V::NAME, &mut snapshot, &breaker, &retry, Timestamp::now(), move |attempt| {
            probe.fetch_add(1, Ordering::SeqCst);
            op(attempt)
        })
        .await;
        self.store_circuit(snapshot);
        (result, counter.load(Ordering::SeqCst))
    }

    /// 记录一次成功。
    pub(crate) fn note_success(&self, attempts: u32, elapsed_ms: u64) {
        let mut guard = self.core.last.lock().unwrap_or_else(PoisonError::into_inner);
        guard.error = None;
        guard.attempts = attempts;
        guard.latency_ms = Some(elapsed_ms);
    }

    /// 记录一次失败（脱敏需求：错误文本来自我们自己的构造，不含凭据）。
    pub(crate) fn note_failure(&self, error: &DomainError, attempts: u32, elapsed_ms: u64) {
        let mut guard = self.core.last.lock().unwrap_or_else(PoisonError::into_inner);
        guard.error = Some(error.to_string());
        guard.attempts = attempts;
        guard.latency_ms = Some(elapsed_ms);
    }

    /// 当前设置快照（`Arc`：供 `&self` 路径在 `'static` 闭包里使用）。
    pub(crate) fn settings_arc(&self) -> Arc<AdapterSettings> {
        Arc::new(self.core.settings.clone())
    }

    /// 已关闭检查（`push`/`pull`/`sync` 与 `send` 共用）。
    pub(crate) fn ensure_open(&self) -> DomainResult<()> {
        if self.core.closed {
            return Err(DomainError::PreconditionFailed(format!("适配器 {} 已关闭，请先重新 init", V::NAME)));
        }
        Ok(())
    }

    /// Live 路径：编码 → 熔断 + 重试 → 回执。
    pub(crate) async fn send_live(&self, msg: &AdapterMessage) -> DomainResult<AdapterReceipt> {
        let request = Arc::new(V::encode(msg, &self.core.settings)?);
        let masked_endpoint = request.masked_endpoint();
        let request_for_op = Arc::clone(&request);
        let settings_for_op = self.settings_arc();
        let started = std::time::Instant::now();
        let (result, attempts) = self
            .invoke(move |_attempt| {
                let req = Arc::clone(&request_for_op);
                let cfg = Arc::clone(&settings_for_op);
                async move { V::invoke_live(&req, &cfg).await }
            })
            .await;
        let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        match result {
            Ok(remote_id) => {
                self.note_success(attempts, elapsed_ms);
                Ok(AdapterReceipt {
                    adapter: V::NAME.to_string(),
                    accepted: true,
                    mocked: false,
                    remote_id,
                    attempts,
                    elapsed_ms,
                    origin: masked_endpoint,
                    delivered_at: Timestamp::now(),
                })
            }
            Err(error) => {
                self.note_failure(&error, attempts, elapsed_ms);
                Err(error)
            }
        }
    }

    /// 能力清单（测试与控制台复用）。
    #[must_use]
    pub fn capabilities(&self) -> Vec<AdapterCapability> {
        V::metadata().capabilities
    }
}

/// `push/pull/sync` 能力的一句话摘要（健康说明与能力矩阵共用）。
#[must_use]
pub fn semantics_summary(profile: &SemanticProfile) -> String {
    let mut implemented = Vec::new();
    let mut unsupported = Vec::new();
    for semantic in Semantic::ALL {
        if profile.is_implemented(semantic) {
            implemented.push(semantic.as_str());
        } else {
            unsupported.push(semantic.as_str());
        }
    }
    match (implemented.is_empty(), unsupported.is_empty()) {
        (true, _) => format!("{} 均不适用（Unsupported）", unsupported.join("/")),
        (false, true) => format!("{} 已实现", implemented.join("/")),
        (false, false) => format!("{} 已实现；{} 不适用（Unsupported）", implemented.join("/"), unsupported.join("/")),
    }
}
