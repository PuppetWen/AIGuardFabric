//! 由 `registry.rs` 拆分：`AdapterRegistry`/`BroadcastOutcome`/`SubscriptionRule` 的实现（纯搬移，逻辑不变）。
use super::*;

impl SubscriptionRule {
    /// 全订阅规则。
    #[must_use]
    pub fn all(adapter: &str) -> Self {
        Self { adapter: adapter.to_string(), event_prefixes: vec!["*".to_string()], min_severity: None }
    }

    /// 设置事件前缀（链式）。
    #[must_use]
    pub fn with_prefixes(mut self, prefixes: &[&str]) -> Self {
        self.event_prefixes = prefixes.iter().map(|s| (*s).to_string()).collect();
        self
    }

    /// 设置最低等级（链式）。
    #[must_use]
    pub fn with_min_severity(mut self, severity: Severity) -> Self {
        self.min_severity = Some(severity);
        self
    }

    /// 是否命中（仅看规则本身；适配器自身订阅规则另由 [`VendorAdapter::subscribes`] 判定）。
    #[must_use]
    pub fn matches(&self, msg: &AdapterMessage) -> bool {
        msg.matches_prefix(&self.event_prefixes) && msg.meets_severity(self.min_severity)
    }
}

impl BroadcastOutcome {
    /// 是否成功。
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.result.is_ok()
    }

    /// 错误文本（成功时为 `None`）。
    #[must_use]
    pub fn error_text(&self) -> Option<String> {
        self.result.as_ref().err().map(ToString::to_string)
    }
}

impl std::fmt::Debug for AdapterRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdapterRegistry")
            .field("tenant_id", &self.tenant_id)
            .field("mock_mode", &self.mock_mode)
            .field("adapters", &self.entries.keys().collect::<Vec<_>>())
            .field("enabled", &self.entries.iter().map(|(k, v)| (k.as_str(), v.enabled)).collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl AdapterRegistry {
    /// 新建空注册表（凭据来自 `AGF_ADAPTER_<NAME>_<KEY>` 环境变量）。
    #[must_use]
    pub fn new(tenant_id: TenantId, mock_mode: bool) -> Self {
        Self { tenant_id, mock_mode, secrets: Arc::new(EnvSecrets::platform_default()), entries: BTreeMap::new() }
    }

    /// 覆盖凭据解析口（生产注入 `credentials` 表解析器，测试注入内存凭据）。
    #[must_use]
    pub fn with_secrets(mut self, secrets: Arc<dyn SecretLookup>) -> Self {
        self.secrets = secrets;
        self
    }
    /// 无凭据环境的默认值：登记全部内置适配器并进入 Mock（**零配置可用**）。
    ///
    /// # Errors
    /// 内置适配器注册名冲突（不应发生）时返回 `Conflict`。
    pub fn mock_only(tenant_id: TenantId) -> DomainResult<Self> {
        let mut registry = Self::new(tenant_id, true);
        registry.register_builtin()?;
        Ok(registry)
    }

    /// 登记全部内置适配器，返回登记数量。
    ///
    /// # Errors
    /// 任何注册名冲突时返回 `DomainError::Conflict`。
    pub fn register_builtin(&mut self) -> DomainResult<usize> {
        let mut count = 0;
        for adapter in crate::vendors::builtin() {
            self.register_boxed(adapter)?;
            count += 1;
        }
        Ok(count)
    }

    /// 登记一个适配器（返回注册名）。
    ///
    /// # Errors
    /// 注册名已存在时返回 `DomainError::Conflict`。
    pub fn register<V: VendorSpec>(&mut self) -> DomainResult<String> {
        self.register_boxed(Box::new(crate::vendor::VendorAdapterImpl::<V>::new()))
    }

    /// 登记一个已构造的适配器（返回注册名）。
    ///
    /// 注册表处于 Mock 模式（`AGF_MOCK_MODE=1` / [`Self::mock_only`]）时，
    /// 登记即把适配器**强制**切到 Mock（零配置可用，且后续 `apply_config` 也不会离开 Mock）。
    ///
    /// # Errors
    /// 注册名已存在时返回 `DomainError::Conflict`。
    pub fn register_boxed(&mut self, mut adapter: Box<dyn VendorAdapter>) -> DomainResult<String> {
        let name = adapter.name().to_string();
        if self.entries.contains_key(&name) {
            return Err(DomainError::Conflict(format!("适配器 {name} 已登记（同类型只允许一个实例）")));
        }
        if self.mock_mode {
            adapter.force_mock();
        }
        // 元信息是静态的：登记时缓存一份，供控制台无锁读取
        let metadata = adapter.metadata();
        // 登记即可用：是否真正下发由 `enabled`（配置里的热插拔开关）与实际模式共同决定
        let enabled = true;
        self.entries.insert(
            name.clone(),
            Entry { handle: Arc::new(Mutex::new(adapter)), enabled, rule: SubscriptionRule::all(&name), metadata },
        );
        Ok(name)
    }

    /// 适配器元信息（厂商 / 版本 / 能力清单 / 是否需要网络）。
    #[must_use]
    pub fn metadata(&self, name: &str) -> Option<AdapterMetadata> {
        self.entries.get(name).map(|e| e.metadata.clone())
    }

    /// 全部元信息。
    #[must_use]
    pub fn metadata_all(&self) -> Vec<AdapterMetadata> {
        self.entries.values().map(|e| e.metadata.clone()).collect()
    }

    /// `agf_core::adapter::AdapterDescriptor` 视图（控制台"接入管理"页无锁读取）。
    #[must_use]
    pub fn core_descriptor(&self, name: &str) -> Option<AdapterDescriptor> {
        self.entries.get(name).map(|e| e.metadata.to_descriptor())
    }

    /// `agf_core::adapter::AdapterHealth` 视图（平台统一契约的健康形态）。
    ///
    /// # Errors
    /// 适配器未登记 → `NotFound`；健康探测本身失败 → 适配器返回的错误。
    pub async fn core_health(&self, name: &str) -> DomainResult<agf_core::adapter::AdapterHealth> {
        let handle = self
            .entries
            .get(name)
            .map(|e| Arc::clone(&e.handle))
            .ok_or_else(|| DomainError::NotFound { entity: "adapter", id: name.to_string() })?;
        let guard = handle.lock().await;
        guard.health().await
    }

    /// 注册名清单（字典序）。
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        self.entries.keys().cloned().collect()
    }

    /// 已登记数量。
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 是否已登记某适配器。
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.entries.contains_key(name)
    }

    /// 取适配器句柄。
    #[must_use]
    pub fn handle(&self, name: &str) -> Option<AdapterHandle> {
        self.entries.get(name).map(|e| Arc::clone(&e.handle))
    }

    /// 是否处于 Mock 模式。
    #[must_use]
    pub const fn mock_mode(&self) -> bool {
        self.mock_mode
    }

    /// 租户。
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// 全部描述符（控制台"接入管理"页数据源）。
    #[must_use]
    pub fn descriptors(&self) -> Vec<AdapterDescriptor> {
        self.entries.values().filter_map(|e| e.handle.try_lock().ok().map(|g| g.descriptor())).collect()
    }

    /// 是否启用。
    #[must_use]
    pub fn is_enabled(&self, name: &str) -> Option<bool> {
        self.entries.get(name).map(|e| e.enabled)
    }

    /// 启停（热插拔开关）。返回是否发生变化。
    ///
    /// # Errors
    /// 适配器未登记时返回 `NotFound`。
    pub fn set_enabled(&mut self, name: &str, enabled: bool) -> DomainResult<bool> {
        let entry = self
            .entries
            .get_mut(name)
            .ok_or_else(|| DomainError::NotFound { entity: "adapter", id: name.to_string() })?;
        let changed = entry.enabled != enabled;
        entry.enabled = enabled;
        Ok(changed)
    }

    /// 读取订阅规则。
    #[must_use]
    pub fn rule(&self, name: &str) -> Option<&SubscriptionRule> {
        self.entries.get(name).map(|e| &e.rule)
    }

    /// 设置订阅规则。
    ///
    /// # Errors
    /// 适配器未登记、前缀为空、规则归属与参数不一致时返回错误。
    pub fn subscribe(&mut self, rule: SubscriptionRule) -> DomainResult<()> {
        if rule.event_prefixes.is_empty() {
            return Err(DomainError::Validation(format!("适配器 {} 的订阅前缀不得为空", rule.adapter)));
        }
        let entry = self
            .entries
            .get_mut(&rule.adapter)
            .ok_or_else(|| DomainError::NotFound { entity: "adapter", id: rule.adapter.clone() })?;
        entry.rule = rule;
        Ok(())
    }

    /// 配置热替换：**失败保持旧配置**（`prepare` 纯校验通过后才 `commit`）。
    ///
    /// # Errors
    /// 适配器未登记（`NotFound`）、配置非法（`Config`）、路由覆盖项非法时返回错误。
    pub async fn apply_config(&mut self, config: &AdapterConfig) -> DomainResult<()> {
        // ① 路由覆盖项先做纯校验（保证"整体失败则整体不变"）
        let update = Self::rule_update(config)?;
        // ② 句柄先克隆，避免持有 self.entries 的借用
        let handle = self
            .entries
            .get(&config.adapter)
            .map(|e| Arc::clone(&e.handle))
            .ok_or_else(|| DomainError::NotFound { entity: "adapter", id: config.adapter.clone() })?;
        {
            let mut guard = handle.lock().await;
            let candidate = guard.prepare(config, self.secrets.as_ref())?;
            guard.commit(candidate);
        }
        if let Some(entry) = self.entries.get_mut(&config.adapter) {
            entry.enabled = config.enabled;
            if let Some(prefixes) = update.prefixes {
                entry.rule.event_prefixes = prefixes;
            }
            if let Some(min) = update.min_severity {
                entry.rule.min_severity = Some(min);
            }
        }
        Ok(())
    }

    /// 批量应用配置：未登记的配置计入 `skipped`，单个非法配置不阻断其余。
    ///
    /// # Errors
    /// 仅当内部状态损坏（不应发生）时返回错误；单适配器失败记入报告。
    pub async fn init_all(&mut self, configs: &[AdapterConfig]) -> DomainResult<InitReport> {
        let mut report = InitReport::default();
        for config in configs {
            if !self.contains(&config.adapter) {
                report.skipped += 1;
                continue;
            }
            match self.apply_config(config).await {
                Ok(()) => report.applied += 1,
                Err(error) => {
                    report.failed.push(FailureNote { adapter: config.adapter.clone(), error: error.to_string() });
                }
            }
        }
        Ok(report)
    }

    /// 事件路由：启用 + 订阅规则命中 + 适配器自身订阅规则命中。
    ///
    /// 采用 `try_lock`：某个适配器正在下发时该轮**跳过**它（不阻塞其它适配器），
    /// 下一次广播会重新命中——这是"路由不阻塞主流程"的实现取舍。
    pub async fn route(&self, msg: &AdapterMessage) -> Vec<String> {
        let mut matched = Vec::new();
        for (name, entry) in &self.entries {
            if !entry.enabled || !entry.rule.matches(msg) {
                continue;
            }
            let Ok(guard) = entry.handle.try_lock() else { continue };
            if !guard.subscribes(msg) {
                continue;
            }
            matched.push(name.clone());
        }
        matched
    }

    /// 向指定适配器下发。
    ///
    /// # Errors
    /// 适配器未登记 → `NotFound`；已禁用 → `PreconditionFailed`；其余为适配器自身错误。
    pub async fn send_to(&self, name: &str, msg: &AdapterMessage) -> DomainResult<AdapterReceipt> {
        let entry =
            self.entries.get(name).ok_or_else(|| DomainError::NotFound { entity: "adapter", id: name.to_string() })?;
        if !entry.enabled {
            return Err(DomainError::PreconditionFailed(format!("适配器 {name} 已禁用")));
        }
        let handle = Arc::clone(&entry.handle);
        let mut guard = handle.lock().await;
        guard.send(msg).await
    }

    /// 广播：按 [`Self::route`] 逐适配器下发，单个失败不影响其它。
    pub async fn broadcast(&self, msg: &AdapterMessage) -> Vec<BroadcastOutcome> {
        let names = self.route(msg).await;
        let mut outcomes = Vec::with_capacity(names.len());
        for name in names {
            let result = self.send_to(&name, msg).await;
            outcomes.push(BroadcastOutcome { adapter: name, result });
        }
        outcomes
    }

    /// 全部健康记录（含未启用适配器；按注册名字典序）。
    pub async fn health_all(&self) -> Vec<AdapterHealthRecord> {
        let mut records = Vec::with_capacity(self.entries.len());
        for entry in self.entries.values() {
            let handle = Arc::clone(&entry.handle);
            let guard = handle.lock().await;
            if let Ok(record) = guard.health_check().await {
                records.push(record);
            }
        }
        records
    }

    /// 健康记录（按名索引）。
    pub async fn health_map(&self) -> BTreeMap<String, AdapterHealthRecord> {
        self.health_all().await.into_iter().map(|r| (r.adapter.clone(), r)).collect()
    }

    /// 关闭全部适配器（幂等）。返回关闭数量。
    pub async fn close_all(&self) -> usize {
        let mut count = 0;
        for entry in self.entries.values() {
            let handle = Arc::clone(&entry.handle);
            let mut guard = handle.lock().await;
            if guard.close().await.is_ok() {
                count += 1;
            }
        }
        count
    }

    /// 从配置解析路由覆盖项。
    pub(crate) fn rule_update(config: &AdapterConfig) -> DomainResult<RuleUpdate> {
        let mut update = RuleUpdate::default();
        if let Some(value) = config.settings.get("event_prefixes") {
            let array = value.as_array().ok_or_else(|| {
                DomainError::Config(format!("适配器 {} 的 event_prefixes 必须是数组", config.adapter))
            })?;
            let mut prefixes = Vec::with_capacity(array.len());
            for item in array {
                let prefix = item.as_str().ok_or_else(|| {
                    DomainError::Config(format!("适配器 {} 的 event_prefixes 元素必须是字符串", config.adapter))
                })?;
                if prefix.trim().is_empty() {
                    return Err(DomainError::Config(format!(
                        "适配器 {} 的 event_prefixes 不得含空白项",
                        config.adapter
                    )));
                }
                prefixes.push(prefix.to_string());
            }
            if prefixes.is_empty() {
                return Err(DomainError::Config(format!("适配器 {} 的 event_prefixes 不得为空数组", config.adapter)));
            }
            update.prefixes = Some(prefixes);
        }
        if let Some(text) = config.get_str("min_severity") {
            let severity = Severity::parse(text)
                .map_err(|e| DomainError::Config(format!("适配器 {} 的 min_severity 非法: {e}", config.adapter)))?;
            update.min_severity = Some(severity);
        }
        Ok(update)
    }
}
