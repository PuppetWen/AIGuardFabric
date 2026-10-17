//! 由 `cache.rs` 拆分：`impl_CachedResponse`/`cost_micro` 等 9 项（纯搬移，逻辑不变）。
use super::*;

impl CachedResponse {
    /// 由一次真实调用结果构造缓存条目。
    #[must_use]
    pub fn from_response(
        tenant: TenantId,
        fingerprint: impl Into<String>,
        endpoint: &ModelEndpoint,
        response: ChatResponse,
        ttl_secs: i64,
    ) -> Self {
        let saved_micro = cost_micro(endpoint, &response.usage);
        Self {
            tenant_id: tenant,
            request_fingerprint: fingerprint.into(),
            endpoint_id: endpoint.id,
            saved_prompt_tokens: response.usage.prompt_tokens,
            saved_micro,
            hits: 0,
            created_at: Timestamp::now(),
            expires_at_unix: Timestamp::now().unix_secs().saturating_add(ttl_secs),
            response,
        }
    }

    /// 是否已过期。
    #[must_use]
    pub fn is_expired_at(&self, now_unix: i64) -> bool {
        now_unix >= self.expires_at_unix
    }

    /// 命中时更新命中计数。
    pub fn record_hit(&mut self) {
        self.hits = self.hits.saturating_add(1);
    }
}

/// 计算一次调用在给定端点上的费用（微元，整数运算）。
///
/// Delegates to the gateway meter so cache reads and writes use one pricing rule.
#[must_use]
pub fn cost_micro(endpoint: &ModelEndpoint, usage: &Usage) -> u64 {
    crate::meter::breakdown(endpoint, usage).total_micro
}

/// 可缓存性判定（**纯函数，逐分支单测**）。
///
/// ## 规则
///
/// | 条件 | 可否缓存 | 理由 |
/// |---|---|---|
/// | `req.stream == true` | ❌ | 未捕获完整响应前不能写入；流式路径由网关显式累积后才写入（`req.stream` 置 false 的副本来写） |
/// | `temperature > 0`（且未显式 `allow`） | ❌ | 采样请求本就要求"每次不同"，缓存会破坏语义 |
/// | 含**有副作用**的工具（写文件/发请求/改配置…） | ❌ | 复用过期的工具调用结果可能导致重复或错序的副作用 |
/// | 数据分级为 `Restricted` 且端点非本地部署 | ❌ | 数据不出域：受限数据既不能出域，也不应把结果留在共享缓存 |
/// | 端点未启用 / `pricing` 无所谓 | ✅（其余条件满足时） | 由路由层保证只选启用端点 |
/// | 其它 | ✅ | 确定性、无副作用、数据分级允许 |
///
/// `allow_cache` 是调用方（[`crate::gateway::CallContext`]）的显式放行标记，
/// **只能豁免温度检查**，不能豁免数据分级与副作用检查——后两者是安全底线。
#[must_use]
pub fn is_cacheable(req: &ChatRequest, endpoint: &ModelEndpoint, allow_cache: bool) -> bool {
    // Native thinking/context edits and signed blocks are not represented by the canonical cache key.
    if req.anthropic_native.is_some() {
        return false;
    }
    // 1) 流式：网关在累积完成前不写缓存（累积完成后用非流式副本写入）
    if req.stream {
        return false;
    }
    // 2) 温度：确定性采样才允许复用
    if !allow_cache && req.temperature.is_some_and(|t| t > 0.0) {
        return false;
    }
    // 3) 副作用工具：不可复用（安全底线，allow_cache 不能豁免）
    if req.has_side_effecting_tools() {
        return false;
    }
    // 4) 数据不出域（安全底线，allow_cache 不能豁免）
    if !endpoint.accepts_data_class(data_class_of(req)) {
        return false;
    }
    true
}

/// 从请求元数据推断数据分级（缺省 `Internal`）。
#[must_use]
pub fn data_class_of(req: &ChatRequest) -> agf_core::enums::DataClass {
    req.data_class_hint().unwrap_or(agf_core::enums::DataClass::Internal)
}

/// 精确缓存键布局：`aigw:cache:{tenant_id}:{request_fingerprint}`。
///
/// 定义为自由函数（而非 [`SemanticCache`] 的关联函数）是**刻意**的：
/// 关联函数没有 `self` 参数会让 trait 失去 dyn 兼容性（无法 `Arc<dyn SemanticCache>`）。
#[must_use]
pub fn exact_cache_key(tenant: TenantId, fingerprint: &str) -> String {
    format!("aigw:cache:{tenant}:{fingerprint}")
}

impl CacheStats {
    /// 命中率（无请求时为 0）。
    #[must_use]
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 { 0.0 } else { self.hits as f64 / total as f64 }
    }
}

impl InMemorySemanticCache {
    /// 新建（默认容量与 TTL）。
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY, DEFAULT_TTL_SECS)
    }

    /// 指定容量与 TTL。
    #[must_use]
    pub fn with_capacity(capacity: usize, ttl_secs: i64) -> Self {
        let capacity = capacity.max(1);
        Self {
            inner: Arc::new(parking_lot::Mutex::new(MemoryInner {
                entries: HashMap::with_capacity(capacity.min(4096)),
                order: VecDeque::with_capacity(capacity.min(4096)),
                stats: CacheStats::default(),
            })),
            capacity,
            ttl_secs,
        }
    }

    /// 容量上限。
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// 统计快照。
    #[must_use]
    pub fn stats(&self) -> CacheStats {
        self.inner.lock().stats
    }

    /// 清空（测试与运维用）。
    pub fn clear(&self) {
        let mut guard = self.inner.lock();
        guard.entries.clear();
        guard.order.clear();
    }

    /// 清理过期条目，返回清理数量。
    pub fn evict_expired(&self, now_unix: i64) -> usize {
        let mut guard = self.inner.lock();
        let expired: Vec<String> =
            guard.entries.iter().filter(|(_, v)| v.is_expired_at(now_unix)).map(|(k, _)| k.clone()).collect();
        for key in &expired {
            guard.entries.remove(key);
            guard.order.retain(|k| k != key);
        }
        expired.len()
    }

    pub(crate) fn touch(order: &mut VecDeque<String>, key: &str) {
        order.retain(|k| k != key);
        order.push_back(key.to_string());
    }

    pub(crate) fn evict_oldest_if_needed(inner: &mut MemoryInner, capacity: usize) {
        while inner.entries.len() > capacity {
            let Some(oldest) = inner.order.pop_front() else { break };
            inner.entries.remove(&oldest);
        }
    }
}

impl Default for InMemorySemanticCache {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SemanticCache for InMemorySemanticCache {
    async fn get(&self, tenant: TenantId, fingerprint: &str) -> DomainResult<Option<CachedResponse>> {
        let key = exact_cache_key(tenant, fingerprint);
        let now = Timestamp::now().unix_secs();
        let mut guard = self.inner.lock();
        if guard.entries.get(&key).is_some_and(|e| e.is_expired_at(now)) {
            guard.entries.remove(&key);
            guard.order.retain(|k| k != &key);
        }
        match guard.entries.get_mut(&key) {
            Some(entry) => {
                entry.record_hit();
                let snapshot = entry.clone();
                guard.stats.hits = guard.stats.hits.saturating_add(1);
                guard.stats.saved_tokens = guard.stats.saved_tokens.saturating_add(snapshot.saved_prompt_tokens);
                guard.stats.saved_micro = guard.stats.saved_micro.saturating_add(snapshot.saved_micro);
                Self::touch(&mut guard.order, &key);
                Ok(Some(snapshot))
            }
            None => {
                guard.stats.misses = guard.stats.misses.saturating_add(1);
                Ok(None)
            }
        }
    }

    async fn put(&self, entry: CachedResponse, ttl_secs: i64) -> DomainResult<()> {
        let key = exact_cache_key(entry.tenant_id, &entry.request_fingerprint);
        let capacity = self.capacity;
        let mut guard = self.inner.lock();
        let mut entry = entry;
        if ttl_secs > 0 {
            entry.expires_at_unix = Timestamp::now().unix_secs().saturating_add(ttl_secs);
        } else {
            // 显式传入 TTL<=0：立即过期（"只读一次""禁用缓存"的语义）
            entry.expires_at_unix = Timestamp::now().unix_secs().saturating_sub(1);
        }
        guard.entries.insert(key.clone(), entry);
        Self::touch(&mut guard.order, &key);
        Self::evict_oldest_if_needed(&mut guard, capacity);
        debug!(entries = guard.entries.len(), "内存语义缓存写入");
        Ok(())
    }

    async fn invalidate(&self, tenant: TenantId, fingerprint: &str) -> DomainResult<()> {
        let key = exact_cache_key(tenant, fingerprint);
        let mut guard = self.inner.lock();
        guard.entries.remove(&key);
        guard.order.retain(|k| k != &key);
        Ok(())
    }

    fn hits(&self) -> u64 {
        self.inner.lock().stats.hits
    }

    fn misses(&self) -> u64 {
        self.inner.lock().stats.misses
    }

    fn saved_tokens(&self) -> u64 {
        self.inner.lock().stats.saved_tokens
    }

    fn saved_micro(&self) -> u64 {
        self.inner.lock().stats.saved_micro
    }

    fn len(&self) -> Option<usize> {
        Some(self.inner.lock().entries.len())
    }
}
