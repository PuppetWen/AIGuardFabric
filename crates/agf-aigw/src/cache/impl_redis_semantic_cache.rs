//! 由 `cache.rs` 拆分：`impl_RedisSemanticCache`/`impl_RedisSemanticCache` 等 9 项（纯搬移，逻辑不变）。
use super::*;

impl RedisSemanticCache {
    /// 由已连接的 `RedisStore` 构造。
    #[must_use]
    pub fn new(store: RedisStore) -> Self {
        Self { store, stats: Arc::new(parking_lot::Mutex::new(CacheStats::default())) }
    }

    /// 统计快照。
    #[must_use]
    pub fn stats(&self) -> CacheStats {
        *self.stats.lock()
    }

    /// 底层 Redis 句柄。
    #[must_use]
    pub const fn store(&self) -> &RedisStore {
        &self.store
    }
}

#[async_trait]
impl SemanticCache for RedisSemanticCache {
    async fn get(&self, tenant: TenantId, fingerprint: &str) -> DomainResult<Option<CachedResponse>> {
        let key = self.store.key(&["aigw", "cache", &tenant.to_string(), fingerprint]);
        let entry: Option<CachedResponse> = self.store.get_json(&key).await?;
        let mut stats = self.stats.lock();
        match entry {
            Some(mut e) => {
                e.record_hit();
                stats.hits = stats.hits.saturating_add(1);
                stats.saved_tokens = stats.saved_tokens.saturating_add(e.saved_prompt_tokens);
                stats.saved_micro = stats.saved_micro.saturating_add(e.saved_micro);
                Ok(Some(e))
            }
            None => {
                stats.misses = stats.misses.saturating_add(1);
                Ok(None)
            }
        }
    }

    async fn put(&self, entry: CachedResponse, ttl_secs: i64) -> DomainResult<()> {
        let key = self.store.key(&["aigw", "cache", &entry.tenant_id.to_string(), &entry.request_fingerprint]);
        let ttl = if ttl_secs > 0 { ttl_secs } else { DEFAULT_TTL_SECS };
        self.store.set_json(&key, &entry, Some(ttl)).await
    }

    async fn invalidate(&self, tenant: TenantId, fingerprint: &str) -> DomainResult<()> {
        let key = self.store.key(&["aigw", "cache", &tenant.to_string(), fingerprint]);
        self.store.del(&key).await
    }

    fn hits(&self) -> u64 {
        self.stats.lock().hits
    }

    fn misses(&self) -> u64 {
        self.stats.lock().misses
    }

    fn saved_tokens(&self) -> u64 {
        self.stats.lock().saved_tokens
    }

    fn saved_micro(&self) -> u64 {
        self.stats.lock().saved_micro
    }

    fn len(&self) -> Option<usize> {
        None
    }
}

impl ExactCache {
    /// 仅内存（Redis 不可用时）。
    #[must_use]
    pub fn memory() -> Self {
        Self { primary: None, fallback: InMemorySemanticCache::new() }
    }

    /// Redis 为主 + 内存兜底。
    #[must_use]
    pub fn with_redis(redis: RedisSemanticCache) -> Self {
        Self { primary: Some(Arc::new(redis)), fallback: InMemorySemanticCache::new() }
    }

    /// 内存缓存（只读引用，用于统计）。
    #[must_use]
    pub const fn memory_layer(&self) -> &InMemorySemanticCache {
        &self.fallback
    }

    /// 是否接了 Redis。
    #[must_use]
    pub const fn has_redis(&self) -> bool {
        self.primary.is_some()
    }

    /// 是否为空（两层都空）。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fallback.is_empty()
    }
}

#[async_trait]
impl SemanticCache for ExactCache {
    async fn get(&self, tenant: TenantId, fingerprint: &str) -> DomainResult<Option<CachedResponse>> {
        if let Some(primary) = &self.primary {
            match primary.get(tenant, fingerprint).await {
                Ok(Some(hit)) => {
                    // 回填内存层，降低后续抖动影响
                    let _ = self.fallback.put(hit.clone(), DEFAULT_TTL_SECS).await;
                    return Ok(Some(hit));
                }
                Ok(None) => {}
                Err(e) => {
                    debug!(error = %e, "Redis 语义缓存读取失败，回退内存层");
                }
            }
        }
        self.fallback.get(tenant, fingerprint).await
    }

    async fn put(&self, entry: CachedResponse, ttl_secs: i64) -> DomainResult<()> {
        if let Some(primary) = &self.primary {
            if let Err(e) = primary.put(entry.clone(), ttl_secs).await {
                debug!(error = %e, "Redis 语义缓存写入失败（不影响主流程）");
            }
        }
        self.fallback.put(entry, ttl_secs).await
    }

    async fn invalidate(&self, tenant: TenantId, fingerprint: &str) -> DomainResult<()> {
        if let Some(primary) = &self.primary {
            primary.invalidate(tenant, fingerprint).await?;
        }
        self.fallback.invalidate(tenant, fingerprint).await
    }

    fn hits(&self) -> u64 {
        self.primary.as_ref().map_or(0, |p| p.hits()) + self.fallback.hits()
    }

    fn misses(&self) -> u64 {
        self.primary.as_ref().map_or(0, |p| p.misses()) + self.fallback.misses()
    }

    fn saved_tokens(&self) -> u64 {
        self.primary.as_ref().map_or(0, |p| p.saved_tokens()) + self.fallback.saved_tokens()
    }

    fn saved_micro(&self) -> u64 {
        self.primary.as_ref().map_or(0, |p| p.saved_micro()) + self.fallback.saved_micro()
    }

    fn len(&self) -> Option<usize> {
        self.fallback.len()
    }
}

/// 允许实现声明默认 TTL（供网关写入时使用）。
impl InMemorySemanticCache {
    /// 默认 TTL（秒）。
    #[must_use]
    pub const fn default_ttl_secs(&self) -> i64 {
        self.ttl_secs
    }
}

/// 便捷：请求指纹 + 端点 + 数据分级三者一致才允许写缓存（网关调用点复用）。
#[must_use]
pub fn should_write_cache(
    req: &ChatRequest,
    endpoint: &ModelEndpoint,
    allow_cache: bool,
    response: &ChatResponse,
) -> bool {
    is_cacheable(req, endpoint, allow_cache)
        && response.finish_reason != FinishReason::ContentFilter
        && !response.message.content.is_empty()
        && response.usage.prompt_tokens > 0
}

/// 计算"如果这次真调用了会花多少钱"（缓存命中节省额）。
#[must_use]
pub fn would_cost_micro(endpoint: &ModelEndpoint, usage: &Usage) -> u64 {
    cost_micro(endpoint, usage)
}

/// 估算 Duration（TTL 检查的辅助函数，供测试与上层复用）。
#[must_use]
pub fn ttl_duration(ttl_secs: i64) -> Duration {
    if ttl_secs <= 0 { Duration::ZERO } else { Duration::from_secs(u64::try_from(ttl_secs).unwrap_or(u64::MAX)) }
}

impl MonotonicClock {
    /// 起始计时。
    #[must_use]
    pub fn start() -> Self {
        Self { origin: Instant::now() }
    }

    /// 已流逝秒数。
    #[must_use]
    pub fn elapsed_secs(&self) -> u64 {
        self.origin.elapsed().as_secs()
    }
}
