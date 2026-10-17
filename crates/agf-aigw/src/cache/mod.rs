//! 语义缓存：精确指纹缓存（内存 / Redis）+ 可缓存性判定。
//!
//! ## 两级缓存的定位
//!
//! - **精确指纹缓存**（本模块 `ExactCache` 路径）：请求指纹（
//!   [`crate::wire::ChatRequest::fingerprint`]）完全一致才命中，**零误判**；
//! - **向量相似度缓存**（embedding 相似度）：需要本地 embedding 模型，
//!   本 crate 只保留 [`SemanticCacheEntry`]（`agf-core` 定义）的检索接口位，
//!   真实相似度检索由 `agf-storage`/向量库承担（已登记待验证项）。
//!
//! ## 为什么必须严格限制"什么能缓存"
//!
//! 缓存命中意味着**跳过真实模型调用**，这在安全治理平台里是"语义改变"：
//! 如果请求带温度采样、带副作用工具、或属于"数据不出域"的受限数据，
//! 复用历史回复会产生**不可接受的安全后果**。因此可缓存性判定被抽成纯函数
//! [`is_cacheable`]，并逐分支单测。
//!
//! ## 缓存键布局
//!
//! ```text
//! {prefix}:aigw:cache:{tenant_id}:{request_fingerprint}
//! ```
//! 租户前缀确保多租户共用 Redis 实例时不串号（与 `agf-storage` 的键约定一致）。

pub(crate) use std::collections::HashMap;
pub(crate) use std::collections::VecDeque;

pub(crate) use std::sync::Arc;

pub(crate) use std::time::Duration;
pub(crate) use std::time::Instant;

pub(crate) use agf_core::error::DomainResult;

pub(crate) use agf_core::ids::Id;
pub(crate) use agf_core::ids::TenantId;

pub(crate) use agf_core::model::ModelEndpoint;

pub(crate) use agf_core::time::Timestamp;

pub(crate) use async_trait::async_trait;

pub(crate) use serde::Deserialize;
pub(crate) use serde::Serialize;

pub(crate) use tracing::debug;

pub(crate) use agf_storage::redis_store::RedisStore;

pub(crate) use crate::wire::ChatRequest;
pub(crate) use crate::wire::ChatResponse;
pub(crate) use crate::wire::FinishReason;
pub(crate) use crate::wire::Usage;

#[cfg(test)]
pub(crate) use crate::wire::ChatMessage;
#[cfg(test)]
pub(crate) use crate::wire::ToolDefinition;

#[cfg(test)]
pub(crate) use agf_core::enums::DataClass;

#[cfg(test)]
pub(crate) use agf_core::model::Modality;
#[cfg(test)]
pub(crate) use agf_core::model::ModelPricing;

#[cfg(test)]
pub(crate) use pretty_assertions::assert_eq as eq;

#[cfg(test)]
pub(crate) use serde_json::json;

#[allow(unused_imports)]
pub use impl_cached_response::*;
#[allow(unused_imports)]
pub use impl_redis_semantic_cache::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 默认缓存条目容量（内存实现）。
pub const DEFAULT_CAPACITY: usize = 512;

/// 默认缓存 TTL（秒）。
pub const DEFAULT_TTL_SECS: i64 = 900;

/// 一条缓存回复。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedResponse {
    /// 租户。
    pub tenant_id: TenantId,
    /// 请求指纹。
    pub request_fingerprint: String,
    /// 命中的模型端点 id。
    pub endpoint_id: Id,
    /// 缓存的完整回复。
    pub response: ChatResponse,
    /// 该次真实调用消耗的输入 token（用于统计"省了多少"）。
    pub saved_prompt_tokens: u64,
    /// 该次真实调用花的钱（微元）。
    pub saved_micro: u64,
    /// 命中次数。
    pub hits: u64,
    /// 写入时间。
    pub created_at: Timestamp,
    /// 过期时刻（Unix 秒）。
    pub expires_at_unix: i64,
}

/// 语义缓存契约。
///
/// 实现必须满足：**任何错误都不得让主流程失败**——缓存是加速器，不是依赖。
/// 因此实现内部应把 Redis 故障降级为"未命中"（`agf-storage::RedisStore` 已如此处理）。
#[async_trait]
pub trait SemanticCache: Send + Sync + std::fmt::Debug {
    /// 读取缓存（返回副本；命中计数由实现内部维护）。
    ///
    /// # Errors
    /// 仅在"缓存内容损坏到无法判定"时返回错误；网络/连接问题应降级为 `Ok(None)`。
    async fn get(&self, tenant: TenantId, fingerprint: &str) -> DomainResult<Option<CachedResponse>>;

    /// 写入缓存。
    ///
    /// # Errors
    /// 序列化失败；网络问题应降级为 `Ok(())`。
    async fn put(&self, entry: CachedResponse, ttl_secs: i64) -> DomainResult<()>;

    /// 失效单个条目。
    ///
    /// # Errors
    /// 网络问题应降级为 `Ok(())`。
    async fn invalidate(&self, tenant: TenantId, fingerprint: &str) -> DomainResult<()>;

    /// 累计命中次数。
    fn hits(&self) -> u64;

    /// 累计未命中次数。
    fn misses(&self) -> u64;

    /// 累计节省的输入 token。
    fn saved_tokens(&self) -> u64;

    /// 累计节省的金额（微元）。
    fn saved_micro(&self) -> u64;

    /// 当前条目数（Redis 实现返回 `None`，因为不扫描键空间）。
    fn len(&self) -> Option<usize>;

    /// 缓存是否为空（`None` 表示未知，按非空处理）。
    fn is_empty(&self) -> bool {
        self.len() == Some(0)
    }
}

/// 缓存统计（命中/未命中/节省量）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheStats {
    /// 命中次数。
    pub hits: u64,
    /// 未命中次数。
    pub misses: u64,
    /// 节省的输入 token。
    pub saved_tokens: u64,
    /// 节省的金额（微元）。
    pub saved_micro: u64,
}

/// 内存语义缓存（TTL + 近似 LRU 淘汰）。
///
/// 用途：
/// 1. 单机/离线演示（无 Redis 也能演示"缓存命中省成本"）；
/// 2. Redis 故障时的降级层（网关可用 [`ExactCache::memory`] 直接构造）。
#[derive(Debug)]
pub struct InMemorySemanticCache {
    inner: Arc<parking_lot::Mutex<MemoryInner>>,
    capacity: usize,
    ttl_secs: i64,
}

#[derive(Debug, Default)]
pub(crate) struct MemoryInner {
    entries: HashMap<String, CachedResponse>,
    /// 访问顺序（队首最旧）。
    order: VecDeque<String>,
    stats: CacheStats,
}

/// Redis 语义缓存（多实例共享，Redis 故障自动降级为未命中）。
#[derive(Debug, Clone)]
pub struct RedisSemanticCache {
    store: RedisStore,
    stats: Arc<parking_lot::Mutex<CacheStats>>,
}

/// 双写缓存：Redis 为主、内存为兜底。
///
/// 用途：Redis 抖动时仍然能在本进程内命中（避免"一次抖动 = 全部击穿"）。
#[derive(Debug)]
pub struct ExactCache {
    primary: Option<Arc<dyn SemanticCache>>,
    fallback: InMemorySemanticCache,
}

/// 进程启动后的单调计时（内存 TTL 用，避免墙钟回拨导致的误判）。
#[derive(Debug, Clone, Copy)]
pub struct MonotonicClock {
    origin: Instant,
}

mod impl_cached_response;
mod impl_redis_semantic_cache;
#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod tests;
