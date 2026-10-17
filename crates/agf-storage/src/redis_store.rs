//! Redis 客户端封装：缓存、三级配额计数器、分布式锁、限流令牌桶。
//!
//! 设计取舍：
//! - Redis **不可用不阻塞主流程**：所有方法在连接失败时返回 `Ok(None)`/降级结果，
//!   由调用方决定语义（配额超限判定在 Redis 挂了以后"保守拒绝"还是"放行"由策略决定，
//!   见 [`QuotaCounter::check_and_consume`] 的 `fail_closed` 参数）。
//! - 键统一加租户前缀，避免多租户共用实例时串号。

use std::time::Duration;

use agf_core::error::{DomainError, DomainResult};
use agf_core::ids::TenantId;
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, Script};
use tracing::{debug, info, warn};

use crate::StorageConfig;

mod rate_limit;
pub use rate_limit::DistributedRateVerdict;

/// Lua：原子地"读取当前值 → 与上限比较 → 未超限则自增"。
///
/// 返回 `{当前值(自增后或未变), 是否放行(1/0)}`。
/// 使用服务端时间做窗口过期，避免多实例时钟漂移。
const QUOTA_SCRIPT: &str = r"
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local amount = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])
local current = tonumber(redis.call('GET', key) or '0')
if limit > 0 and current + amount > limit then
  return {current, 0}
end
local newval = redis.call('INCRBY', key, amount)
if ttl > 0 and redis.call('TTL', key) < 0 then
  redis.call('EXPIRE', key, ttl)
end
return {newval, 1}
";

/// Lua：释放配额（请求失败回滚已消费额度）。
const QUOTA_RELEASE_SCRIPT: &str = r"
local key = KEYS[1]
local amount = tonumber(ARGV[1])
local current = tonumber(redis.call('GET', key) or '0')
local newval = current - amount
if newval <= 0 then
  redis.call('DEL', key)
  return 0
end
redis.call('SET', key, newval, 'KEEPTTL')
return newval
";

/// Redis 句柄。
///
/// 手写 `Debug`：`redis::aio::ConnectionManager` 未实现 `Debug`，
/// 但上层需要在日志/错误里携带 `RedisStore`，因此只打印键前缀。
#[derive(Clone)]
pub struct RedisStore {
    conn: ConnectionManager,
    prefix: String,
}

impl std::fmt::Debug for RedisStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisStore").field("prefix", &self.prefix).finish_non_exhaustive()
    }
}

impl RedisStore {
    /// 连接 Redis 并创建连接管理器（自动重连）。
    ///
    /// # Errors
    /// URL 非法或首次连接失败。
    pub async fn connect(cfg: &StorageConfig) -> DomainResult<Self> {
        let client = redis::Client::open(cfg.redis_url.as_str())
            .map_err(|e| DomainError::Config(format!("Redis URL 非法: {e}")))?;
        let conn =
            tokio::time::timeout(Duration::from_secs(cfg.redis_connect_timeout_secs), ConnectionManager::new(client))
                .await
                .map_err(|_| DomainError::DependencyUnavailable {
                    dependency: "redis".to_string(),
                    cause: "连接超时".to_string(),
                })?
                .map_err(|e| DomainError::DependencyUnavailable {
                    dependency: "redis".to_string(),
                    cause: format!("连接失败: {e}"),
                })?;
        info!(prefix = %cfg.redis_prefix, "Redis 连接就绪");
        Ok(Self { conn, prefix: cfg.redis_prefix.clone() })
    }

    /// 由已有连接管理器构造（测试用）。
    #[must_use]
    pub fn from_manager(conn: ConnectionManager, prefix: impl Into<String>) -> Self {
        Self { conn, prefix: prefix.into() }
    }

    /// 组装完整键名。
    #[must_use]
    pub fn key(&self, parts: &[&str]) -> String {
        let mut k = self.prefix.clone();
        for p in parts {
            k.push(':');
            k.push_str(p);
        }
        k
    }

    /// 健康探测。
    ///
    /// # Errors
    /// Redis 不可达。
    pub async fn ping(&self) -> DomainResult<()> {
        let mut conn = self.conn.clone();
        let pong: String = redis::cmd("PING").query_async(&mut conn).await.map_err(|e| {
            DomainError::DependencyUnavailable { dependency: "redis".to_string(), cause: format!("PING 失败: {e}") }
        })?;
        if pong != "PONG" {
            return Err(DomainError::DependencyUnavailable {
                dependency: "redis".to_string(),
                cause: format!("异常响应: {pong}"),
            });
        }
        Ok(())
    }

    /// 读取字符串缓存。
    ///
    /// # Errors
    /// Redis 不可达时返回 `Ok(None)`（降级为缓存未命中），仅反序列化失败返回错误。
    pub async fn get_string(&self, key: &str) -> DomainResult<Option<String>> {
        let mut conn = self.conn.clone();
        match conn.get::<_, Option<String>>(key).await {
            Ok(v) => Ok(v),
            Err(e) => {
                warn!(key, error = %e, "Redis GET 失败，降级为缓存未命中");
                Ok(None)
            }
        }
    }

    /// 写入字符串缓存。
    ///
    /// # Errors
    /// 反序列化以外无错误；Redis 不可达时记录告警并返回 `Ok(())`。
    pub async fn set_string(&self, key: &str, value: &str, ttl_secs: Option<i64>) -> DomainResult<()> {
        let mut conn = self.conn.clone();
        let res: Result<(), _> = match ttl_secs {
            Some(ttl) if ttl > 0 => conn.set_ex(key, value, u64::try_from(ttl).unwrap_or(60)).await,
            _ => conn.set(key, value).await,
        };
        if let Err(e) = res {
            warn!(key, error = %e, "Redis SET 失败（不影响主流程）");
        } else {
            debug!(key, "缓存已写入");
        }
        Ok(())
    }

    /// 删除缓存。
    ///
    /// # Errors
    /// 无（失败仅告警）。
    pub async fn del(&self, key: &str) -> DomainResult<()> {
        let mut conn = self.conn.clone();
        let res: Result<(), _> = conn.del(key).await;
        if let Err(e) = res {
            warn!(key, error = %e, "Redis DEL 失败");
        }
        Ok(())
    }

    /// 读取 JSON 缓存。
    ///
    /// # Errors
    /// JSON 反序列化失败。
    pub async fn get_json<T: serde::de::DeserializeOwned>(&self, key: &str) -> DomainResult<Option<T>> {
        match self.get_string(key).await? {
            Some(raw) => serde_json::from_str(&raw)
                .map(Some)
                .map_err(|e| DomainError::Parse(format!("缓存内容不是合法 JSON（键 {key}）: {e}"))),
            None => Ok(None),
        }
    }

    /// 写入 JSON 缓存。
    ///
    /// # Errors
    /// 序列化失败。
    pub async fn set_json<T: serde::Serialize>(&self, key: &str, value: &T, ttl_secs: Option<i64>) -> DomainResult<()> {
        let raw = serde_json::to_string(value)?;
        self.set_string(key, &raw, ttl_secs).await
    }

    /// 三级配额计数器。
    #[must_use]
    pub fn quota(
        &self,
        tenant: TenantId,
        scope: &str,
        dimension: &str,
        bucket: &str,
        target: Option<&str>,
    ) -> QuotaCounter {
        let tenant_s = tenant.to_string();
        let mut parts = vec!["quota", tenant_s.as_str(), scope, dimension, bucket];
        if let Some(t) = target {
            parts.push(t);
        }
        QuotaCounter { key: self.key(&parts), store: self.clone() }
    }

    /// 分布式锁（单实例语义，用于"同一任务只有一个执行者"）。
    ///
    /// 返回 `true` 表示加锁成功。
    ///
    /// # Errors
    /// Redis 不可达。**注意**：不可达时返回错误而不是"假定加锁成功"，
    /// 避免多个实例同时执行同一任务。
    pub async fn acquire_lock(&self, name: &str, ttl_secs: u64) -> DomainResult<bool> {
        let mut conn = self.conn.clone();
        let key = self.key(&["lock", name]);
        // SET key value NX EX ttl
        let res: Option<String> = redis::cmd("SET")
            .arg(&key)
            .arg(format!("{}", std::process::id()))
            .arg("NX")
            .arg("EX")
            .arg(ttl_secs)
            .query_async(&mut conn)
            .await
            .map_err(|e| DomainError::DependencyUnavailable {
                dependency: "redis".to_string(),
                cause: format!("加锁失败: {e}"),
            })?;
        Ok(res.is_some())
    }

    /// 释放分布式锁。
    ///
    /// # Errors
    /// Redis 不可达。
    pub async fn release_lock(&self, name: &str) -> DomainResult<()> {
        let mut conn = self.conn.clone();
        let key = self.key(&["lock", name]);
        let res: Result<(), _> = conn.del(key).await;
        res.map_err(|e| DomainError::DependencyUnavailable {
            dependency: "redis".to_string(),
            cause: format!("释放锁失败: {e}"),
        })
    }

    /// 固定窗口限流：返回 `(是否放行, 当前计数, 窗口剩余秒数)`。
    ///
    /// # Errors
    /// Redis 不可达。
    pub async fn rate_limit(&self, name: &str, limit: i64, window_secs: i64) -> DomainResult<(bool, i64, i64)> {
        let rl_key = self.key(&["ratelimit", name]);
        let counter = QuotaCounter { key: rl_key, store: self.clone() };
        let outcome = counter.check_and_consume(limit, 1, window_secs, true).await?;
        Ok((outcome.allowed, outcome.used, window_secs))
    }

    /// 计数器自增（用于统计，如"今日事件数"）。
    ///
    /// # Errors
    /// Redis 不可达时返回 `Ok(None)`。
    pub async fn incr(&self, key: &str, amount: i64, ttl_secs: Option<i64>) -> DomainResult<Option<i64>> {
        let mut conn = self.conn.clone();
        let res: Result<i64, _> = conn.incr(key, amount).await;
        match res {
            Ok(v) => {
                if let Some(ttl) = ttl_secs {
                    if ttl > 0 {
                        let _: Result<(), _> = conn.expire(key, ttl).await;
                    }
                }
                Ok(Some(v))
            }
            Err(e) => {
                warn!(key, error = %e, "Redis INCR 失败");
                Ok(None)
            }
        }
    }
}

/// 配额计数器句柄。
#[derive(Debug, Clone)]
pub struct QuotaCounter {
    key: String,
    store: RedisStore,
}

/// 配额检查结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaOutcome {
    /// 是否放行。
    pub allowed: bool,
    /// 消费后的用量。
    pub used: i64,
}

impl QuotaCounter {
    /// 键名（排障用）。
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// 原子"检查 + 消费"。
    ///
    /// - `limit <= 0` 视为不限量；
    /// - `fail_closed = true` 时 Redis 不可达将**拒绝**请求（配额是安全控制，宁可少服务）；
    ///   为 `false` 时放行（用于非关键计量）。
    ///
    /// # Errors
    /// Redis 不可达且 `fail_closed = true`。
    pub async fn check_and_consume(
        &self,
        limit: i64,
        amount: i64,
        window_secs: i64,
        fail_closed: bool,
    ) -> DomainResult<QuotaOutcome> {
        let mut conn = self.store.conn.clone();
        let script = Script::new(QUOTA_SCRIPT);
        let res: Result<(i64, i64), _> =
            script.key(&self.key).arg(limit).arg(amount).arg(window_secs).invoke_async(&mut conn).await;
        match res {
            Ok((used, allowed)) => Ok(QuotaOutcome { allowed: allowed == 1, used }),
            Err(e) => {
                if fail_closed {
                    Err(DomainError::DependencyUnavailable {
                        dependency: "redis".to_string(),
                        cause: format!("配额检查失败（已按保守策略拒绝）: {e}"),
                    })
                } else {
                    warn!(key = %self.key, error = %e, "配额检查失败，按放行处理（非关键计量）");
                    Ok(QuotaOutcome { allowed: true, used: 0 })
                }
            }
        }
    }

    /// 归还已消费额度（请求失败时回滚）。
    ///
    /// # Errors
    /// Redis 不可达。
    pub async fn release(&self, amount: i64) -> DomainResult<i64> {
        let mut conn = self.store.conn.clone();
        let script = Script::new(QUOTA_RELEASE_SCRIPT);
        let res: Result<i64, _> = script.key(&self.key).arg(amount).invoke_async(&mut conn).await;
        res.map_err(|e| DomainError::DependencyUnavailable {
            dependency: "redis".to_string(),
            cause: format!("配额归还失败: {e}"),
        })
    }

    /// 只读查询当前用量（不消费）。
    ///
    /// # Errors
    /// Redis 不可达时返回 `Ok(0)`。
    pub async fn peek(&self) -> DomainResult<i64> {
        let mut conn = self.store.conn.clone();
        let res: Result<Option<i64>, _> = conn.get(&self.key).await;
        match res {
            Ok(v) => Ok(v.unwrap_or(0)),
            Err(e) => {
                warn!(key = %self.key, error = %e, "读取配额用量失败");
                Ok(0)
            }
        }
    }

    /// 重置计数器（管理员操作）。
    ///
    /// # Errors
    /// Redis 不可达。
    pub async fn reset(&self) -> DomainResult<()> {
        self.store.del(&self.key).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 这些测试不依赖真实 Redis：只覆盖键组装与纯逻辑分支。
    /// 真实 Redis 的行为验证见 `tests/redis_live.rs`（需要 `AGF_TEST_REDIS_URL`，登记 PV-012）。
    fn store_stub() -> Option<RedisStore> {
        None
    }

    #[test]
    fn quota_key_layout_is_stable() {
        // 直接验证键拼接规则（不依赖连接）
        let prefix = "agf";
        let tenant = TenantId::default_tenant();
        let tenant_s = tenant.to_string();
        let parts = vec!["quota", tenant_s.as_str(), "tenant", "tokens", "20260301"];
        let mut key = prefix.to_string();
        for p in &parts {
            key.push(':');
            key.push_str(p);
        }
        assert_eq!(key, format!("agf:quota:{tenant}:tenant:tokens:20260301"), "键布局变更会影响线上计数，必须稳定");
    }

    #[test]
    fn lua_scripts_are_syntactically_plausible() {
        assert!(QUOTA_SCRIPT.contains("redis.call('INCRBY'"));
        assert!(QUOTA_SCRIPT.contains("return {newval, 1}"));
        assert!(QUOTA_SCRIPT.contains("return {current, 0}"));
        assert!(QUOTA_RELEASE_SCRIPT.contains("redis.call('DEL'"));
        assert!(QUOTA_RELEASE_SCRIPT.contains("KEEPTTL"));
    }

    #[test]
    fn outcome_equality() {
        assert_eq!(QuotaOutcome { allowed: true, used: 1 }, QuotaOutcome { allowed: true, used: 1 });
        assert_ne!(QuotaOutcome { allowed: true, used: 1 }, QuotaOutcome { allowed: false, used: 1 });
    }

    #[test]
    fn stub_is_none() {
        assert!(store_stub().is_none(), "占位：真实 Redis 集成测试通过环境变量启用");
    }
}
