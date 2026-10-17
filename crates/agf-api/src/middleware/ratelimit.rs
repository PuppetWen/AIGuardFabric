//! 三级限流（自 `middleware.rs` 拆出）。

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

/// 单级限流参数。
#[derive(Debug, Clone, Copy)]
pub struct RateLimitTier {
    /// 桶容量（突发上限）。
    pub capacity: u32,
    /// 每秒补充令牌数。
    pub refill_per_sec: f64,
}

impl RateLimitTier {
    /// 构造。
    #[must_use]
    pub const fn new(capacity: u32, refill_per_sec: f64) -> Self {
        Self { capacity, refill_per_sec }
    }
}

/// 三级限流参数。
#[derive(Debug, Clone, Copy)]
pub struct RateLimitTiers {
    /// 按主体（API Key / JWT 主体）。
    pub identity: RateLimitTier,
    /// 按租户。
    pub tenant: RateLimitTier,
    /// 全进程。
    pub global: RateLimitTier,
}

impl Default for RateLimitTiers {
    fn default() -> Self {
        Self {
            identity: RateLimitTier::new(240, 120.0),
            tenant: RateLimitTier::new(3_000, 600.0),
            global: RateLimitTier::new(20_000, 4_000.0),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

/// 单级判定结果。
#[derive(Debug, Clone, Copy)]
pub struct LimitVerdict {
    /// 是否放行。
    pub allowed: bool,
    /// 该级上限。
    pub limit: u32,
    /// 剩余额度。
    pub remaining: u32,
    /// 距下一令牌的秒数（向上取整，至少 1）。
    pub reset_secs: u64,
    /// 级别名。
    pub scope: &'static str,
}

/// 进程内令牌桶限流器。
#[derive(Debug)]
pub struct RateLimiter {
    tiers: RateLimitTiers,
    buckets: Mutex<HashMap<String, Bucket>>,
    checks: AtomicU64,
}

impl RateLimiter {
    /// 构造并预置各维度的桶。
    #[must_use]
    pub fn new(tiers: RateLimitTiers) -> Self {
        Self { tiers, buckets: Mutex::new(HashMap::new()), checks: AtomicU64::new(0) }
    }

    /// 参数快照。
    #[must_use]
    pub const fn tiers(&self) -> RateLimitTiers {
        self.tiers
    }

    /// Refill all dimensions under one lock, then charge only if every dimension allows the request.
    /// A rejected identity must not drain the tenant or global budget shared by other users.
    #[must_use]
    pub fn check_all(&self, identity_key: &str, tenant: TenantId) -> Vec<LimitVerdict> {
        let now = Instant::now();
        let dimensions = [
            ("global".to_string(), self.tiers.global, "global"),
            (format!("tenant:{tenant}"), self.tiers.tenant, "tenant"),
            (format!("identity:{identity_key}"), self.tiers.identity, "identity"),
        ];
        let Ok(mut buckets) = self.buckets.lock() else {
            // 锁中毒时不阻断流量（可用性优先），但记为放行
            return dimensions
                .into_iter()
                .map(|(_, tier, scope)| LimitVerdict {
                    allowed: true,
                    limit: tier.capacity,
                    remaining: tier.capacity,
                    reset_secs: 1,
                    scope,
                })
                .collect();
        };
        // Idle buckets are full after capacity/refill seconds and no longer need stored state.
        // Sweep periodically so a stream of distinct valid credentials cannot grow this map forever.
        if buckets.len() > 4_096 && self.checks.fetch_add(1, Ordering::Relaxed).is_multiple_of(1_024) {
            buckets.retain(|key, bucket| {
                let tier = if key == "global" {
                    self.tiers.global
                } else if key.starts_with("tenant:") {
                    self.tiers.tenant
                } else {
                    self.tiers.identity
                };
                tier.refill_per_sec <= 0.0
                    || !tier.refill_per_sec.is_finite()
                    || now.saturating_duration_since(bucket.last).as_secs_f64()
                        < f64::from(tier.capacity) / tier.refill_per_sec
            });
        }
        let mut available = [0.0; 3];
        for (index, (key, tier, _)) in dimensions.iter().enumerate() {
            available[index] = if let Some(bucket) = buckets.get_mut(key) {
                let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
                bucket.tokens = (bucket.tokens + elapsed * tier.refill_per_sec).min(f64::from(tier.capacity));
                bucket.last = now;
                bucket.tokens
            } else {
                f64::from(tier.capacity)
            };
        }
        let admitted = available.iter().all(|tokens| *tokens >= 1.0);
        dimensions
            .into_iter()
            .enumerate()
            .map(|(index, (key, tier, scope))| {
                let remaining = if admitted { available[index] - 1.0 } else { available[index] };
                if admitted {
                    buckets.insert(key, Bucket { tokens: remaining, last: now });
                }
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                let remaining_u32 = remaining.max(0.0) as u32;
                let deficit = (1.0 - remaining).max(0.0);
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                let reset_secs = if deficit <= 0.0 || tier.refill_per_sec <= 0.0 {
                    1
                } else {
                    ((deficit / tier.refill_per_sec).ceil() as u64).max(1)
                };
                LimitVerdict {
                    allowed: available[index] >= 1.0,
                    limit: tier.capacity,
                    remaining: remaining_u32,
                    reset_secs,
                    scope,
                }
            })
            .collect()
    }
}

/// 取最紧的一级（剩余最少者）作为响应头来源。
#[must_use]
pub fn tightest(verdicts: &[LimitVerdict]) -> Option<&LimitVerdict> {
    verdicts.iter().min_by_key(|v| (v.allowed, v.remaining))
}

async fn check_limits(
    state: &AppState,
    identity_key: &str,
    tenant: TenantId,
) -> Result<Vec<LimitVerdict>, DomainError> {
    let Some(redis) = state.persistence.as_ref().and_then(|bridge| bridge.store().redis()) else {
        if state.shared_rate_limit_required {
            return Err(DomainError::DependencyUnavailable {
                dependency: "redis".into(),
                cause: "多副本共享限流已启用，但 Redis 未连接".into(),
            });
        }
        return Ok(state.limiter.check_all(identity_key, tenant));
    };
    let tiers = state.limiter.tiers();
    let levels = [("global", tiers.global), ("tenant", tiers.tenant), ("identity", tiers.identity)];
    let names = ["global".to_string(), format!("tenant:{tenant}"), format!("identity:{identity_key}")];
    let result = redis
        .rate_limits_atomic(names, levels.map(|(_, tier)| tier.capacity), levels.map(|(_, tier)| tier.refill_per_sec))
        .await?;
    Ok(result
        .into_iter()
        .zip(levels)
        .map(|(value, (scope, tier))| LimitVerdict {
            allowed: value.allowed,
            limit: tier.capacity,
            remaining: value.remaining,
            reset_secs: value.reset_secs,
            scope,
        })
        .collect())
}

/// 限流中间件。
pub async fn rate_limit(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let path = matched_path(&req);
    if is_probe_path(&path) {
        return next.run(req).await;
    }
    let (mut parts, body) = req.into_parts();
    // Use authenticated state for both budget keys. Invalid credentials use a separate
    // anonymous budget, so an arbitrary tenant header cannot exhaust another tenant.
    let (identity_key, tenant) = match Principal::from_request_parts(&mut parts, &state).await {
        Ok(principal) => {
            let identity = principal.display();
            let tenant = principal.tenant;
            parts.extensions.insert(principal);
            (identity, tenant)
        }
        Err(_) => (identity_key_of(&parts.headers), TenantId::from_id(Id::nil())),
    };
    let req = Request::from_parts(parts, body);
    let verdicts = match check_limits(&state, &identity_key, tenant).await {
        Ok(verdicts) => verdicts,
        Err(error) => return ApiError::new(error).into_response(),
    };
    if let Some(denied) = verdicts.iter().find(|v| !v.allowed) {
        state.metrics.record_rate_limited();
        return ApiError::new(DomainError::RateLimited(format!(
            "{} 级限流触发：{} 秒后可重试",
            denied.scope, denied.reset_secs
        )))
        .with_header("Retry-After", denied.reset_secs.to_string())
        .with_header(HEADER_RATE_LIMIT_LIMIT, denied.limit.to_string())
        .with_header(HEADER_RATE_LIMIT_REMAINING, "0")
        .with_header(HEADER_RATE_LIMIT_RESET, denied.reset_secs.to_string())
        .into_response();
    }
    let mut response = next.run(req).await;
    if let Some(verdict) = tightest(&verdicts) {
        let headers = response.headers_mut();
        insert_header(headers, HEADER_RATE_LIMIT_LIMIT, &verdict.limit.to_string());
        insert_header(headers, HEADER_RATE_LIMIT_REMAINING, &verdict.remaining.to_string());
        insert_header(headers, HEADER_RATE_LIMIT_RESET, &verdict.reset_secs.to_string());
    }
    response
}

fn is_probe_path(path: &str) -> bool {
    matches!(path, "/healthz" | "/readyz" | "/metrics")
}

pub(super) fn matched_path(req: &Request) -> String {
    req.extensions().get::<MatchedPath>().map_or_else(|| req.uri().path().to_string(), |m| m.as_str().to_string())
}

pub(super) fn identity_key_of(headers: &axum::http::HeaderMap) -> String {
    // client_address::normalize has already replaced untrusted forwarding headers with the
    // actual peer address. Invalid credentials cannot rotate this identity bucket.
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map_or_else(|| "anonymous".to_string(), |v| format!("ip:{}", v.split(',').next().unwrap_or("").trim()))
}

pub(super) fn insert_header(headers: &mut axum::http::HeaderMap, name: &'static str, value: &str) {
    if let (Ok(header_name), Ok(header_value)) = (axum::http::HeaderName::try_from(name), HeaderValue::from_str(value))
    {
        headers.insert(header_name, header_value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejected_identity_does_not_drain_shared_budgets() {
        let limiter = RateLimiter::new(RateLimitTiers {
            identity: RateLimitTier::new(1, 0.0),
            tenant: RateLimitTier::new(2, 0.0),
            global: RateLimitTier::new(2, 0.0),
        });
        let tenant = TenantId::new();
        assert!(limiter.check_all("first", tenant).iter().all(|v| v.allowed));
        let rejected = limiter.check_all("first", tenant);
        assert!(!rejected[2].allowed);
        assert_eq!(rejected[0].remaining, 1);
        assert_eq!(rejected[1].remaining, 1);
        assert!(limiter.check_all("second", tenant).iter().all(|v| v.allowed));
    }

    #[test]
    fn rejected_requests_do_not_allocate_new_identity_buckets() {
        let limiter = RateLimiter::new(RateLimitTiers {
            identity: RateLimitTier::new(10, 0.0),
            tenant: RateLimitTier::new(10, 0.0),
            global: RateLimitTier::new(1, 0.0),
        });
        let tenant = TenantId::new();
        assert!(limiter.check_all("first", tenant).iter().all(|v| v.allowed));
        for index in 0..1_000 {
            assert!(!limiter.check_all(&format!("anonymous-{index}"), tenant)[0].allowed);
        }
        assert_eq!(limiter.buckets.lock().map(|b| b.len()).ok(), Some(3));
    }

    #[test]
    fn unauthenticated_credentials_cannot_rotate_identity_bucket() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("192.0.2.10"));
        let baseline = identity_key_of(&headers);
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer invalid-token"));
        headers.insert("x-api-key", HeaderValue::from_static("attacker-controlled"));
        headers.insert(HEADER_TENANT, HeaderValue::from_static("00000000-0000-0000-0000-000000000002"));
        assert_eq!(identity_key_of(&headers), baseline);
    }
}
