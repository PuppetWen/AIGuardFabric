//! Three shared token buckets charged atomically with Redis server time.

use super::*;

const SCRIPT: &str = r"
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local tokens = {}
local capacity = {}
local refill = {}
local existed = {}
local admitted = 1
for i = 1, 3 do
  capacity[i] = tonumber(ARGV[i * 2 - 1])
  refill[i] = tonumber(ARGV[i * 2])
  local state = redis.call('HMGET', KEYS[i], 'tokens', 'at')
  existed[i] = state[1] and state[2]
  tokens[i] = capacity[i]
  if existed[i] then
    local elapsed = math.max(0, now - tonumber(state[2]))
    tokens[i] = math.min(capacity[i], tonumber(state[1]) + elapsed * refill[i] / 1000)
  end
  if tokens[i] < 1 then admitted = 0 end
end
local result = {}
for i = 1, 3 do
  local allowed = tokens[i] >= 1 and 1 or 0
  if admitted == 1 then tokens[i] = tokens[i] - 1 end
  if existed[i] or admitted == 1 then
    redis.call('HSET', KEYS[i], 'tokens', tostring(tokens[i]), 'at', now)
    if refill[i] > 0 then
      redis.call('PEXPIRE', KEYS[i], math.max(1000, math.ceil(capacity[i] / refill[i] * 1000)))
    end
  end
  local deficit = math.max(0, 1 - tokens[i])
  local reset = refill[i] > 0 and math.max(1, math.ceil(deficit / refill[i])) or 1
  result[#result + 1] = allowed
  result[#result + 1] = math.floor(math.max(0, tokens[i]))
  result[#result + 1] = reset
end
return result
";

/// Per-dimension result from one atomic Redis admission decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DistributedRateVerdict {
    /// Whether this dimension had a token before the all-or-nothing charge.
    pub allowed: bool,
    /// Whole tokens remaining after admission, or unchanged on denial.
    pub remaining: u32,
    /// Seconds until the next token is available (minimum one).
    pub reset_secs: u64,
}

impl RedisStore {
    /// Check and consume global, tenant and identity budgets in one Redis script.
    /// All keys share a hash tag so Redis Cluster executes the script on one shard.
    ///
    /// # Errors
    /// Invalid tier parameters or Redis failure. Callers should fail closed on Redis errors;
    /// using local buckets would silently remove the cross-instance ceiling.
    pub async fn rate_limits_atomic(
        &self,
        names: [String; 3],
        capacities: [u32; 3],
        refill_per_sec: [f64; 3],
    ) -> DomainResult<[DistributedRateVerdict; 3]> {
        if refill_per_sec.iter().any(|rate| !rate.is_finite() || *rate < 0.0) {
            return Err(DomainError::Config("限流补充速率必须为有限非负数".into()));
        }
        let keys = names.map(|name| self.key(&["ratelimit", "{all}", &name]));
        let script = Script::new(SCRIPT);
        let mut call = script.prepare_invoke();
        for key in &keys {
            call.key(key);
        }
        for index in 0..3 {
            call.arg(capacities[index]).arg(refill_per_sec[index]);
        }
        let mut conn = self.conn.clone();
        let result: Vec<i64> = call.invoke_async(&mut conn).await.map_err(|error| {
            DomainError::DependencyUnavailable {
                dependency: "redis".into(), cause: format!("原子限流失败: {error}")
            }
        })?;
        if result.len() != 9 {
            return Err(DomainError::Parse("Redis 限流脚本返回值长度非法".into()));
        }
        Ok(std::array::from_fn(|index| DistributedRateVerdict {
            allowed: result[index * 3] == 1,
            remaining: u32::try_from(result[index * 3 + 1]).unwrap_or(0),
            reset_secs: u64::try_from(result[index * 3 + 2]).unwrap_or(1),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires AGF_TEST_REDIS_URL; uses isolated expiring keys"]
    #[allow(clippy::expect_used)]
    async fn two_instances_share_budgets_without_charging_rejected_identity() {
        let url = std::env::var("AGF_TEST_REDIS_URL").expect("isolated Redis test URL");
        let client = redis::Client::open(url).expect("Redis client");
        let manager = ConnectionManager::new(client).await.expect("Redis test connection");
        let prefix = format!("agf:ratelimit-test:{}", uuid::Uuid::now_v7());
        let first = RedisStore::from_manager(manager.clone(), &prefix);
        let second = RedisStore::from_manager(manager, prefix);
        let tiers = [2, 2, 1];
        let refill = [0.1, 0.1, 0.1];
        let names = |identity: &str| ["global".into(), "tenant:test".into(), format!("identity:{identity}")];

        let accepted = first.rate_limits_atomic(names("alice"), tiers, refill).await.expect("first request");
        assert!(accepted.iter().all(|verdict| verdict.allowed));
        let rejected = second.rate_limits_atomic(names("alice"), tiers, refill).await.expect("repeat request");
        assert!(!rejected[2].allowed);
        assert_eq!(rejected[0].remaining, 1);
        assert_eq!(rejected[1].remaining, 1);
        let other = second.rate_limits_atomic(names("bob"), tiers, refill).await.expect("other identity");
        assert!(other.iter().all(|verdict| verdict.allowed));
        let exhausted = first.rate_limits_atomic(names("carol"), tiers, refill).await.expect("global cap");
        assert!(!exhausted[0].allowed);

        let concurrent = || ["global-concurrent".into(), "tenant:concurrent".into(), "identity:shared".into()];
        let (left, right) = tokio::join!(
            first.rate_limits_atomic(concurrent(), [1; 3], refill),
            second.rate_limits_atomic(concurrent(), [1; 3], refill)
        );
        let admitted = [left.expect("first concurrent result"), right.expect("second concurrent result")]
            .into_iter()
            .filter(|verdicts| verdicts.iter().all(|verdict| verdict.allowed))
            .count();
        assert_eq!(admitted, 1);

        let mut conn = first.conn.clone();
        let keys = [
            "global",
            "tenant:test",
            "identity:alice",
            "identity:bob",
            "identity:carol",
            "global-concurrent",
            "tenant:concurrent",
            "identity:shared",
        ];
        for name in keys {
            let key = first.key(&["ratelimit", "{all}", name]);
            let _: i64 = redis::cmd("DEL").arg(key).query_async(&mut conn).await.expect("cleanup test key");
        }
    }
}
