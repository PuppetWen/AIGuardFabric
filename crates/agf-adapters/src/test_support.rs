//! 测试支撑（**仅 `cfg(test)` 编译**）：构造 `AdapterConfig` / `AdapterSettings` / 凭据注入。
//!
//! 刻意放在独立模块而不是每个厂商模块内重复：厂商单测的样板代码越少，
//! "断言真实行为"的比例越高。**不进入 release 构建**，也不含任何明文凭据常量。

use std::collections::BTreeMap;

use agf_core::adapter::{AdapterConfig, CircuitBreakerConfig, RetryConfig};
use agf_core::ids::{Id, TenantId};
use agf_core::time::Timestamp;
use serde_json::Value;

use crate::contract::AdapterMetadata;
use crate::settings::{AdapterSettings, StaticSecrets};

/// 构造测试用 DB 实体（重试退避压到 1ms，保证测试快速且确定）。
#[must_use]
pub(crate) fn config_for(adapter: &str, settings: &[(&str, Value)], mock: bool) -> AdapterConfig {
    let now = Timestamp::now();
    let mut map: BTreeMap<String, Value> = BTreeMap::new();
    for (k, v) in settings {
        map.insert((*k).to_string(), v.clone());
    }
    AdapterConfig {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        adapter: adapter.to_string(),
        display_name: format!("{adapter}-test"),
        enabled: true,
        settings: map,
        secret_refs: BTreeMap::new(),
        circuit_breaker: CircuitBreakerConfig {
            enabled: true,
            failure_threshold: 3,
            open_secs: 30,
            half_open_probes: 1,
        },
        retry: RetryConfig {
            max_attempts: 3,
            initial_backoff_ms: 1,
            multiplier: 1.0,
            max_backoff_ms: 1,
            jitter: false,
        },
        timeout_secs: 5,
        mock,
        is_default: true,
        created_at: now,
        updated_at: now,
    }
}

/// 注入凭据的内存查找表。
#[must_use]
pub(crate) fn secrets(pairs: &[(&str, &str)]) -> StaticSecrets {
    let mut lookup = StaticSecrets::new();
    for (k, v) in pairs {
        lookup = lookup.with(k, v);
    }
    lookup
}

/// 由元信息 + 设置 + 凭据构造设置（走与生产一致的 `from_config` 路径）。
#[must_use]
pub(crate) fn settings_for(
    meta: &AdapterMetadata,
    settings: &[(&str, Value)],
    secret_pairs: &[(&str, &str)],
) -> Option<AdapterSettings> {
    let config = config_for(&meta.name, settings, false);
    AdapterSettings::from_config(meta, &config, &secrets(secret_pairs)).ok()
}

/// 构造设置但**跳过通用校验**：专供"配置存在但非法"的厂商校验单测，
/// 让测试能直接调用 `VendorSpec::validate_settings` 观察拒绝行为。
#[must_use]
pub(crate) fn raw_settings(
    meta: &AdapterMetadata,
    settings: &[(&str, Value)],
    secret_pairs: &[(&str, &str)],
) -> AdapterSettings {
    let mut out = AdapterSettings::defaults(meta).with_required_settings(&[]);
    for (k, v) in settings {
        out.settings.insert((*k).to_string(), v.clone());
    }
    for (k, v) in secret_pairs {
        out.secrets.insert((*k).to_string(), secrecy::SecretString::from((*v).to_string()));
    }
    out.endpoint = meta.endpoint_key.as_ref().and_then(|key| out.get_str(key)).map(ToString::to_string);
    out
}
