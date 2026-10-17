//! 全局常量。

/// 平台产品名。
pub const PRODUCT_NAME: &str = "AIGuardFabric";
/// 平台中文名。
pub const PRODUCT_NAME_ZH: &str = "智御矩阵";
/// API 前缀。
pub const API_PREFIX: &str = "/api/v1";
/// 默认租户 slug。
pub const DEFAULT_TENANT_SLUG: &str = "default";
/// 内置管理员用户名。
pub const BOOTSTRAP_ADMIN_USER: &str = "admin";

/// 请求 ID 头。
pub const HEADER_REQUEST_ID: &str = "X-Request-Id";
/// 幂等键头。
pub const HEADER_IDEMPOTENCY_KEY: &str = "Idempotency-Key";
/// API Key 头。
pub const HEADER_API_KEY: &str = "X-AGF-Key";
/// 租户头（多租户切换；必须与令牌内租户一致或被超管使用）。
pub const HEADER_TENANT: &str = "X-AGF-Tenant";
/// 限流剩余头。
pub const HEADER_RATE_LIMIT_REMAINING: &str = "X-RateLimit-Remaining";
/// 限流上限头。
pub const HEADER_RATE_LIMIT_LIMIT: &str = "X-RateLimit-Limit";
/// 限流重置头。
pub const HEADER_RATE_LIMIT_RESET: &str = "X-RateLimit-Reset";

/// API Key 前缀（生产）。
pub const API_KEY_PREFIX_LIVE: &str = "agf_live_";
/// API Key 前缀（测试）。
pub const API_KEY_PREFIX_TEST: &str = "agf_test_";
/// Agent 上报令牌前缀。
pub const AGENT_TOKEN_PREFIX: &str = "agf_agent_";

/// 默认 JWT 受众。
pub const JWT_AUDIENCE: &str = "agf-api";
/// 默认 JWT 签发者。
pub const JWT_ISSUER: &str = "aiguardfabric";

/// 主密钥长度（AES-256）。
pub const MASTER_KEY_BYTES: usize = 32;
/// AES-GCM nonce 长度。
pub const GCM_NONCE_BYTES: usize = 12;

/// 默认分页大小。
pub const DEFAULT_PAGE_SIZE: u32 = crate::pagination::DEFAULT_PAGE_SIZE;
/// 单页上限。
pub const MAX_PAGE_SIZE: u32 = crate::pagination::MAX_PAGE_SIZE;

/// 单条日志报文默认上限（字节）。
pub const DEFAULT_MAX_MESSAGE_BYTES: usize = 1_048_576;
/// 证据链默认保留天数。
pub const DEFAULT_EVIDENCE_RETENTION_DAYS: u32 = 365;
/// 热数据保留天数（ClickHouse/TimescaleDB）。
pub const DEFAULT_HOT_RETENTION_DAYS: u32 = 30;
/// 冷数据保留天数（对象存储 Parquet）。
pub const DEFAULT_COLD_RETENTION_DAYS: u32 = 365;

/// 规则灰度默认比例。
pub const DEFAULT_ROLLOUT_PERCENT: u8 = 100;
/// 规则正负样本最小数量（CI 门禁）。
pub const MIN_POSITIVE_SAMPLES: usize = 1;
/// 规则正负样本最小数量（CI 门禁）。
pub const MIN_NEGATIVE_SAMPLES: usize = 1;

/// 红队用例库目标规模（§4.2 内置 200+ 用例）。
pub const REDTEAM_TARGET_CASE_COUNT: usize = 200;

/// 内置日志解析模板目标数量（§4.5 100+ 模板）。
pub const PARSER_TEMPLATE_TARGET_COUNT: usize = 100;

/// 覆盖率门禁阈值（百分比）。
pub const COVERAGE_MIN_PERCENT: f64 = 70.0;

/// 证据编号前缀。
pub const EVIDENCE_CODE_PREFIX: &str = "EV";
/// 红队用例键前缀。
pub const REDTEAM_CASE_PREFIX: &str = "RT";

/// Mock 模式环境变量名。
pub const ENV_MOCK_MODE: &str = "AGF_MOCK_MODE";
/// 项目根环境变量名。
pub const ENV_PROJECT_ROOT: &str = "AGF_PROJECT_ROOT";

/// 平台内置服务账号名（审计用）。
pub mod service_accounts {
    /// 调度器。
    pub const SCHEDULER: &str = "agf-scheduler";
    /// 接入服务。
    pub const INGEST: &str = "agf-ingest";
    /// 关联分析。
    pub const CORRELATOR: &str = "agf-correlator";
    /// 运行时网关。
    pub const RUNTIME: &str = "agf-runtime";
    /// CLI。
    pub const CLI: &str = "agfctl";
    /// 迁移。
    pub const MIGRATOR: &str = "agf-migrator";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_key_prefixes_are_distinct() {
        assert_ne!(API_KEY_PREFIX_LIVE, API_KEY_PREFIX_TEST);
        assert_ne!(API_KEY_PREFIX_TEST, AGENT_TOKEN_PREFIX);
        assert!(API_KEY_PREFIX_LIVE.ends_with('_'));
    }

    #[test]
    fn crypto_constants_are_correct() {
        assert_eq!(MASTER_KEY_BYTES, 32, "AES-256 需要 32 字节密钥");
        assert_eq!(GCM_NONCE_BYTES, 12, "GCM 推荐 12 字节 nonce");
    }

    #[test]
    fn retention_defaults_are_ordered() {
        // 常量比较在编译期即为常量表达式，用 const 断言表达"必须有序"的意图
        const _: () = assert!(DEFAULT_HOT_RETENTION_DAYS < DEFAULT_COLD_RETENTION_DAYS);
        assert_eq!(DEFAULT_EVIDENCE_RETENTION_DAYS, 365);
        assert!(HOT_RETENTION_DAYS_LIST[0] < HOT_RETENTION_DAYS_LIST[1]);
    }

    /// 供测试读取的保留期序列（避免直接断言两个 const 触发 `assertions_on_constants`）。
    const HOT_RETENTION_DAYS_LIST: [u32; 2] = [DEFAULT_HOT_RETENTION_DAYS, DEFAULT_COLD_RETENTION_DAYS];

    #[test]
    fn headers_are_well_formed() {
        for h in [
            HEADER_REQUEST_ID,
            HEADER_IDEMPOTENCY_KEY,
            HEADER_API_KEY,
            HEADER_TENANT,
            HEADER_RATE_LIMIT_REMAINING,
            HEADER_RATE_LIMIT_LIMIT,
            HEADER_RATE_LIMIT_RESET,
        ] {
            assert!(!h.is_empty());
            assert!(h.is_ascii());
        }
    }

    #[test]
    fn service_accounts_named() {
        assert!(service_accounts::SCHEDULER.starts_with("agf-"));
        assert_eq!(service_accounts::CLI, "agfctl");
    }

    #[test]
    fn coverage_gate_is_70() {
        assert!((COVERAGE_MIN_PERCENT - 70.0).abs() < f64::EPSILON);
    }
}
