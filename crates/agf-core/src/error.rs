//! 统一错误类型。
//!
//! 设计原则（§12.3 分层错误处理）：
//! - 领域层用 [`DomainError`]（thiserror，穷举变体），不使用 `anyhow`；
//! - 基础设施层捕获底层错误后映射为 [`DomainError`]，保留 cause 字符串；
//! - `agf-api` 把 [`DomainError`] 映射为 RFC 9457 `application/problem+json`。

use thiserror::Error;

/// 领域结果别名。
pub type DomainResult<T> = Result<T, DomainError>;

/// 领域错误。
///
/// 变体与 HTTP 状态的映射见 [`DomainError::problem_type`] 与 [`DomainError::status_code`]。
///
/// 派生 `PartialEq`/`Eq` 是刻意的：所有载荷都是 `String`/`&'static str`/数值，
/// 语义等价即可比较；这让"断言某操作返回某错误"（幂等性、授权拒绝、配额耗尽）
/// 成为可读且稳定的测试写法，而不是每次手写 `matches!`。
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DomainError {
    /// 输入校验失败（400）。
    #[error("校验失败: {0}")]
    Validation(String),

    /// 资源不存在（404）。
    #[error("资源不存在: {entity} / {id}")]
    NotFound {
        /// 实体名，如 `asset`。
        entity: &'static str,
        /// 实体标识。
        id: String,
    },

    /// 资源冲突（409）。
    #[error("资源冲突: {0}")]
    Conflict(String),

    /// 未认证（401）。
    #[error("未认证: {0}")]
    Unauthenticated(String),

    /// 无权限（403）。
    #[error("权限不足: {0}")]
    Forbidden(String),

    /// 租户隔离违规（403）——跨租户访问被拒绝。
    #[error("租户隔离拒绝: tenant={tenant} resource={resource}")]
    TenantViolation {
        /// 请求方租户。
        tenant: String,
        /// 被访问资源。
        resource: String,
    },

    /// 配额耗尽（429）。
    #[error("配额耗尽: {scope} / {dimension} 已用 {used} 超过上限 {limit}")]
    QuotaExceeded {
        /// 配额层级（tenant/agent/session）。
        scope: String,
        /// 维度（tokens/requests/concurrency/cost）。
        dimension: String,
        /// 已用。
        used: i64,
        /// 上限。
        limit: i64,
    },

    /// 限流（429）。
    #[error("限流: {0}")]
    RateLimited(String),

    /// 前置条件不满足（412），如首登未改密、策略未签名。
    #[error("前置条件不满足: {0}")]
    PreconditionFailed(String),

    /// 外部依赖不可用（502/503）——含降级提示。
    #[error("外部依赖不可用: {dependency} 原因: {cause}")]
    DependencyUnavailable {
        /// 依赖名（如 `alicloud.cms`）。
        dependency: String,
        /// 原因描述。
        cause: String,
    },

    /// 上游超时（504）。
    #[error("上游超时: {0}")]
    Timeout(String),

    /// 策略拒绝（403）——运行时拦截。
    #[error("策略拒绝: policy={policy} 动作={action} 原因: {reason}")]
    PolicyDenied {
        /// 命中的策略标识。
        policy: String,
        /// 策略动作。
        action: String,
        /// 拒绝原因。
        reason: String,
    },

    /// 配置缺失或非法。
    #[error("配置错误: {0}")]
    Config(String),

    /// 解析失败（日志、YAML 规则、剧本）。
    #[error("解析失败: {0}")]
    Parse(String),

    /// 加解密或密钥处理失败。
    #[error("加密错误: {0}")]
    Crypto(String),

    /// 尚未实现（脚手架阶段专用；每个变体必须登记 TODO 锚点与待验证项）。
    #[error("尚未实现: {0}")]
    NotImplemented(String),

    /// 内部错误（不应发生，兜底）。
    #[error("内部错误: {0}")]
    Internal(String),
}

impl DomainError {
    /// RFC 9457 `type` 字段值（URI 引用，指向错误文档锚点）。
    #[must_use]
    pub fn problem_type(&self) -> &'static str {
        match self {
            Self::Validation(_) => "https://aiguardfabric.dev/errors/validation",
            Self::NotFound { .. } => "https://aiguardfabric.dev/errors/not-found",
            Self::Conflict(_) => "https://aiguardfabric.dev/errors/conflict",
            Self::Unauthenticated(_) => "https://aiguardfabric.dev/errors/unauthenticated",
            Self::Forbidden(_) | Self::TenantViolation { .. } | Self::PolicyDenied { .. } => {
                "https://aiguardfabric.dev/errors/forbidden"
            }
            Self::QuotaExceeded { .. } | Self::RateLimited(_) => "https://aiguardfabric.dev/errors/rate-limited",
            Self::PreconditionFailed(_) => "https://aiguardfabric.dev/errors/precondition-failed",
            Self::DependencyUnavailable { .. } => "https://aiguardfabric.dev/errors/dependency-unavailable",
            Self::Timeout(_) => "https://aiguardfabric.dev/errors/timeout",
            Self::Config(_) => "https://aiguardfabric.dev/errors/config",
            Self::Parse(_) => "https://aiguardfabric.dev/errors/parse",
            Self::Crypto(_) => "https://aiguardfabric.dev/errors/crypto",
            Self::NotImplemented(_) => "https://aiguardfabric.dev/errors/not-implemented",
            Self::Internal(_) => "https://aiguardfabric.dev/errors/internal",
        }
    }

    /// 建议 HTTP 状态码。
    #[must_use]
    pub const fn status_code(&self) -> u16 {
        match self {
            Self::Validation(_) | Self::Parse(_) => 400,
            Self::Unauthenticated(_) => 401,
            Self::Forbidden(_) | Self::TenantViolation { .. } | Self::PolicyDenied { .. } => 403,
            Self::NotFound { .. } => 404,
            Self::Conflict(_) => 409,
            Self::PreconditionFailed(_) => 412,
            Self::QuotaExceeded { .. } | Self::RateLimited(_) => 429,
            Self::DependencyUnavailable { .. } => 503,
            Self::Timeout(_) => 504,
            Self::Config(_) | Self::Crypto(_) | Self::NotImplemented(_) | Self::Internal(_) => 500,
        }
    }

    /// 稳定机器可读 code（前端 i18n 与告警规则依赖此值，禁止随意变更）。
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Validation(_) => "validation_failed",
            Self::NotFound { .. } => "not_found",
            Self::Conflict(_) => "conflict",
            Self::Unauthenticated(_) => "unauthenticated",
            Self::Forbidden(_) => "forbidden",
            Self::TenantViolation { .. } => "tenant_violation",
            Self::QuotaExceeded { .. } => "quota_exceeded",
            Self::RateLimited(_) => "rate_limited",
            Self::PreconditionFailed(_) => "precondition_failed",
            Self::DependencyUnavailable { .. } => "dependency_unavailable",
            Self::Timeout(_) => "upstream_timeout",
            Self::PolicyDenied { .. } => "policy_denied",
            Self::Config(_) => "config_error",
            Self::Parse(_) => "parse_error",
            Self::Crypto(_) => "crypto_error",
            Self::NotImplemented(_) => "not_implemented",
            Self::Internal(_) => "internal_error",
        }
    }

    /// 该错误是否属于"外部依赖缺失，可降级"。
    #[must_use]
    pub const fn is_degradable(&self) -> bool {
        matches!(self, Self::DependencyUnavailable { .. } | Self::Config(_) | Self::NotImplemented(_))
    }

    /// 构造 [`Self::NotImplemented`] 的便捷方式（保留 TODO 锚点用途）。
    pub fn not_implemented(what: impl Into<String>) -> Self {
        Self::NotImplemented(what.into())
    }
}

impl From<serde_json::Error> for DomainError {
    fn from(value: serde_json::Error) -> Self {
        Self::Parse(format!("json: {value}"))
    }
}

impl From<serde_yaml::Error> for DomainError {
    fn from(value: serde_yaml::Error) -> Self {
        Self::Parse(format!("yaml: {value}"))
    }
}

impl From<std::io::Error> for DomainError {
    fn from(value: std::io::Error) -> Self {
        Self::Internal(format!("io: {value}"))
    }
}

impl From<uuid::Error> for DomainError {
    fn from(value: uuid::Error) -> Self {
        Self::Validation(format!("uuid: {value}"))
    }
}

impl From<url::ParseError> for DomainError {
    fn from(value: url::ParseError) -> Self {
        Self::Validation(format!("url: {value}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 状态码映射覆盖全部变体() {
        let cases: Vec<DomainError> = vec![
            DomainError::Validation("x".into()),
            DomainError::NotFound { entity: "asset", id: "1".into() },
            DomainError::Conflict("x".into()),
            DomainError::Unauthenticated("x".into()),
            DomainError::Forbidden("x".into()),
            DomainError::TenantViolation { tenant: "a".into(), resource: "b".into() },
            DomainError::QuotaExceeded { scope: "tenant".into(), dimension: "tokens".into(), used: 2, limit: 1 },
            DomainError::RateLimited("x".into()),
            DomainError::PreconditionFailed("x".into()),
            DomainError::DependencyUnavailable { dependency: "cms".into(), cause: "x".into() },
            DomainError::Timeout("x".into()),
            DomainError::PolicyDenied { policy: "p".into(), action: "deny".into(), reason: "x".into() },
            DomainError::Config("x".into()),
            DomainError::Parse("x".into()),
            DomainError::Crypto("x".into()),
            DomainError::NotImplemented("x".into()),
            DomainError::Internal("x".into()),
        ];
        for e in cases {
            assert!(e.status_code() >= 400, "code={} err={e}", e.code());
            assert!(e.problem_type().starts_with("https://"));
            assert!(!e.code().is_empty());
        }
    }

    #[test]
    fn 可降级判定() {
        assert!(DomainError::NotImplemented("mcp".into()).is_degradable());
        assert!(!DomainError::Validation("x".into()).is_degradable());
    }
}
