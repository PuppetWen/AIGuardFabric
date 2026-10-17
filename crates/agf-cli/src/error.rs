//! agfctl 错误类型与**退出码映射**。
//!
//! ## 退出码语义（外部依赖与业务判定必须可区分）
//!
//! | 退出码 | 含义 | 典型来源 |
//! |---|---|---|
//! | 0 | 成功 | 全部子命令 |
//! | 1 | 判定失败（校验未通过 / 探针不健康 / 清单不一致） | `rules verify`、`redteam verify`、`airgap verify`、`healthcheck` |
//! | 2 | 外部依赖不可用或未验证（PG 不可达 / `pg_dump` 不存在） | `db`、`migrate`、`backup`、`restore` |
//!
//! 之所以把「依赖不可用」与「校验失败」分开，是因为二者的处置动作完全不同：
//! 前者要修环境（阶段二才能真验，见 `TODO(agfctl-*)` 锚点），后者要修内容。
//! 把两者混成同一个退出码会让 CI 无法归因，也会掩盖"假装成功"的降级。

use thiserror::Error;

/// agfctl 错误。
#[derive(Debug, Error)]
pub enum AppError {
    /// 携带退出码的**业务结论**（校验失败、探针不健康等），不是程序缺陷。
    #[error("{0}")]
    Exit(Exit),
    /// 意外错误（I/O、序列化、配置解析）——统一按退出码 1 收口。
    #[error(transparent)]
    Fatal(#[from] anyhow::Error),
}

impl AppError {
    /// 生成的进程退出码。
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Exit(e) => e.code(),
            Self::Fatal(_) => crate::exit::GENERAL_FAILURE,
        }
    }

    /// 是否为「外部依赖不可用」类结论（阶段二才能真验的部分）。
    #[must_use]
    pub const fn is_dependency_unavailable(&self) -> bool {
        matches!(self, Self::Exit(e) if e.code() == crate::exit::DEPENDENCY_UNAVAILABLE)
    }
}

/// 结论型退出（不打印堆栈，只打印一句人话）。
///
/// 实现 [`std::error::Error`] 是为了让它能作为 `anyhow` 的错误源被 `?` 传播。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exit {
    code: u8,
    message: Option<String>,
}

impl std::fmt::Display for Exit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.message {
            Some(m) => write!(f, "{m}"),
            None => write!(f, "退出码 {}", self.code),
        }
    }
}

impl std::error::Error for Exit {}

impl Exit {
    /// 以指定退出码结束，无附加信息。
    #[must_use]
    pub const fn new(code: u8) -> Self {
        Self { code, message: None }
    }

    /// 以「校验失败」（退出码 1）结束并说明原因。
    #[must_use]
    pub fn failed(reason: impl Into<String>) -> Self {
        Self { code: crate::exit::VALIDATION_FAILED, message: Some(reason.into()) }
    }

    /// 以「外部依赖不可用」（退出码 2）结束并说明原因与 TODO 锚点。
    #[must_use]
    pub fn dependency_unavailable(reason: impl Into<String>) -> Self {
        Self { code: crate::exit::DEPENDENCY_UNAVAILABLE, message: Some(reason.into()) }
    }

    /// 退出码。
    #[must_use]
    pub const fn code(&self) -> u8 {
        self.code
    }

    /// 结论文本。
    #[must_use]
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
}

impl From<Exit> for AppError {
    fn from(value: Exit) -> Self {
        Self::Exit(value)
    }
}

impl From<agf_core::error::DomainError> for AppError {
    fn from(value: agf_core::error::DomainError) -> Self {
        Self::Fatal(anyhow::Error::new(value))
    }
}

impl From<std::io::Error> for AppError {
    fn from(value: std::io::Error) -> Self {
        Self::Fatal(anyhow::Error::new(value))
    }
}

impl From<serde_json::Error> for AppError {
    fn from(value: serde_json::Error) -> Self {
        Self::Fatal(anyhow::Error::new(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exit::{DEPENDENCY_UNAVAILABLE, GENERAL_FAILURE, VALIDATION_FAILED};

    #[test]
    fn exit_codes_map_to_contract() {
        assert_eq!(AppError::Exit(Exit::new(0)).exit_code(), 0);
        assert_eq!(AppError::Exit(Exit::failed("坏规则")).exit_code(), VALIDATION_FAILED);
        assert_eq!(AppError::Exit(Exit::dependency_unavailable("PG 不可达")).exit_code(), DEPENDENCY_UNAVAILABLE);
        assert_eq!(AppError::Fatal(anyhow::anyhow!("boom")).exit_code(), GENERAL_FAILURE);
    }

    #[test]
    fn dependency_unavailable_is_distinguishable_from_validation_failure() {
        let dep = AppError::Exit(Exit::dependency_unavailable("pg_dump 不存在"));
        assert!(dep.is_dependency_unavailable());
        assert_eq!(dep.exit_code(), 2);
        let bad = AppError::Exit(Exit::failed("校验不一致"));
        assert!(!bad.is_dependency_unavailable());
        assert_eq!(bad.exit_code(), 1);
        assert_ne!(dep.exit_code(), bad.exit_code(), "依赖不可用与校验失败不得共用退出码");
    }

    #[test]
    fn exit_message_is_optional_and_displayed() {
        assert_eq!(Exit::new(7).to_string(), "退出码 7");
        assert_eq!(Exit::failed("原因").to_string(), "原因");
        assert_eq!(Exit::failed("原因").message(), Some("原因"));
        assert_eq!(Exit::new(7).message(), None);
    }

    #[test]
    fn exits_and_io_errors_convert_to_app_error() {
        let from_exit: AppError = Exit::failed("结论").into();
        assert_eq!(from_exit.exit_code(), 1);
        let io: AppError = std::io::Error::new(std::io::ErrorKind::NotFound, "缺文件").into();
        assert_eq!(io.exit_code(), GENERAL_FAILURE);
        let json: AppError = serde_json::from_str::<serde_json::Value>("{").expect_err("非法 JSON").into();
        assert_eq!(json.exit_code(), GENERAL_FAILURE);
    }

    #[test]
    fn domain_error_becomes_fatal() {
        let err: AppError = agf_core::error::DomainError::Validation("规则包非法".to_string()).into();
        assert_eq!(err.exit_code(), GENERAL_FAILURE);
        assert!(matches!(err, AppError::Fatal(_)));
    }

    #[test]
    fn exit_is_a_std_error_so_it_can_travel_through_question_mark() {
        fn inner() -> anyhow::Result<()> {
            Err(Exit::dependency_unavailable("PG 不可达"))?;
            Ok(())
        }
        let err = inner().expect_err("应失败");
        assert!(err.to_string().contains("PG 不可达"));
    }
}
