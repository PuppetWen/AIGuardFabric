//! `agfctl healthcheck --url <URL>` — HTTP `/healthz` 探针（§4.10 健康自检）。
//!
//! 与 `apps/server`、`apps/ingest`、`apps/scheduler` 的同名子命令**行为一致**：
//! 2xx → 退出码 0；非 2xx 或网络错误 → 退出码 1；stdout 打 `OK <状态码>`，
//! stderr 打 `FAIL <原因>`，因此可直接作为 compose / K8s 的探针使用。

use std::time::Duration;

use serde::Serialize;

use crate::error::{AppError, Exit};
use crate::output::Output;

/// 探针结论。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HealthOutcome {
    /// 探测地址。
    pub url: String,
    /// 是否健康。
    pub healthy: bool,
    /// HTTP 状态码（网络错误时为 `None`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// 失败原因（健康时为 `None`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl HealthOutcome {
    /// 网络错误结论。
    #[must_use]
    pub fn unreachable(url: &str, error: impl Into<String>) -> Self {
        Self { url: url.to_string(), healthy: false, status: None, error: Some(error.into()) }
    }

    /// 有响应结论。
    #[must_use]
    pub fn from_status(url: &str, status: u16, healthy: bool) -> Self {
        Self { url: url.to_string(), healthy, status: Some(status), error: None }
    }

    /// 退出码：健康 0，不健康 1。
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        if self.healthy { crate::exit::SUCCESS } else { crate::exit::VALIDATION_FAILED }
    }

    /// stdout 行（与其它 app 的探针格式一致）。
    #[must_use]
    pub fn stdout_line(&self) -> String {
        match self.status {
            Some(status) => format!("OK {status} {}", self.url),
            None => format!("FAIL {}", self.url),
        }
    }

    /// stderr 行（失败时）。
    #[must_use]
    pub fn stderr_line(&self) -> String {
        match (&self.status, &self.error) {
            (Some(status), _) => format!("FAIL {status} {}", self.url),
            (None, Some(err)) => format!("FAIL {}: {err}", self.url),
            (None, None) => format!("FAIL {}", self.url),
        }
    }
}

/// 执行探测（不做 IO 的纯逻辑之外的部分都在这里）。
///
/// # Errors
/// 探针不健康时返回携带退出码 1 的 [`AppError::Exit`]（消息已打印，不再重复）。
pub async fn run(url: &str, timeout_secs: u64, output: Output) -> Result<(), AppError> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs.max(1)))
        .build()
        .map_err(|e| AppError::Fatal(anyhow::anyhow!("构造 HTTP 客户端失败: {e}")))?;

    let outcome = match client.get(url).send().await {
        Ok(resp) => {
            let status = resp.status();
            HealthOutcome::from_status(url, status.as_u16(), status.is_success())
        }
        Err(e) => HealthOutcome::unreachable(url, e.to_string()),
    };

    if output.is_json() {
        output.emit(&serde_json::json!({ "ok": outcome.healthy, "report": outcome }))?;
    } else if outcome.healthy {
        output.line(&outcome.stdout_line());
    } else {
        output.error(&outcome.stderr_line());
    }

    if outcome.healthy { Ok(()) } else { Err(AppError::Exit(Exit::new(outcome.exit_code()))) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_maps_to_exit_zero_and_ok_line() {
        let ok = HealthOutcome::from_status("http://127.0.0.1:8080/healthz", 200, true);
        assert_eq!(ok.exit_code(), 0);
        assert_eq!(ok.stdout_line(), "OK 200 http://127.0.0.1:8080/healthz");
        assert!(ok.error.is_none());
    }

    #[test]
    fn non_2xx_maps_to_exit_one_with_fail_line() {
        let bad = HealthOutcome::from_status("http://127.0.0.1:8080/healthz", 503, false);
        assert_eq!(bad.exit_code(), 1);
        assert_eq!(bad.stderr_line(), "FAIL 503 http://127.0.0.1:8080/healthz");
    }

    #[test]
    fn network_error_maps_to_exit_one_and_carries_reason() {
        let err = HealthOutcome::unreachable("http://127.0.0.1:1/healthz", "connection refused");
        assert_eq!(err.exit_code(), 1);
        assert!(err.stderr_line().contains("connection refused"));
        assert!(err.stderr_line().starts_with("FAIL http://127.0.0.1:1/healthz:"));
        assert!(err.status.is_none());
    }

    #[test]
    fn outcome_serializes_status_and_error_conditionally() {
        let ok = serde_json::to_string(&HealthOutcome::from_status("u", 200, true)).unwrap_or_default();
        assert!(ok.contains("\"status\":200"));
        assert!(!ok.contains("error"), "健康时不应出现 error 字段: {ok}");
        let bad = serde_json::to_string(&HealthOutcome::unreachable("u", "boom")).unwrap_or_default();
        assert!(!bad.contains("status"), "网络错误时不应出现 status 字段: {bad}");
        assert!(bad.contains("boom"));
    }

    #[tokio::test]
    async fn run_against_closed_port_fails_with_exit_one() {
        // 127.0.0.1:1 必然不可达；探针必须给退出码 1 而不是 panic
        let err = run("http://127.0.0.1:1/healthz", 2, Output::silent()).await.expect_err("不可达必须失败");
        assert_eq!(err.exit_code(), 1, "探针失败是判定失败（1），不是依赖不可用（2）");
        assert!(matches!(err, AppError::Exit(ref e) if e.message().is_none()));
    }
}
