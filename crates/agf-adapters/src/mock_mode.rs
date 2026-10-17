//! Mock 模式判定（`AGF_MOCK_MODE`）。
//!
//! 与 `agf-alicloud::mock_mode_from_env` 保持同一语义（`1` / `true` / `yes` / `on`，
//! 大小写不敏感），但额外提供**纯函数** [`parse_mock_mode`]：
//! 环境变量在 edition 2024 下只能经 `unsafe` 设置，测试无法写环境，
//! 因此解析逻辑必须可独立单测。

/// Mock 模式环境变量名（复用 `agf-core` 的常量，避免两处口径漂移）。
pub const MOCK_MODE_ENV: &str = agf_core::constants::ENV_MOCK_MODE;

/// 解析 Mock 模式开关文本。
///
/// 接受 `1` / `true` / `yes` / `on`（前后空白忽略、大小写不敏感），
/// 其余一切取值（含空串）视为**关闭**。
#[must_use]
pub fn parse_mock_mode(value: &str) -> bool {
    matches!(value.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
}

/// 读取进程环境中的 [`MOCK_MODE_ENV`]。
#[must_use]
pub fn mock_mode_from_env() -> bool {
    std::env::var(MOCK_MODE_ENV).is_ok_and(|v| parse_mock_mode(&v))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_truthy_values() {
        for v in ["1", "true", "TRUE", " yes ", "On"] {
            assert!(parse_mock_mode(v), "{v} 应判为 Mock 模式");
        }
    }

    #[test]
    fn parses_falsy_values() {
        for v in ["0", "false", "no", "off", "", "  ", "2", "enabled"] {
            assert!(!parse_mock_mode(v), "{v} 不应判为 Mock 模式");
        }
    }

    #[test]
    fn env_constant_matches_core() {
        assert_eq!(MOCK_MODE_ENV, "AGF_MOCK_MODE");
    }
}
