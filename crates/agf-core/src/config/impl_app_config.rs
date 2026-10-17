//! 由 `config.rs` 拆分：`AppConfig` 的实现（纯搬移，逻辑不变）。
use super::*;

use crate::error::{DomainError, DomainResult};
use crate::secret::mask_default;

impl AppConfig {
    /// 生产环境安全校验。
    ///
    /// 开发环境只产出警告，生产环境直接拒绝启动（安全基线 §2.6）。
    ///
    /// # Errors
    /// 生产环境下存在高危配置时返回错误。
    pub fn enforce_safety(&self) -> DomainResult<Vec<String>> {
        let mut warnings: Vec<String> = Vec::new();
        if !self.security.jwt_secret_strong_enough() {
            warnings.push("AGF_JWT_SECRET 长度不足 32 字节或仍为占位值".to_string());
        }
        if self.security.master_key_is_placeholder() {
            warnings.push("AGF_MASTER_KEY_BASE64 未配置（应为 32 字节 base64）".to_string());
        } else if self.security.master_key_len() != crate::constants::MASTER_KEY_BYTES {
            warnings.push(format!(
                "AGF_MASTER_KEY_BASE64 解码后为 {} 字节，应为 {} 字节",
                self.security.master_key_len(),
                crate::constants::MASTER_KEY_BYTES
            ));
        }
        if self.database.uses_placeholder_password() {
            warnings.push("AGF_PG_PASSWORD 为占位值或强度不足".to_string());
        }
        if !self.security.force_password_change {
            warnings.push("AGF_FORCE_PASSWORD_CHANGE 已关闭，不满足首登强制改密基线".to_string());
        }
        if self.security.bootstrap_admin_user == "admin" && !self.security.bootstrap_admin_password.is_empty() {
            warnings.push("引导管理员使用默认用户名且显式设置了口令，请改为随机生成".to_string());
        }
        if self.mock_mode && self.env.is_prod() {
            warnings.push("生产环境仍开启 AGF_MOCK_MODE，所有外部适配器返回模拟数据".to_string());
        }
        if self.env.is_prod() && !warnings.is_empty() {
            return Err(DomainError::Config(format!("生产环境安全检查未通过: {}", warnings.join("；"))));
        }
        Ok(warnings)
    }

    /// 适配器是否启用。
    #[must_use]
    pub fn adapter_enabled(&self, name: &str) -> bool {
        self.device_adapters.get(name).copied().unwrap_or(false)
    }

    /// 全部外部依赖是否都应走 Mock。
    #[must_use]
    pub const fn force_mock(&self) -> bool {
        self.mock_mode
    }
}

impl std::fmt::Debug for AppConfig {
    /// 自动打码所有密钥字段（保证 `?config` 可安全打印）。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppConfig")
            .field("env", &self.env)
            .field("mock_mode", &self.mock_mode)
            .field("degrade_on_missing", &self.degrade_on_missing)
            .field("log_level", &self.log_level)
            .field("log_format", &self.log_format)
            .field("project_root", &self.project_root)
            .field("data_dir", &self.data_dir)
            .field("server", &self.server)
            .field("database", &format_args!("{}", self.database.masked_dsn()))
            .field("redis", &format_args!("{}", self.redis.masked_url()))
            .field("nats", &self.nats)
            .field("clickhouse_enabled", &self.clickhouse.enabled)
            .field("s3_endpoint", &self.s3.endpoint)
            .field("jwt_secret", &format_args!("{}", mask_default(&self.security.jwt_secret)))
            .field("master_key", &format_args!("{}", mask_default(&self.security.master_key_b64)))
            .field("bootstrap_admin", &self.security.bootstrap_admin_user)
            .field("quota", &self.quota)
            .field("observability", &self.observability)
            .finish_non_exhaustive()
    }
}
