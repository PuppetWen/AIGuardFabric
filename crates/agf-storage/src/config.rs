//! 存储层配置（从 `agf_core::config::AppConfig` 映射而来，避免上层直接依赖环境变量解析）。

use std::path::PathBuf;

use agf_core::config::AppConfig;
use agf_core::credential::KeyBackend;
use agf_core::error::{DomainError, DomainResult};

/// 存储层配置。
#[derive(Debug, Clone)]
pub struct StorageConfig {
    // ---- PostgreSQL ----
    /// 主机。
    pub pg_host: String,
    /// 端口。
    pub pg_port: u16,
    /// 库名。
    pub pg_database: String,
    /// 用户名。
    pub pg_user: String,
    /// 口令。
    pub pg_password: String,
    /// 是否强制 TLS（生产建议 true）。
    pub pg_require_tls: bool,
    /// 连接池上限。
    pub pg_pool_max: u32,
    /// 连接池下限。
    pub pg_pool_min: u32,
    /// 连接超时（秒）。
    pub pg_connect_timeout_secs: u64,

    // ---- Redis ----
    /// 连接 URL。
    pub redis_url: String,
    /// 键前缀。
    pub redis_prefix: String,
    /// 连接超时（秒）。
    pub redis_connect_timeout_secs: u64,

    // ---- 对象存储 ----
    /// 端点。
    pub s3_endpoint: String,
    /// 区域。
    pub s3_region: String,
    /// 桶。
    pub s3_bucket: String,
    /// Access Key。
    pub s3_access_key: String,
    /// Secret Key。
    pub s3_secret_key: String,
    /// 强制 path-style。
    pub s3_force_path_style: bool,

    // ---- 本地路径 ----
    /// 数据卷根目录。
    pub data_dir: PathBuf,
    /// 迁移目录（用于 `agfctl migrate --dir` 与文档展示）。
    pub migrations_dir: PathBuf,

    // ---- 加密 ----
    /// 主密钥 base64。
    pub master_key_b64: String,
    /// 主密钥版本标识（轮换时递增）。
    pub master_key_id: String,
    /// 密钥后端。
    pub key_backend: KeyBackend,
    /// 指纹盐（凭据指纹用）。
    pub fingerprint_salt: String,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            pg_host: "127.0.0.1".to_string(),
            pg_port: 5432,
            pg_database: "aiguardfabric".to_string(),
            pg_user: "agf".to_string(),
            pg_password: String::new(),
            pg_require_tls: false,
            pg_pool_max: 20,
            pg_pool_min: 2,
            pg_connect_timeout_secs: 10,
            redis_url: "redis://127.0.0.1:6379/0".to_string(),
            redis_prefix: "agf".to_string(),
            redis_connect_timeout_secs: 5,
            s3_endpoint: String::new(),
            s3_region: "us-east-1".to_string(),
            s3_bucket: "agf-evidence".to_string(),
            s3_access_key: String::new(),
            s3_secret_key: String::new(),
            s3_force_path_style: true,
            data_dir: PathBuf::from("./data"),
            migrations_dir: PathBuf::from("./deploy/sql/migrations"),
            master_key_b64: String::new(),
            master_key_id: "v1".to_string(),
            key_backend: KeyBackend::LocalFile,
            fingerprint_salt: "aiguardfabric-default-salt".to_string(),
        }
    }
}

impl From<&AppConfig> for StorageConfig {
    fn from(cfg: &AppConfig) -> Self {
        let key_backend = parse_key_backend(&cfg.security.kms_backend);
        Self {
            pg_host: cfg.database.host.clone(),
            pg_port: cfg.database.port,
            pg_database: cfg.database.database.clone(),
            pg_user: cfg.database.user.clone(),
            pg_password: cfg.database.password.clone(),
            pg_require_tls: cfg.env.is_prod(),
            pg_pool_max: cfg.database.pool_max,
            pg_pool_min: cfg.database.pool_min,
            pg_connect_timeout_secs: cfg.database.connect_timeout_secs,
            redis_url: cfg.redis.url.clone(),
            redis_prefix: cfg.redis.key_prefix.clone(),
            redis_connect_timeout_secs: 5,
            s3_endpoint: cfg.s3.endpoint.clone(),
            s3_region: cfg.s3.region.clone(),
            s3_bucket: cfg.s3.bucket.clone(),
            s3_access_key: cfg.s3.access_key.clone(),
            s3_secret_key: cfg.s3.secret_key.clone(),
            s3_force_path_style: cfg.s3.force_path_style,
            data_dir: PathBuf::from(&cfg.data_dir),
            migrations_dir: PathBuf::from(&cfg.project_root).join("deploy/sql/migrations"),
            master_key_b64: cfg.security.master_key_b64.clone(),
            master_key_id: "v1".to_string(),
            key_backend,
            fingerprint_salt: cfg.security.fingerprint_salt.clone(),
        }
    }
}

/// 解析密钥后端名。
#[must_use]
pub fn parse_key_backend(raw: &str) -> KeyBackend {
    match raw.to_ascii_lowercase().as_str() {
        "aliyun-kms" | "kms" => KeyBackend::AliyunKms,
        "aws-kms" => KeyBackend::AwsKms,
        "vault" => KeyBackend::Vault,
        "mock" => KeyBackend::Mock,
        _ => KeyBackend::LocalFile,
    }
}

impl StorageConfig {
    /// PostgreSQL DSN（含口令，**不要写日志**）。
    #[must_use]
    pub fn pg_dsn(&self) -> String {
        format!(
            "postgres://{}:{}@{}:{}/{}",
            self.pg_user, self.pg_password, self.pg_host, self.pg_port, self.pg_database
        )
    }

    /// 校验关键配置；开发环境只给出可运行的默认行为。
    ///
    /// # Errors
    /// 生产环境缺少主密钥或口令时返回错误。
    pub fn validate(&self, prod: bool) -> DomainResult<Vec<String>> {
        let mut warnings = Vec::new();
        if self.pg_password.is_empty() {
            if prod {
                return Err(DomainError::Config("生产环境必须设置 AGF_PG_PASSWORD".to_string()));
            }
            warnings.push("未设置数据库口令（开发环境允许，生产会拒绝启动）".to_string());
        }
        if self.master_key_b64.is_empty() || self.master_key_b64.contains("CHANGE_ME") {
            if prod {
                return Err(DomainError::Config(
                    "生产环境必须设置 AGF_MASTER_KEY_BASE64（32 字节 base64，可用 agfctl genkey 生成）".to_string(),
                ));
            }
            warnings.push("未设置主密钥：凭据加密功能不可用（`agfctl genkey` 生成后写入 .env）".to_string());
        }
        if self.s3_endpoint.is_empty() {
            warnings.push("未配置对象存储，证据包将落本地 <data_dir>/objects".to_string());
        }
        Ok(warnings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn default_config_is_dev_friendly() {
        let c = StorageConfig::default();
        assert!(c.validate(false).is_ok());
        assert_eq!(c.pg_port, 5432);
        assert!(c.pg_dsn().starts_with("postgres://agf:"));
    }

    #[test]
    fn prod_requires_password_and_master_key() {
        let c = StorageConfig::default();
        let err = c.validate(true);
        assert!(err.is_err());
        let msg = err.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(msg.contains("AGF_PG_PASSWORD"));
    }

    #[test]
    fn prod_passes_with_secrets() {
        let c = StorageConfig {
            pg_password: "Str0ngPassw0rd!2026".to_string(),
            master_key_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            ..StorageConfig::default()
        };
        assert!(c.validate(true).is_ok());
    }

    #[test]
    fn key_backend_parsing() {
        assert_eq!(parse_key_backend("aliyun-kms"), KeyBackend::AliyunKms);
        assert_eq!(parse_key_backend("AWS-KMS"), KeyBackend::AwsKms);
        assert_eq!(parse_key_backend("vault"), KeyBackend::Vault);
        assert_eq!(parse_key_backend("mock"), KeyBackend::Mock);
        assert_eq!(parse_key_backend("whatever"), KeyBackend::LocalFile);
    }

    #[test]
    fn maps_from_app_config() {
        let env: BTreeMap<String, String> = [
            ("AGF_PG_HOST", "db.internal"),
            ("AGF_PG_PORT", "6543"),
            ("AGF_PG_PASSWORD", "Secret123456789"),
            ("AGF_MASTER_KEY_BASE64", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
            ("AGF_KMS_BACKEND", "vault"),
            ("AGF_DATA_DIR", "D:/agf/data"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let cfg = agf_core::config::from_env_map(&env);
        assert!(cfg.is_ok());
        let Ok(cfg) = cfg else { return };
        let sc = StorageConfig::from(&cfg);
        assert_eq!(sc.pg_host, "db.internal");
        assert_eq!(sc.pg_port, 6543);
        assert_eq!(sc.key_backend, KeyBackend::Vault);
        assert!(sc.pg_dsn().contains("db.internal:6543"));
        assert!(sc.data_dir.to_string_lossy().contains("agf"));
    }
}
