//! 由 `config.rs` 拆分：`base_env` 等 15 个函数（纯搬移，逻辑不变）。

use std::collections::BTreeMap;

use super::*;

pub(crate) fn base_env() -> BTreeMap<String, String> {
    BTreeMap::new()
}

#[test]
pub(crate) fn defaults_parse_without_any_env() {
    let cfg = from_env_map(&base_env());
    assert!(cfg.is_ok(), "空环境应能解析出全部默认值");
    let Ok(cfg) = cfg else { return };
    assert_eq!(cfg.env, RunEnv::Dev);
    assert!(cfg.mock_mode, "默认必须开启 Mock 模式（离线可演示）");
    assert_eq!(cfg.server.port, 8080);
    assert_eq!(cfg.database.port, 5432);
    assert_eq!(cfg.server.api_prefix, "/api/v1");
    assert!(!cfg.adapter_enabled("qingteng"));
}

#[test]
pub(crate) fn env_overrides_are_applied() {
    let mut env = base_env();
    env.insert("AGF_ENV".into(), "prod".into());
    env.insert("AGF_SERVER_PORT".into(), "9999".into());
    env.insert("AGF_MOCK_MODE".into(), "0".into());
    env.insert("AGF_QINGTENG_ENABLED".into(), "true".into());
    env.insert("AGF_LOG_FORMAT".into(), "json".into());
    let cfg = from_env_map(&env);
    assert!(cfg.is_ok());
    let Ok(cfg) = cfg else { return };
    assert_eq!(cfg.env, RunEnv::Prod);
    assert_eq!(cfg.server.port, 9999);
    assert!(!cfg.mock_mode);
    assert!(cfg.adapter_enabled("qingteng"));
    assert_eq!(cfg.log_format, LogFormat::Json);
}

#[test]
pub(crate) fn invalid_values_are_rejected() {
    let mut env = base_env();
    env.insert("AGF_SERVER_PORT".into(), "not-a-port".into());
    assert!(from_env_map(&env).is_err());

    let mut env2 = base_env();
    env2.insert("AGF_MOCK_MODE".into(), "maybe".into());
    assert!(from_env_map(&env2).is_err());

    let mut env3 = base_env();
    env3.insert("AGF_ENV".into(), "staging".into());
    assert!(from_env_map(&env3).is_err());

    let mut env4 = base_env();
    env4.insert("AGF_LOG_FORMAT".into(), "xml".into());
    assert!(from_env_map(&env4).is_err());
}

#[test]
pub(crate) fn boolean_encodings_accepted() {
    for v in ["1", "true", "TRUE", "yes", "on"] {
        let mut env = base_env();
        env.insert("AGF_MOCK_MODE".into(), v.to_string());
        let cfg = from_env_map(&env);
        assert!(cfg.is_ok(), "值 {v} 应被接受");
        assert!(cfg.map(|c| c.mock_mode).unwrap_or(false), "值 {v} 应视为 true");
    }
    for v in ["0", "false", "no", "off"] {
        let mut env = base_env();
        env.insert("AGF_MOCK_MODE".into(), v.to_string());
        let cfg = from_env_map(&env);
        assert!(cfg.is_ok(), "值 {v} 应被接受");
        assert!(!cfg.map(|c| c.mock_mode).unwrap_or(true), "值 {v} 应视为 false");
    }
}

#[test]
pub(crate) fn debug_output_masks_secrets() {
    let mut env = base_env();
    env.insert("AGF_PG_PASSWORD".into(), "SuperSecretDbPassword123".into());
    env.insert("AGF_JWT_SECRET".into(), "SuperSecretJwtSecretValue1234567890".into());
    env.insert("AGF_MASTER_KEY_BASE64".into(), "SuperSecretMasterKeyBase64Value==".into());
    let Ok(cfg) = from_env_map(&env) else { return };
    let dbg = format!("{cfg:?}");
    assert!(!dbg.contains("SuperSecretDbPassword123"), "DB 口令泄露到 Debug: {dbg}");
    assert!(!dbg.contains("SuperSecretJwtSecretValue1234567890"), "JWT 密钥泄露到 Debug");
    assert!(!dbg.contains("SuperSecretMasterKeyBase64Value"), "主密钥泄露到 Debug");
    assert!(dbg.contains("mock_mode"));
}

#[test]
pub(crate) fn masked_dsn_hides_password() {
    let db = DatabaseConfig { password: "SuperSecretDbPassword123".into(), ..DatabaseConfig::default() };
    let masked = db.masked_dsn();
    assert!(!masked.contains("SuperSecretDbPassword123"));
    assert!(masked.contains("agf"));
    assert!(db.dsn().contains("SuperSecretDbPassword123"), "真实 DSN 必须含口令（用于连接）");
}

#[test]
pub(crate) fn masked_redis_url_hides_password() {
    let r = RedisConfig { url: "redis://agf:SuperSecret@127.0.0.1:6379/0".into(), ..RedisConfig::default() };
    let masked = r.masked_url();
    assert!(!masked.contains("SuperSecret"), "Redis 口令泄露: {masked}");
    assert!(masked.contains("127.0.0.1:6379"));
    let plain = RedisConfig { url: "redis://127.0.0.1:6379/0".into(), ..RedisConfig::default() };
    assert_eq!(plain.masked_url(), "redis://127.0.0.1:6379/0");
}

#[test]
pub(crate) fn prod_rejects_placeholder_secrets() {
    let mut env = base_env();
    env.insert("AGF_ENV".into(), "prod".into());
    env.insert("AGF_MOCK_MODE".into(), "0".into());
    let Ok(cfg) = from_env_map(&env) else { return };
    let res = cfg.enforce_safety();
    assert!(res.is_err(), "生产环境使用占位密钥必须拒绝启动");
    let msg = res.err().map(|e| e.to_string()).unwrap_or_default();
    assert!(msg.contains("JWT"));
    assert!(msg.contains("MASTER_KEY"));
}

#[test]
pub(crate) fn prod_accepts_strong_secrets() {
    let mut env = base_env();
    env.insert("AGF_ENV".into(), "prod".into());
    env.insert("AGF_MOCK_MODE".into(), "0".into());
    env.insert("AGF_JWT_SECRET".into(), "9f2a7c1e4b8d6f3a0c5e9b2d7f4a1c8e".into());
    env.insert("AGF_MASTER_KEY_BASE64".into(), base64_of_32());
    env.insert("AGF_PG_PASSWORD".into(), "Str0ngDbPassw0rd!2026".into());
    env.insert("AGF_FINGERPRINT_SALT".into(), "s".into());
    let Ok(cfg) = from_env_map(&env) else { return };
    let res = cfg.enforce_safety();
    assert!(res.is_ok(), "合法生产配置应通过: {:?}", res.err().map(|e| e.to_string()));
    assert_eq!(cfg.security.master_key_len(), 32);
}

pub(crate) fn base64_of_32() -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode([7_u8; 32])
}

#[test]
pub(crate) fn dev_only_warns() {
    let mut env = base_env();
    env.insert("AGF_ENV".into(), "dev".into());
    let Ok(cfg) = from_env_map(&env) else { return };
    let res = cfg.enforce_safety();
    assert!(res.is_ok(), "开发环境不应因弱配置拒绝启动");
    let warns = res.unwrap_or_default();
    assert!(!warns.is_empty(), "应产出警告列表");
}

#[test]
pub(crate) fn server_bind_addr() {
    let s = ServerConfig::default();
    assert_eq!(s.bind_addr(), "0.0.0.0:8080");
}

#[test]
pub(crate) fn s3_configured_detection() {
    let mut s = S3Config {
        endpoint: "http://127.0.0.1:9000".into(),
        region: "us-east-1".into(),
        bucket: "b".into(),
        access_key: "k".into(),
        secret_key: "s".into(),
        force_path_style: true,
    };
    assert!(s.is_configured());
    s.secret_key = String::new();
    assert!(!s.is_configured());
}

#[test]
pub(crate) fn device_adapter_matrix_populated() {
    let Ok(cfg) = from_env_map(&base_env()) else { return };
    assert_eq!(cfg.device_adapters.len(), 13, "应覆盖全部内置设备适配器开关");
    assert!(cfg.device_adapters.contains_key("fortinet"));
    assert!(cfg.device_adapters.contains_key("alicloud-waf"));
}
