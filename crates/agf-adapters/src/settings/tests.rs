//! 由 `settings.rs` 拆分：`meta` 等 13 个函数（纯搬移，逻辑不变）。
use super::*;

pub(crate) fn meta() -> AdapterMetadata {
    AdapterMetadata::new("feishu", "飞书机器人", "字节跳动", crate::contract::AdapterCategory::Notification)
        .with_secrets(&["webhook_url"], &["signing_secret"])
        .with_capabilities(vec![AdapterCapability::PushEvents])
}

pub(crate) fn config(settings: BTreeMap<String, serde_json::Value>) -> AdapterConfig {
    let now = agf_core::time::Timestamp::now();
    AdapterConfig {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        adapter: "feishu".into(),
        display_name: "飞书".into(),
        enabled: true,
        settings,
        secret_refs: BTreeMap::new(),
        circuit_breaker: CircuitBreakerConfig::default(),
        retry: RetryConfig::default(),
        timeout_secs: 30,
        mock: false,
        is_default: true,
        created_at: now,
        updated_at: now,
    }
}

#[test]
pub(crate) fn env_key_composition_is_canonical() {
    assert_eq!(env_key_for("AGF_ADAPTER", "feishu", "webhook_url"), "AGF_ADAPTER_FEISHU_WEBHOOK_URL");
    assert_eq!(env_key_for("agf", "my-vendor", "api-token"), "AGF_MY_VENDOR_API_TOKEN");
}

#[test]
pub(crate) fn static_lookup_does_not_leak_in_debug() {
    let secrets = StaticSecrets::new().with("webhook_url", "https://example.invalid/hook/secret-token-1234");
    let mut cfg = config(BTreeMap::new());
    cfg.settings.insert("timeout".into(), serde_json::json!(15));
    let settings = AdapterSettings::from_config(&meta(), &cfg, &secrets);
    assert!(settings.is_ok());
    let Ok(settings) = settings else { return };
    let text = format!("{settings:?}");
    assert!(!text.contains("secret-token-1234"), "Debug 不得泄露凭据: {text}");
    assert!(text.contains("webhook_url"), "但必须显示凭据键名便于排障");
    assert_eq!(settings.secret_raw("webhook_url"), Some("https://example.invalid/hook/secret-token-1234"));
}

#[test]
pub(crate) fn static_lookup_prefers_adapter_scoped_key() {
    let secrets = StaticSecrets::new().with("webhook_url", "shared").with("feishu:webhook_url", "scoped");
    assert_eq!(
        secrets.lookup("feishu", "webhook_url").map(|v| v.expose_secret().to_string()),
        Some("scoped".to_string())
    );
    assert_eq!(
        secrets.lookup("slack", "webhook_url").map(|v| v.expose_secret().to_string()),
        Some("shared".to_string())
    );
    assert!(secrets.lookup("any", "missing").is_none());
    assert_eq!(secrets.get("feishu:webhook_url"), Some("scoped"));
}

#[test]
pub(crate) fn no_secrets_never_resolves() {
    let settings = AdapterSettings::from_config(&meta(), &config(BTreeMap::new()), &NoSecrets);
    assert!(settings.is_ok());
    let Ok(settings) = settings else { return };
    assert!(!settings.has_secret("webhook_url"));
    assert_eq!(settings.missing_secrets(), vec!["webhook_url"]);
    assert!(!settings.is_configured());
}

#[test]
pub(crate) fn resolve_endpoint_prefers_settings_then_secret() {
    let secrets = StaticSecrets::new().with("webhook_url", "https://hook.example.invalid/abc");
    let mut cfg = config(BTreeMap::new());
    cfg.settings.insert("endpoint".into(), serde_json::json!("https://set.example.invalid/x"));
    let settings =
        AdapterSettings::from_config(&meta(), &cfg, &secrets).unwrap_or_else(|_| AdapterSettings::defaults(&meta()));
    // endpoint_key 未在元信息声明时 resolve 走 secret 分支
    assert_eq!(
        settings.resolve_endpoint(Some("webhook_url")).ok().as_deref(),
        Some("https://hook.example.invalid/abc")
    );
    assert!(settings.resolve_endpoint(None).is_err() || settings.endpoint.is_some());
}

#[test]
pub(crate) fn invalid_timeout_is_rejected() {
    let mut cfg = config(BTreeMap::new());
    cfg.timeout_secs = 0;
    let err = AdapterSettings::from_config(&meta(), &cfg, &NoSecrets);
    assert!(matches!(err, Err(DomainError::Config(_))), "超时为 0 必须被判为非法配置");
    cfg.timeout_secs = MAX_TIMEOUT_SECS + 1;
    assert!(AdapterSettings::from_config(&meta(), &cfg, &NoSecrets).is_err());
}

#[test]
pub(crate) fn invalid_retry_and_circuit_are_rejected() {
    let mut cfg = config(BTreeMap::new());
    cfg.retry.max_attempts = 0;
    assert!(AdapterSettings::from_config(&meta(), &cfg, &NoSecrets).is_err());
    cfg.retry.max_attempts = 3;
    cfg.retry.initial_backoff_ms = 5_000;
    cfg.retry.max_backoff_ms = 100;
    assert!(AdapterSettings::from_config(&meta(), &cfg, &NoSecrets).is_err());
    cfg.retry = RetryConfig::default();
    cfg.circuit_breaker.failure_threshold = 0;
    assert!(AdapterSettings::from_config(&meta(), &cfg, &NoSecrets).is_err());
    cfg.circuit_breaker = CircuitBreakerConfig::default();
    cfg.circuit_breaker.open_secs = 0;
    assert!(AdapterSettings::from_config(&meta(), &cfg, &NoSecrets).is_err());
}

#[test]
pub(crate) fn invalid_endpoint_is_rejected() {
    let mut cfg = config(BTreeMap::new());
    cfg.settings.insert("endpoint".into(), serde_json::json!("not a url"));
    let meta = meta().with_endpoint_key("endpoint");
    assert!(matches!(AdapterSettings::from_config(&meta, &cfg, &NoSecrets), Err(DomainError::Config(_))));
    cfg.settings.insert("endpoint".into(), serde_json::json!("ftp://example.invalid/x"));
    assert!(AdapterSettings::from_config(&meta, &cfg, &NoSecrets).is_err(), "scheme 白名单外必须拒绝");
    cfg.settings.insert("endpoint".into(), serde_json::json!("https://syslog.example.invalid:514"));
    assert!(AdapterSettings::from_config(&meta, &cfg, &NoSecrets).is_ok());
}

#[test]
pub(crate) fn invalid_sync_conflict_policy_is_rejected_not_silently_defaulted() {
    let mut cfg = config(BTreeMap::new());
    cfg.settings.insert(crate::contract::SETTING_CONFLICT_POLICY.into(), serde_json::json!("whatever"));
    let error = AdapterSettings::from_config(&meta(), &cfg, &NoSecrets).expect_err("非法冲突策略必须报配置错误");
    assert!(matches!(error, DomainError::Config(_)), "{error}");
    assert!(error.to_string().contains("sync_conflict_policy"), "{error}");

    for value in ["external-wins", "local-wins", "外部优先", "本地优先"] {
        let mut ok = config(BTreeMap::new());
        ok.settings.insert(crate::contract::SETTING_CONFLICT_POLICY.into(), serde_json::json!(value));
        let settings = AdapterSettings::from_config(&meta(), &ok, &NoSecrets).expect("合法策略");
        assert!(crate::contract::ConflictPolicy::parse(value).is_some());
        assert!(settings.get_str(crate::contract::SETTING_CONFLICT_POLICY).is_some());
    }
}

#[test]
pub(crate) fn validate_endpoint_accepts_non_http_channels() {
    for ep in ["syslog://10.0.0.1:514", "udp://10.0.0.1:5514", "smtp://mail.example.invalid:587"] {
        assert!(validate_endpoint(ep).is_ok(), "{ep} 应被接受");
    }
    assert!(validate_endpoint("").is_err());
    assert!(validate_endpoint("https://").is_err());
}

#[test]
pub(crate) fn mode_helpers() {
    assert!(AdapterMode::Mocked.is_mock());
    assert!(!AdapterMode::Mocked.is_live());
    assert_eq!(AdapterMode::Live.as_str(), "live");
    assert_eq!(AdapterMode::Unconfigured.as_str(), "unconfigured");
}

#[test]
pub(crate) fn missing_settings_detection() {
    let mut settings = AdapterSettings::defaults(&meta()).with_required_settings(&["smtp_host"]);
    assert_eq!(settings.missing_settings(), vec!["smtp_host"]);
    assert!(!settings.is_configured());
    settings.settings.insert("smtp_host".into(), serde_json::json!("mail.example.invalid"));
    assert!(settings.missing_settings().is_empty());
}
