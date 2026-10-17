//! 由 `credential.rs` 拆分：`ctx` 等 17 个函数（纯搬移，逻辑不变）。
use super::*;

pub(crate) fn ctx(now: Timestamp) -> CredentialContext {
    CredentialContext::new(MapSecretStore::shared(&[]), false).with_now(now)
}

#[test]
pub(crate) fn debug_impl_never_leaks_secret() {
    let cred = CloudCredential::long_term("LTAI5tSecretId000", "SuperSecretValue");
    let text = format!("{cred:?}");
    assert!(!text.contains("SuperSecretValue"), "Debug 不得输出明文 secret: {text}");
    assert!(text.contains("<redacted>"));
}

#[test]
pub(crate) fn masked_description_is_safe() {
    let cred = CloudCredential::long_term("LTAI5tSecretId000", "sk");
    let text = cred.masked();
    assert!(text.starts_with("long-term-ak:"));
    assert!(!text.contains("sk"));
}

#[test]
pub(crate) fn static_resolver_returns_credential_and_warns_on_long_term() {
    let now = Timestamp::now();
    let resolver = StaticResolver::long_term("LTAI5tAbCdEfGhIjKlMn", "sk-secret");
    let integration = fixture_integration(CloudCredentialKind::LongTermAk, "1234567890");
    let outcome = resolver.resolve(&integration, &ctx(now));
    assert!(outcome.is_ok());
    let Some(outcome) = outcome.ok() else { return };
    assert!(outcome.long_lived_risk, "长期 AK 必须标记风险");
    assert_eq!(outcome.warnings.len(), 1);
    assert_eq!(outcome.warnings[0].name, "credential:long-term-ak");
    assert!(!outcome.warnings[0].required, "风险项不阻断接入，但自检页标红");
    let check = outcome.warnings[0].to_check(now);
    assert!(!check.passed);
    assert!(!check.is_blocking());
}

#[test]
pub(crate) fn assume_role_kind_is_not_long_lived() {
    let now = Timestamp::now();
    let cred = CloudCredential::sts("STS.abc", "sk", "token", now.offset_secs(3_600), CloudCredentialKind::AssumeRole);
    let outcome =
        StaticResolver::new(cred).resolve(&fixture_integration(CloudCredentialKind::AssumeRole, "999"), &ctx(now));
    assert!(outcome.is_ok());
    let Some(outcome) = outcome.ok() else { return };
    assert!(!outcome.long_lived_risk);
    assert!(outcome.warnings.is_empty());
}

#[test]
pub(crate) fn invalid_credential_is_rejected() {
    let empty = CloudCredential {
        access_key_id: String::new(),
        access_key_secret: "x".to_string(),
        security_token: None,
        expires_at: None,
        kind: CloudCredentialKind::LongTermAk,
    };
    assert!(empty.validate().is_err());
    let no_secret = CloudCredential {
        access_key_id: "ak".to_string(),
        access_key_secret: String::new(),
        security_token: None,
        expires_at: None,
        kind: CloudCredentialKind::LongTermAk,
    };
    assert!(no_secret.validate().is_err());
}

#[test]
pub(crate) fn expiry_detection_and_refresh_threshold() {
    let now = Timestamp::now();
    let expiring = CloudCredential::sts("ak", "sk", "t", now.offset_secs(600), CloudCredentialKind::StsToken);
    assert!(expiring.is_expiring_soon(now));
    assert!(!expiring.is_expired(now));
    let expired = CloudCredential::sts("ak", "sk", "t", now.offset_secs(-1), CloudCredentialKind::StsToken);
    assert!(expired.is_expired(now));
    assert!(expired.is_expiring_soon(now));
    let fresh = CloudCredential::sts("ak", "sk", "t", now.offset_secs(3_600), CloudCredentialKind::StsToken);
    assert!(!fresh.is_expiring_soon(now));
    assert!(!fresh.is_expired(now));
    let long_lived = CloudCredential::long_term("ak", "sk");
    assert!(!long_lived.is_expiring_soon(now), "长期 AK 无过期时间");
}

#[test]
pub(crate) fn refreshable_credential_reuses_cache_until_expiring() {
    let now = Timestamp::now();
    let cred = CloudCredential::sts("ak", "sk", "t", now.offset_secs(7_200), CloudCredentialKind::StsToken);
    let refreshable = RefreshableCredential::new(Arc::new(StaticResolver::new(cred)));
    let integration = fixture_integration(CloudCredentialKind::StsToken, "1");
    assert!(refreshable.should_refresh(now).unwrap_or(false), "首次必须刷新");
    let first = refreshable.resolve(&integration, &ctx(now));
    assert!(first.is_ok());
    assert!(!refreshable.should_refresh(now).unwrap_or(true), "新鲜凭据不应刷新");
    // 过期后必须重新解析
    assert!(refreshable.should_refresh(now.offset_secs(7_000)).unwrap_or(false));
    assert!(refreshable.invalidate().is_ok());
    assert!(refreshable.should_refresh(now).unwrap_or(false));
    assert!(refreshable.cached().is_ok_and(|c| c.is_none()));
}

#[test]
pub(crate) fn env_resolver_reports_missing_config_as_config_error() {
    let now = Timestamp::now();
    // 空读取口 = 所有环境变量都缺，且不触碰真实进程环境
    let resolver = EnvResolver::with_prefix("AGF_ALIYUN_TEST_MISSING_").with_getter(Arc::new(|_| None));
    let err = resolver.resolve(&fixture_integration(CloudCredentialKind::LongTermAk, "42"), &ctx(now));
    assert!(matches!(err, Err(DomainError::Config(_))), "缺配置必须是 Config 错误: {err:?}");
    assert_eq!(resolver.name(), "env");
}

#[test]
pub(crate) fn env_resolver_reads_values_and_marks_sts() {
    let now = Timestamp::now();
    let prefix = "AGF_ALIYUN_TEST_ENV_";
    let getter: EnvGetter = {
        let prefix = prefix.to_string();
        Arc::new(move |key: &str| {
            let suffix = key.strip_prefix(&prefix)?;
            match suffix {
                "ACCESS_KEY_ID" => Some("LTAI5tUnitTestAk000".to_string()),
                "ACCESS_KEY_SECRET" => Some("unit-test-secret".to_string()),
                "SECURITY_TOKEN" => Some("sts-token-value".to_string()),
                "SECURITY_TOKEN_EXPIRATION" => Some(now.offset_secs(3600).to_rfc3339()),
                _ => None,
            }
        })
    };
    let resolver = EnvResolver::with_prefix(prefix).with_getter(getter);
    let outcome = resolver.resolve(&fixture_integration(CloudCredentialKind::StsToken, "42"), &ctx(now));
    assert!(outcome.is_ok(), "{outcome:?}");
    if let Ok(outcome) = outcome {
        assert_eq!(outcome.credential.kind, CloudCredentialKind::StsToken);
        assert_eq!(outcome.credential.security_token.as_deref(), Some("sts-token-value"));
        assert!(outcome.credential.expires_at.is_some());
        assert!(!outcome.long_lived_risk);
    }
}

#[test]
pub(crate) fn env_resolver_without_token_is_long_term_and_warns() {
    let now = Timestamp::now();
    let getter: EnvGetter = Arc::new(|key: &str| match key {
        "AGF_ALIYUN_ACCESS_KEY_ID" => Some("LTAI5tEnvAk0000000000".to_string()),
        "AGF_ALIYUN_ACCESS_KEY_SECRET" => Some("env-secret".to_string()),
        _ => None,
    });
    let resolver = EnvResolver::new().with_getter(getter);
    let outcome = resolver.resolve(&fixture_integration(CloudCredentialKind::LongTermAk, "42"), &ctx(now));
    assert!(outcome.is_ok(), "{outcome:?}");
    if let Ok(outcome) = outcome {
        assert_eq!(outcome.credential.kind, CloudCredentialKind::LongTermAk);
        assert!(outcome.long_lived_risk, "环境变量里的长期 AK 同样要登记风险");
        assert_eq!(outcome.warnings.len(), 1);
    }
}

#[test]
pub(crate) fn sts_resolver_refuses_network_in_mock_mode() {
    let now = Timestamp::now();
    let mock_ctx = CredentialContext::new(MapSecretStore::shared(&[]), true).with_now(now);
    let err = StsResolver::new().resolve(&fixture_integration(CloudCredentialKind::StsToken, "1"), &mock_ctx);
    assert!(matches!(err, Err(DomainError::DependencyUnavailable { .. })), "Mock 模式必须阻断 STS: {err:?}");
    // 同步入口不进行网络调用；真实交换由异步入口负责。
    let live_ctx = CredentialContext::new(MapSecretStore::shared(&[]), false).with_now(now);
    let err2 = StsResolver::new()
        .allowing_network()
        .resolve(&fixture_integration(CloudCredentialKind::StsToken, "1"), &live_ctx);
    assert!(matches!(err2, Err(DomainError::DependencyUnavailable { .. })), "{err2:?}");
}

#[test]
pub(crate) fn assume_role_requires_arn_and_source_credential() {
    let now = Timestamp::now();
    let resolver = AssumeRoleResolver::new(Arc::new(StaticResolver::long_term("ak", "sk")));
    let no_arn = fixture_integration(CloudCredentialKind::AssumeRole, "1");
    let err = resolver.resolve(&no_arn, &ctx(now));
    assert!(matches!(err, Err(DomainError::Config(_))), "缺 ARN 必须报配置错误: {err:?}");

    let mut with_arn = fixture_integration(CloudCredentialKind::AssumeRole, "1");
    with_arn.assume_role_arn = Some("acs:ram::1234567890:role/agf-reader".to_string());
    let err2 = resolver.resolve(&with_arn, &ctx(now));
    assert!(matches!(err2, Err(DomainError::DependencyUnavailable { .. })), "无网络时必须明确不可用: {err2:?}");

    // 源凭据缺失时，即使有 ARN 也要先报配置错误（先暴露配置问题）
    let mut broken = with_arn.clone();
    broken.assume_role_arn = Some("acs:ram::1:role/x".to_string());
    let bad_source = AssumeRoleResolver::new(Arc::new(StaticResolver::new(CloudCredential {
        access_key_id: String::new(),
        access_key_secret: String::new(),
        security_token: None,
        expires_at: None,
        kind: CloudCredentialKind::LongTermAk,
    })));
    assert!(matches!(bad_source.resolve(&broken, &ctx(now)), Err(DomainError::Config(_))));
}

#[test]
pub(crate) fn session_name_sanitization() {
    assert_eq!(sanitize_session_name("agf-prod"), "agf-prod");
    assert_eq!(sanitize_session_name("agf prod/1"), "agf-prod-1");
    assert_eq!(sanitize_session_name(""), "agf");
    assert_eq!(sanitize_session_name("a"), "agfa");
    assert!(sanitize_session_name(&"x".repeat(200)).len() <= 64);
}

#[test]
pub(crate) fn recommended_resolver_covers_all_kinds() {
    for kind in [
        CloudCredentialKind::InstanceRole,
        CloudCredentialKind::StsToken,
        CloudCredentialKind::AssumeRole,
        CloudCredentialKind::LongTermAk,
        CloudCredentialKind::WorkloadIdentity,
    ] {
        assert!(!recommended_resolver(kind).is_empty(), "{kind:?} 必须有建议");
    }
}

#[test]
pub(crate) fn map_secret_store_returns_not_found() {
    let store = MapSecretStore::new();
    let missing = store.resolve_secret(Id::new());
    assert!(matches!(missing, Err(DomainError::NotFound { .. })));
    let id = Id::new();
    let store = MapSecretStore::shared(&[(id, "plain-ak".to_string())]);
    assert_eq!(store.resolve_secret(id).ok().as_deref(), Some("plain-ak"));
}

#[test]
pub(crate) fn storage_hint_has_no_plaintext() {
    let hint = storage_hint();
    assert!(hint.contains("AES-256-GCM"));
    assert!(!hint.contains("LTAI5tExample0000") || hint.contains("****"), "提示文案不得回显完整 AK");
}
