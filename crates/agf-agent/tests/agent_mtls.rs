#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
//! 采集器客户端 **mTLS** 的配置与错误面测试：配置解析 / TLS 模式映射 / 缺证书行为 /
//! 跳过校验的 dev 门禁 / 错误分类 / 凭据不泄露。
//!
//! 真机握手（进程内 rustls 服务端要求并读取客户端证书）见 `agent_mtls_handshake.rs`，
//! 共享 PKI 夹具见 `agent_mtls_common.rs`。
//!
//! 全程不联网、不依赖外部证书文件：PKI 由 `rcgen` 在测试内生成并写入临时目录。

use std::path::{Path, PathBuf};

use agf_agent::{
    AgentClient, AgentIdentity, ClientConfig, TlsConfig, TlsEndpoint, TlsErrorKind, TlsMode, TlsTransport,
};
use agf_core::error::DomainError;

#[path = "agent_mtls_common.rs"]
mod common;

use common::make_pki;

// ---------------------------------------------------------------------------
// ① 配置解析与模式映射
// ---------------------------------------------------------------------------

#[test]
fn tls_config_parses_env_lookup() {
    let tls = TlsConfig::from_lookup(|key| {
        match key {
            "AGF_AGENT_TLS_CERT" => Some("/tmp/client.pem"),
            "AGF_AGENT_TLS_KEY" => Some("/tmp/client.key"),
            "AGF_AGENT_TLS_CA" => Some("/tmp/ca.pem"),
            "AGF_AGENT_TLS_INSECURE_SKIP_VERIFY" => Some("YES"),
            "AGF_ENV" => Some("dev"),
            _ => None,
        }
        .map(str::to_string)
    });
    assert_eq!(tls.client_cert_pem.as_ref().unwrap().to_string_lossy().replace('\\', "/"), "/tmp/client.pem");
    assert_eq!(tls.client_key_pem.as_ref().unwrap().to_string_lossy().replace('\\', "/"), "/tmp/client.key");
    assert_eq!(tls.ca_pem.as_ref().unwrap().to_string_lossy().replace('\\', "/"), "/tmp/ca.pem");
    assert!(tls.insecure_requested, "YES 也必须被识别为真（大小写不敏感）");
    assert!(tls.insecure_allowed, "AGF_ENV=dev 是跳过校验的授权来源之一");
    assert!(tls.insecure_skip_verify);
    assert_eq!(tls.env_name.as_deref(), Some("dev"));
    assert!(tls.keypair_complete());
}

#[test]
fn empty_env_paths_count_as_unset() {
    let tls = TlsConfig::from_lookup(|key| match key {
        "AGF_AGENT_TLS_CERT" => Some("   ".to_string()),
        _ => Some(String::new()),
    });
    assert!(tls.client_cert_pem.is_none(), "空白路径不得被当成已配置");
    assert!(tls.client_key_pem.is_none());
    assert!(tls.ca_pem.is_none());
    assert!(!tls.is_configured());
}

#[test]
fn tls_mode_mapping_is_deterministic() {
    let mut tls = TlsConfig::default();
    assert_eq!(tls.mode_for(Some("https://agf.example.invalid")), TlsMode::ServerAuth);
    assert_eq!(tls.mode_for(Some("http://agf.example.invalid")), TlsMode::Plaintext);
    assert_eq!(tls.mode_for(None), TlsMode::Plaintext);
    tls.client_cert_pem = Some(PathBuf::from("c.pem"));
    assert_eq!(tls.mode_for(Some("HTTPS://AGF.EXAMPLE.INVALID")), TlsMode::Mutual, "scheme 判定大小写不敏感");
    assert_eq!(tls.mode_for(Some("http://agf.example.invalid")), TlsMode::Plaintext);
    assert!(TlsMode::Mutual.is_mutual() && TlsMode::Mutual.is_tls());
    assert!(!TlsMode::ServerAuth.is_mutual());
    assert!(!TlsMode::Plaintext.is_tls());
    assert_eq!(TlsMode::Mutual.to_string(), "mutual");
}

#[test]
fn client_config_reports_mode_and_health() {
    let config = ClientConfig::default().with_server_url("https://agf.example.invalid");
    assert_eq!(config.tls_mode(), TlsMode::ServerAuth);
    let health = config.tls_health();
    assert!(health.is_healthy(), "未配置 mTLS 时单向 TLS 是合法配置: {health:?}");
    assert!(!health.client_cert_configured);

    let tls = TlsConfig { client_cert_pem: Some(PathBuf::from("only-cert.pem")), ..TlsConfig::default() };
    let broken = ClientConfig::default().with_server_url("https://agf.example.invalid").with_tls(tls);
    let health = broken.tls_health();
    assert!(!health.is_healthy());
    assert_eq!(health.error_kind, Some(TlsErrorKind::Config));
    assert!(health.detail.contains("必须成对"));
}

// ---------------------------------------------------------------------------
// ② 缺证书 / 不成对 / 明文配证书 —— 必须明确报错
// ---------------------------------------------------------------------------

#[test]
fn missing_client_key_is_a_hard_error_not_a_silent_downgrade() {
    let tls = TlsConfig { client_cert_pem: Some(PathBuf::from("client.pem")), ..TlsConfig::default() };
    let error = tls.validate(Some("https://agf.example.invalid")).expect_err("只给证书必须报错");
    assert!(matches!(error, DomainError::Config(_)), "{error:?}");
    assert!(error.to_string().contains("AGF_AGENT_TLS_KEY"), "{error}");
    assert_eq!(TlsErrorKind::of(&error), TlsErrorKind::Config);
}

#[test]
fn missing_key_file_is_reported_without_leaking_contents() {
    let tls = TlsConfig {
        client_cert_pem: Some(PathBuf::from("definitely-not-here.pem")),
        client_key_pem: Some(PathBuf::from("definitely-not-here.key")),
        ..TlsConfig::default()
    };
    let error = tls.load().expect_err("文件不存在必须报错");
    assert!(matches!(error, DomainError::Config(_)));
    // `load()` 把"文件不可读"与"组合非法"都归到 `DomainError::Config`（分类接口只看得到变体），
    // 细节由下面的文本断言区分——不假装分类比变体更细。
    assert_eq!(TlsErrorKind::of(&error), TlsErrorKind::Config);
    let text = error.to_string();
    assert!(text.contains("definitely-not-here.pem"), "{text}");
    assert!(!text.contains("PRIVATE KEY"), "错误文本不得包含 PEM 内容: {text}");
}

#[test]
fn client_cert_over_plaintext_is_rejected() {
    let pki = make_pki();
    let tls = TlsConfig {
        client_cert_pem: Some(pki.client_cert_pem.clone()),
        client_key_pem: Some(pki.client_key_pem.clone()),
        ..TlsConfig::default()
    };
    let error = tls.validate(Some("http://127.0.0.1:9/x")).expect_err("明文 + 客户端证书必须报错");
    assert!(matches!(error, DomainError::Config(_)));
    assert!(error.to_string().contains("https://"), "{error}");
}

// ---------------------------------------------------------------------------
// ③ 跳过校验的 dev 门禁
// ---------------------------------------------------------------------------

#[test]
fn insecure_skip_verify_requires_dev_or_explicit_switch() {
    let lookup = |skip: &str, env: Option<&str>, allow: Option<&str>| {
        let skip = skip.to_string();
        let env = env.map(str::to_string);
        let allow = allow.map(str::to_string);
        TlsConfig::from_lookup(move |key| match key {
            "AGF_AGENT_TLS_INSECURE_SKIP_VERIFY" => Some(skip.clone()),
            "AGF_ENV" => env.clone(),
            "AGF_AGENT_TLS_ALLOW_INSECURE" => allow.clone(),
            _ => None,
        })
    };
    // ① 未授权（无 AGF_ENV）→ 请求被折叠 + 明确报错
    let denied = lookup("1", None, None);
    assert!(denied.insecure_requested && !denied.insecure_allowed && !denied.insecure_skip_verify);
    assert!(denied.insecure_denied());
    assert!(denied.validate(Some("https://agf.example.invalid")).is_err(), "未授权的跳过校验必须报错");
    // ② AGF_ENV=dev → 放行（且实际值生效，供上层 warn!）
    let dev = lookup("1", Some("dev"), None);
    assert!(dev.insecure_skip_verify && dev.insecure_allowed);
    assert!(dev.validate(Some("https://agf.example.invalid")).is_ok());
    // ③ AGF_ENV=prod 但显式开关 → 放行
    let prod_explicit = lookup("true", Some("prod"), Some("1"));
    assert!(prod_explicit.insecure_skip_verify);
    assert!(prod_explicit.validate(Some("https://agf.example.invalid")).is_ok());
    // ④ AGF_ENV=prod 且无显式开关 → 拒绝
    let prod = lookup("1", Some("prod"), None);
    assert!(prod.insecure_denied());
    // ⑤ 未请求跳过校验 → 不报错也不生效
    let off = lookup("0", Some("prod"), None);
    assert!(!off.insecure_requested && !off.insecure_skip_verify);
    assert!(off.validate(Some("https://agf.example.invalid")).is_ok());
}

#[test]
fn insecure_skip_verify_health_records_the_risk() {
    let pki = make_pki();
    let tls = TlsConfig {
        client_cert_pem: Some(pki.client_cert_pem.clone()),
        client_key_pem: Some(pki.client_key_pem.clone()),
        ca_pem: Some(pki.ca_pem.clone()),
        insecure_skip_verify: true,
        insecure_allowed: true,
        insecure_requested: true,
        env_name: Some("dev".to_string()),
    };
    let config = ClientConfig::default().with_server_url("https://127.0.0.1:1/x").with_tls(tls);
    let health = config.tls_health();
    assert!(health.insecure_skip_verify);
    assert!(health.insecure_allowed);
    assert!(health.detail.contains("跳过"), "健康画像必须如实标注风险: {}", health.detail);
    assert_eq!(health.mode, TlsMode::Mutual);
    assert!(health.is_healthy());
}

// ---------------------------------------------------------------------------
// ④ 错误分类与 URL 解析
// ---------------------------------------------------------------------------

#[test]
fn error_classification_maps_domain_errors() {
    assert_eq!(TlsErrorKind::of(&DomainError::Config("x".into())), TlsErrorKind::Config);
    assert_eq!(TlsErrorKind::of(&DomainError::Parse("x".into())), TlsErrorKind::BadPem);
    assert_eq!(TlsErrorKind::of(&DomainError::Validation("x".into())), TlsErrorKind::BadPem);
    assert_eq!(
        TlsErrorKind::of(&DomainError::DependencyUnavailable { dependency: "d".into(), cause: "c".into() }),
        TlsErrorKind::Network
    );
    assert_eq!(TlsErrorKind::of(&DomainError::Unauthenticated("x".into())), TlsErrorKind::Handshake);
    // "缺客户端证书"用**我们自己的固定前缀**与普通握手失败区分（不依赖 rustls 的文案）
    let missing = DomainError::Unauthenticated(format!(
        "{}：服务端要求客户端证书",
        agf_agent::client::CLIENT_CERT_MISSING_PREFIX
    ));
    assert_eq!(TlsErrorKind::of(&missing), TlsErrorKind::ClientCertMissing);
    assert_eq!(TlsErrorKind::Config.as_str(), "config");
    assert_eq!(TlsErrorKind::MissingFile.as_str(), "missing-file");
    assert_eq!(TlsErrorKind::ClientCertMissing.as_str(), "client-cert-missing");
    assert_eq!(TlsErrorKind::Handshake.as_str(), "handshake");
}

#[test]
fn pem_parsing_classifies_bad_material() {
    let bad = b"-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n";
    let error = agf_agent::client::parse_certs(bad, "客户端证书").expect_err("坏 PEM 必须报错");
    assert!(matches!(error, DomainError::Config(_)));
    let empty = b"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n";
    let error = agf_agent::client::parse_certs(empty, "客户端证书").expect_err("空证书必须报错");
    assert!(error.to_string().contains("证书为空"), "{error}");
    let error = agf_agent::client::parse_key(b"not a pem at all").expect_err("无私钥必须报错");
    assert!(error.to_string().contains("没有私钥"), "{error}");
}

#[test]
fn mismatched_key_pair_is_classified_as_key_mismatch() {
    let a = make_pki();
    let b = make_pki();
    let tls = TlsConfig {
        client_cert_pem: Some(a.client_cert_pem.clone()),
        // 私钥来自**另一套** PKI
        client_key_pem: Some(b.client_key_pem.clone()),
        ca_pem: Some(a.ca_pem.clone()),
        ..TlsConfig::default()
    };
    let material = tls.load().expect("PEM 本身合法");
    let error = material.client_config().expect_err("证书与私钥不匹配必须报错");
    assert!(error.to_string().contains("KeyMismatch"), "{error}");
    assert!(!error.to_string().contains("PRIVATE KEY"), "错误文本不得回显私钥");
}

#[test]
fn url_parsing_covers_ports_and_bad_schemes() {
    let endpoint = TlsEndpoint::parse("https://127.0.0.1:8443/api/v1/ingest/agent?x=1").expect("合法 URL");
    assert!(endpoint.tls);
    assert_eq!(endpoint.host, "127.0.0.1");
    assert_eq!(endpoint.port, 8443);
    assert_eq!(endpoint.target, "/api/v1/ingest/agent?x=1");

    let default_port = TlsEndpoint::parse("https://host").expect("缺省端口");
    assert_eq!(default_port.port, 443);
    assert_eq!(default_port.target, "/");
    let plain = TlsEndpoint::parse("http://host:8080/x").expect("明文 URL");
    assert!(!plain.tls);
    assert_eq!(plain.port, 8080);

    assert!(TlsEndpoint::parse("ftp://host").is_err(), "不支持的 scheme 必须报错");
    assert!(TlsEndpoint::parse("host:8080").is_err(), "缺 scheme 必须报错");
    assert!(TlsEndpoint::parse("https://host:not-a-port").is_err(), "非法端口必须报错");
}

#[test]
fn credentials_never_appear_in_debug_or_health() {
    let pki = make_pki();
    let secret = std::fs::read_to_string(&pki.client_key_pem).unwrap();
    let tls = TlsConfig {
        client_cert_pem: Some(pki.client_cert_pem.clone()),
        client_key_pem: Some(pki.client_key_pem.clone()),
        ca_pem: Some(pki.ca_pem.clone()),
        ..TlsConfig::default()
    };
    let config =
        ClientConfig::default().with_server_url("https://127.0.0.1:1/x").with_tls(tls.clone()).with_token("top-secret");
    let client = AgentClient::new(AgentIdentity::generate(), config.clone());
    let debug = format!("{client:?}");
    assert!(!debug.contains("top-secret"));
    assert!(!debug.contains("PRIVATE KEY"));
    assert!(!format!("{config:?}").contains("top-secret"));

    let material = tls.load().unwrap();
    let material_debug = format!("{material:?}");
    assert!(material_debug.contains("cert(s):redacted>"), "{material_debug}");
    assert!(material_debug.contains("<PRIVATE KEY:REDACTED>"), "{material_debug}");
    assert!(!material_debug.contains("MII"), "私钥/证书的 base64 内容不得出现在 Debug 里");

    let transport = TlsTransport::new(TlsMode::Mutual, Some(material)).unwrap().with_token("top-secret");
    let transport_debug = format!("{transport:?}");
    assert!(!transport_debug.contains("top-secret"), "{transport_debug}");
    assert!(!transport_debug.contains(&secret[..40]), "私钥内容不得出现在 Debug 里");
}

// ---------------------------------------------------------------------------
// ⑤ 配置错误经 AgentClient 一路可见（不静默）
// ---------------------------------------------------------------------------

#[tokio::test]
async fn config_error_is_visible_in_client_health_and_note() {
    let tls = TlsConfig { client_cert_pem: Some(PathBuf::from("only-cert.pem")), ..TlsConfig::default() };
    let config = ClientConfig::default().with_server_url("https://agf.example.invalid").with_tls(tls);
    let mut client = AgentClient::new(AgentIdentity::generate(), config);
    assert_eq!(client.transport_name(), "http-not-implemented");
    let error = client.transport_config_error().expect("配置错误必须被记录");
    assert!(matches!(error, DomainError::Config(_)));
    let health = client.tls_health();
    assert!(!health.is_healthy());
    assert_eq!(health.error_kind, Some(TlsErrorKind::Config));
    let outcome = client.deliver(agf_agent::PayloadKind::Heartbeat, "{}", "k").await.expect("入队");
    assert!(outcome.queued);
    let note = outcome.note.unwrap_or_default();
    assert!(note.contains("必须成对"), "回执 note 必须带上真实原因: {note}");
}

#[test]
fn tls_config_describe_is_credential_free() {
    let tls = TlsConfig {
        client_cert_pem: Some(Path::new("c.pem").to_path_buf()),
        client_key_pem: Some(Path::new("c.key").to_path_buf()),
        ca_pem: Some(Path::new("ca.pem").to_path_buf()),
        ..TlsConfig::default()
    };
    let text = tls.describe(Some("https://agf.example.invalid"));
    assert!(text.contains("mTLS=开启"));
    assert!(text.contains("ca.pem"));
    assert!(!text.contains("PRIVATE KEY"));
    let plain = TlsConfig::default().describe(Some("http://agf.example.invalid"));
    assert!(plain.contains("明文"));
}

#[test]
fn agent_client_from_env_never_panics_even_with_broken_tls_env() {
    // 进程环境里的 AGF_AGENT_TLS_* 可能未设置或指向不存在的文件——两种都必须给出结论而不是 panic。
    let client = AgentClient::from_env(AgentIdentity::generate());
    let health = client.tls_health();
    if client.server_url().is_some_and(|u| u.starts_with("https://")) {
        // 配置了 https 时：要么材料齐全（Mutual），要么缺证书会被明确标为不健康。
        assert!(health.mode == TlsMode::Mutual || !health.is_healthy());
    } else {
        assert_eq!(health.mode, TlsMode::Plaintext);
    }
}
