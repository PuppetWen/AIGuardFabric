//! 采集器客户端 mTLS 的**真机握手**测试：进程内起 rustls 服务端（要求并读取客户端证书），
//! 覆盖成功 / 缺证书被拒 / 错 CA 失败 / 跳过校验放行 / 经 AgentClient 的完整上行。
//!
//! 共享夹具见 `agent_mtls_common.rs`；配置解析与错误分类的纯函数测试见 `agent_mtls.rs`。
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "agent_mtls_common.rs"]
mod common;

use common::{Pki, SERVER_TIMEOUT, make_pki, spawn_mtls_server, spawn_rejecting_mtls_server, spawn_server_auth_only};

use agf_agent::{
    AgentClient, AgentIdentity, ClientConfig, ClientMode, CollectContext, TlsConfig, TlsErrorKind, TlsMode,
    TlsTransport, collect_all,
};

// ---------------------------------------------------------------------------
// ⑤ 真机 mTLS 握手（进程内 rustls 服务端）
// ---------------------------------------------------------------------------

/// 装配 mTLS 客户端配置（CA = 测试 PKI 的 CA，客户端证书 = 测试 PKI 的客户端证书）。
fn mutual_client_config(pki: &Pki, port: u16) -> ClientConfig {
    let tls = TlsConfig {
        client_cert_pem: Some(pki.client_cert_pem.clone()),
        client_key_pem: Some(pki.client_key_pem.clone()),
        ca_pem: Some(pki.ca_pem.clone()),
        ..TlsConfig::default()
    };
    ClientConfig::default().with_server_url(format!("https://127.0.0.1:{port}")).with_tls(tls)
}

/// 单次尝试（不重试）——端到端测试要的是"这一次握手的结论"。
fn no_retry() -> agf_core::adapter::RetryConfig {
    agf_core::adapter::RetryConfig {
        max_attempts: 1,
        initial_backoff_ms: 1,
        multiplier: 1.0,
        max_backoff_ms: 1,
        jitter: false,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn mutual_tls_handshake_succeeds_and_server_sees_client_cert() {
    let pki = make_pki();
    let expected = pki.client_cert_fingerprint();
    let (addr, server) = spawn_mtls_server(&pki).await;

    let config = mutual_client_config(&pki, addr.port());
    assert_eq!(config.tls_health().mode, TlsMode::Mutual);
    assert!(config.tls_health().is_healthy());

    let mut client = AgentClient::new(AgentIdentity::generate().with_agent_id("agent-mtls-1"), config);
    assert_eq!(client.transport_name(), "mtls", "https + 客户端证书必须装配 mTLS 传输");
    assert_eq!(client.mode(), ClientMode::Live);

    let outcome = client.send_heartbeat(&client.heartbeat_payload(vec![])).await.expect("mTLS 上行应成功");
    assert!(outcome.is_delivered(), "{outcome:?}");
    let response = client.last_uplink_response().expect("真实传输必须留下响应");
    assert_eq!(response.status, 200);
    // `protocol` 直接取自 rustls 的 `ProtocolVersion` 的 Debug 文本（如 `TLSv1_3`）——如实透出，不做美化
    assert!(response.protocol.as_deref().is_some_and(|p| p.starts_with("TLSv1")), "协商协议: {:?}", response.protocol);
    assert!(response.cipher.is_some(), "必须拿到协商的密码套件");

    let seen = tokio::time::timeout(SERVER_TIMEOUT, server)
        .await
        .expect("服务端任务超时")
        .expect("服务端任务")
        .expect("服务端必须看到客户端证书");
    assert_eq!(seen, expected, "服务端看到的客户端证书指纹必须与本地证书一致（证明真的出示了身份）");
}

#[tokio::test(flavor = "multi_thread")]
async fn server_that_requires_client_cert_rejects_anonymous_client() {
    let pki = make_pki();
    let (addr, server) = spawn_rejecting_mtls_server(&pki).await;

    // 客户端**不带**证书（单向 TLS 配置）
    let tls = TlsConfig { ca_pem: Some(pki.ca_pem.clone()), ..TlsConfig::default() };
    let config = ClientConfig::default()
        .with_server_url(format!("https://127.0.0.1:{}/x", addr.port()))
        .with_tls(tls)
        .with_retry(no_retry());
    assert_eq!(config.tls_health().mode, TlsMode::ServerAuth);
    let mut client = AgentClient::new(AgentIdentity::generate(), config);
    let error = client.deliver_strict(agf_agent::PayloadKind::Heartbeat, "{}", "k1").await.expect_err("必须被拒");
    // TLS 1.3 alerts may race a Windows TCP reset. A reset alone cannot prove a missing certificate.
    let kind = TlsErrorKind::of(&error);
    assert!(matches!(kind, TlsErrorKind::ClientCertMissing | TlsErrorKind::Network), "{error}");
    let text = error.to_string();
    if kind == TlsErrorKind::ClientCertMissing {
        assert!(text.contains("客户端证书"), "{text}");
    }
    assert!(!text.contains("PRIVATE KEY"));
    let server_error = tokio::time::timeout(SERVER_TIMEOUT, server).await.unwrap().unwrap();
    assert!(
        matches!(
            server_error.get_ref().and_then(|error| error.downcast_ref::<rustls::Error>()),
            Some(rustls::Error::NoCertificatesPresented)
        ),
        "server must reject missing client identity: {server_error}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_ca_fails_the_handshake() {
    let pki = make_pki();
    let other = make_pki();
    let (addr, server) = spawn_mtls_server(&pki).await;

    let tls = TlsConfig {
        client_cert_pem: Some(pki.client_cert_pem.clone()),
        client_key_pem: Some(pki.client_key_pem.clone()),
        // **错 CA**：用另一套 PKI 的 CA 去校验服务端
        ca_pem: Some(other.ca_pem.clone()),
        ..TlsConfig::default()
    };
    let transport = TlsTransport::from_config(&tls, Some("https://127.0.0.1/x")).expect("配置本身合法");
    let endpoint = format!("https://127.0.0.1:{}/api/v1/ingest/agent", addr.port());
    let error = transport.send_with_response(&endpoint, "{}").expect_err("错 CA 必须握手失败");
    let text = error.to_string();
    assert!(
        text.contains("UnknownIssuer") || text.contains("invalid peer certificate") || text.contains("握手失败"),
        "{text}"
    );
    let _ = tokio::time::timeout(SERVER_TIMEOUT, server).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn insecure_skip_verify_accepts_wrong_ca_but_is_marked() {
    let pki = make_pki();
    let other = make_pki();
    let (addr, server) = spawn_server_auth_only(&pki).await;
    let tls = TlsConfig {
        ca_pem: Some(other.ca_pem.clone()), // 与真实服务端 CA 不同
        insecure_skip_verify: true,
        insecure_allowed: true,
        insecure_requested: true,
        env_name: Some("dev".to_string()),
        ..TlsConfig::default()
    };
    let transport = TlsTransport::from_config(&tls, Some("https://127.0.0.1/x")).expect("配置合法");
    let endpoint = format!("https://127.0.0.1:{}/x", addr.port());
    let response = transport.send_with_response(&endpoint, "{}").expect("跳过校验后应能握手");
    assert_eq!(response.status, 200);
    assert!(response.cipher.is_some());
    let _ = tokio::time::timeout(SERVER_TIMEOUT, server).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn mtls_uplink_via_agent_client_reports_endpoint_and_result() {
    let pki = make_pki();
    let (addr, server) = spawn_mtls_server(&pki).await;
    let config = mutual_client_config(&pki, addr.port()).with_retry(no_retry());
    let dir = tempfile::tempdir().unwrap();
    let mut client = AgentClient::new(AgentIdentity::generate(), config);
    let ctx = CollectContext::for_current_user().with_home(dir.path()).without_system_probes();
    let snapshot = collect_all(client.identity(), &ctx);
    let outcome = client.send_snapshot(snapshot.payload.report, snapshot.payload.extras).await.expect("mTLS 快照上行");
    assert!(outcome.is_delivered(), "{outcome:?}");
    assert!(outcome.endpoint.starts_with("https://127.0.0.1:"), "端点: {}", outcome.endpoint);
    assert!(outcome.endpoint.ends_with("/api/v1/agent/report"), "端点: {}", outcome.endpoint);
    let _ = tokio::time::timeout(SERVER_TIMEOUT, server).await;
}

// ---------------------------------------------------------------------------
