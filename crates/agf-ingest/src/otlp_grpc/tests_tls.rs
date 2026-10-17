//! OTLP/gRPC 端口 TLS/mTLS 用例：配置解析、模式映射、证书缺失/非法降级、mTLS 校验开关。
//!
//! 真机握手（真实 `tonic` 客户端带 CA / 带客户端证书 / 不带 / 错 CA）见
//! `tests/otlp_grpc_tls_live.rs`；host 侧真进程 + Python `grpc` 客户端见
//! `tools/simulators/run_otlp_grpc_tls_e2e.ps1`。

#![allow(clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::Path;

use super::*;
use crate::bus::NoopEventBus;
use crate::pipeline::{InMemorySink, IngestConfig, IngestPipeline, Sink};
use crate::registry::ParserRegistry;
use agf_core::enums::{HealthState, IngestProtocol};
use agf_core::ids::{Id, TenantId};
use agf_core::source::{CollectionMode, LogSource, SourceConnection};
use agf_core::time::Timestamp;

/// 测试用环境变量表（拥有所有权，避免与临时集合的生命周期纠缠）。
struct EnvMap(BTreeMap<String, String>);

impl EnvMap {
    fn new(pairs: &[(&str, &str)]) -> Self {
        Self(pairs.iter().map(|(key, value)| ((*key).to_string(), (*value).to_string())).collect())
    }

    fn get(&self, key: &str) -> Option<String> {
        self.0.get(key).cloned()
    }
}

/// 自签 CA（参数与密钥都留着，供签发叶子证书）。
struct TestCa {
    params: rcgen::CertificateParams,
    key: rcgen::KeyPair,
    cert_pem: String,
}

fn make_ca(common_name: &str) -> Option<TestCa> {
    let mut params = rcgen::CertificateParams::new(Vec::new()).ok()?;
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages.push(rcgen::KeyUsagePurpose::KeyCertSign);
    params.distinguished_name.push(rcgen::DnType::CommonName, common_name);
    let key = rcgen::KeyPair::generate().ok()?;
    let cert = params.self_signed(&key).ok()?;
    Some(TestCa { params, key, cert_pem: cert.pem() })
}

/// 由 CA 签发的叶子证书（SAN 含 `localhost` + `127.0.0.1`，rustls 侧按用途校验 EKU）。
fn make_leaf(ca: &TestCa, common_name: &str, usage: rcgen::ExtendedKeyUsagePurpose) -> Option<(String, String)> {
    let issuer = rcgen::Issuer::from_params(&ca.params, &ca.key);
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]).ok()?;
    params.distinguished_name.push(rcgen::DnType::CommonName, common_name);
    params.extended_key_usages.push(usage);
    let key = rcgen::KeyPair::generate().ok()?;
    let cert = params.signed_by(&key, &issuer).ok()?;
    Some((cert.pem(), key.serialize_pem()))
}

/// 一套落盘的测试 PKI。
struct TempPki {
    dir: std::path::PathBuf,
    ca: std::path::PathBuf,
    server_cert: std::path::PathBuf,
    server_key: std::path::PathBuf,
}

impl TempPki {
    /// 生成一套 PKI；任何一步失败都返回 `None`（调用方 `let Some(..) else { return }` 跳过）。
    fn generate(tag: &str) -> Option<Self> {
        let dir = std::env::temp_dir().join(format!("agf-otlpgrpc-tls-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).ok()?;
        let ca = make_ca("agf-otlpgrpc-test-ca")?;
        let (server_cert_pem, server_key_pem) =
            make_leaf(&ca, "agf-otlpgrpc-server", rcgen::ExtendedKeyUsagePurpose::ServerAuth)?;
        let write = |name: &str, text: &str| -> Option<std::path::PathBuf> {
            let path = dir.join(name);
            std::fs::write(&path, text).ok()?;
            Some(path)
        };
        Some(Self {
            ca: write("ca.crt", &ca.cert_pem)?,
            server_cert: write("server.crt", &server_cert_pem)?,
            server_key: write("server.key", &server_key_pem)?,
            dir,
        })
    }

    /// 服务端 TLS（单向上行）配置。
    fn server_tls_config(&self) -> OtlpGrpcTlsConfig {
        OtlpGrpcTlsConfig {
            enabled: true,
            cert_pem: Some(self.server_cert.clone()),
            key_pem: Some(self.server_key.clone()),
            client_ca_pem: None,
        }
    }

    /// mTLS 配置（服务端证书 + 强制客户端证书）。
    fn mutual_tls_config(&self) -> OtlpGrpcTlsConfig {
        OtlpGrpcTlsConfig { client_ca_pem: Some(self.ca.clone()), ..self.server_tls_config() }
    }
}

fn log_source() -> LogSource {
    let now = Timestamp::now();
    LogSource {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        name: "otlp-grpc-tls-test".to_string(),
        protocol: IngestProtocol::Otlp,
        vendor: "generic".to_string(),
        product: "otlp".to_string(),
        enabled: true,
        parser_id: None,
        connection: SourceConnection::default(),
        mode: CollectionMode::Push,
        poll_interval_secs: None,
        require_mtls: false,
        allowed_cidrs: vec![],
        max_message_bytes: 1_048_576,
        max_eps: 0,
        tags: vec![],
        health: HealthState::Healthy,
        last_event_at: None,
        total_events: 0,
        last_error: None,
        created_at: now,
        updated_at: now,
    }
}

fn receiver() -> Arc<OtlpLogsReceiver> {
    let sink = Arc::new(InMemorySink::new());
    let pipeline = IngestPipeline::new(
        ParserRegistry::with_builtins(),
        Arc::clone(&sink) as Arc<dyn Sink>,
        Arc::new(NoopEventBus),
        IngestConfig { emit_to_bus: false, ..IngestConfig::default() },
    );
    Arc::new(OtlpLogsReceiver::new(Arc::new(pipeline), log_source()))
}

#[test]
fn defaults_are_plaintext_and_backward_compatible() {
    let empty = EnvMap::new(&[]);
    let config = OtlpGrpcConfig::from_lookup(|key| empty.get(key));
    assert_eq!(config, OtlpGrpcConfig::default(), "不配 TLS 相关变量 ⇒ 配置逐字段等于默认值");
    assert_eq!(config.tls, OtlpGrpcTlsConfig::default());
    let resolution = config.tls.resolve();
    assert_eq!(resolution.mode, OtlpGrpcTlsMode::Plaintext);
    assert!(resolution.degraded.is_none(), "默认明文不是降级：{resolution:?}");
    assert!(!config.tls.enabled);
    assert!(config.describe().contains("明文"), "{}", config.describe());
    assert!(OtlpGrpcTlsState::from_config(&config.tls).is_ok());
    assert!(!resolution.mode.is_encrypted());
    assert_eq!(OtlpGrpcTlsMode::Plaintext.as_str(), "plaintext");
}

#[test]
fn tls_and_mtls_modes_map_from_env_and_paths() {
    let env =
        EnvMap::new(&[(ENV_TLS, "1"), (ENV_TLS_CERT, "C:/certs/server.crt"), (ENV_TLS_KEY, "C:/certs/server.key")]);
    let mut config = OtlpGrpcConfig::from_lookup(|key| env.get(key));
    assert!(config.tls.enabled);
    assert_eq!(config.tls.cert_pem.as_deref(), Some(Path::new("C:/certs/server.crt")));
    assert_eq!(config.tls.key_pem.as_deref(), Some(Path::new("C:/certs/server.key")));
    assert!(config.tls.client_ca_pem.is_none());
    // 路径不存在 ⇒ 如实降级为明文（并给出"读取失败"原因），不 panic
    let missing = config.tls.resolve();
    assert_eq!(missing.mode, OtlpGrpcTlsMode::Plaintext);
    assert!(missing.degraded.as_deref().unwrap_or_default().contains("读取失败"), "{missing:?}");

    // 换成**真实存在**的 PEM：单向 TLS 生效
    let Some(pki) = TempPki::generate("modes") else { return };
    config.tls = pki.server_tls_config();
    let single = config.tls.resolve();
    assert_eq!(single.mode, OtlpGrpcTlsMode::ServerTls);
    assert_eq!(single.mode.as_str(), "tls");
    assert!(single.degraded.is_none(), "{single:?}");
    assert!(single.summary.contains("单向"), "{}", single.summary);
    assert!(!single.summary.contains("BEGIN"), "描述里不得出现 PEM 内容");

    // 追加客户端 CA ⇒ mTLS（**要求并校验**客户端证书）
    config.tls = pki.mutual_tls_config();
    let mutual = config.tls.resolve();
    assert_eq!(mutual.mode, OtlpGrpcTlsMode::MutualTls);
    assert_eq!(mutual.mode.as_str(), "mtls");
    assert!(mutual.mode.is_encrypted());
    assert!(mutual.degraded.is_none(), "{mutual:?}");
    assert!(mutual.summary.contains("mTLS"), "{}", mutual.summary);
    assert!(mutual.summary.contains("要求并校验客户端证书"), "{}", mutual.summary);
    assert!(!mutual.summary.contains("server.key"), "描述不得泄露私钥路径: {}", mutual.summary);

    // /readyz 的 notes 用的 `describe()` 必须带上形态
    assert!(config.describe().contains("mTLS"), "{}", config.describe());
}

#[test]
fn missing_or_incomplete_certificates_reject_startup_with_reason() {
    // ① 开了 TLS 但一个证书都没给
    let env = EnvMap::new(&[(ENV_TLS, "1")]);
    let only_flag = OtlpGrpcConfig::from_lookup(|key| env.get(key));
    let resolution = only_flag.tls.resolve();
    assert_eq!(resolution.mode, OtlpGrpcTlsMode::Plaintext);
    assert!(resolution.degraded.as_deref().unwrap_or_default().contains(ENV_TLS_CERT), "{resolution:?}");
    assert!(only_flag.describe().contains("不启用"), "{}", only_flag.describe());
    assert!(OtlpGrpcTlsState::from_config(&only_flag.tls).is_err());

    // ② 只给证书不给私钥（成对约束）
    let env = EnvMap::new(&[(ENV_TLS, "1"), (ENV_TLS_CERT, "C:/certs/server.crt")]);
    let half = OtlpGrpcConfig::from_lookup(|key| env.get(key));
    assert_eq!(half.tls.resolve().mode, OtlpGrpcTlsMode::Plaintext);
    assert!(half.tls.resolve().degraded.as_deref().unwrap_or_default().contains("必须成对"));

    // ③ 只给私钥不给证书
    let env = EnvMap::new(&[(ENV_TLS, "1"), (ENV_TLS_KEY, "C:/certs/server.key")]);
    let half = OtlpGrpcConfig::from_lookup(|key| env.get(key));
    assert_eq!(half.tls.resolve().mode, OtlpGrpcTlsMode::Plaintext);

    // ④ 配了客户端 CA 但没有服务端证书 ⇒ 同样明文 + 原因（mTLS 不能凭空成立）
    let env = EnvMap::new(&[(ENV_TLS, "1"), (ENV_TLS_CLIENT_CA, "C:/certs/ca.crt")]);
    let ca_only = OtlpGrpcConfig::from_lookup(|key| env.get(key));
    let resolution = ca_only.tls.resolve();
    assert_eq!(resolution.mode, OtlpGrpcTlsMode::Plaintext);
    assert!(resolution.degraded.is_some(), "{resolution:?}");
    assert!(ca_only.tls.configured_any());

    let Some(pki) = TempPki::generate("broken") else { return };
    // ⑤ 证书文件存在但**内容不是 PEM** ⇒ 明文 + "没有证书"
    let broken_cert = pki.dir.join("broken.crt");
    let broken_key = pki.dir.join("broken.key");
    if std::fs::write(&broken_cert, b"not a pem").is_err() || std::fs::write(&broken_key, b"not a pem").is_err() {
        return;
    }
    let broken = OtlpGrpcTlsConfig {
        enabled: true,
        cert_pem: Some(broken_cert),
        key_pem: Some(broken_key),
        client_ca_pem: None,
    };
    let resolution = broken.resolve();
    assert_eq!(resolution.mode, OtlpGrpcTlsMode::Plaintext);
    assert!(resolution.degraded.as_deref().unwrap_or_default().contains("没有证书"), "{resolution:?}");
    // 明文状态下 load() 明确报错（调用方据此只 warn）
    assert!(matches!(broken.load(), Err(DomainError::Config(_))));
    assert!(OtlpGrpcTlsState::from_config(&broken).is_err());

    // ⑥ 客户端 CA 内容非法 ⇒ 明文（宁可不启用 TLS，也不"静默只做单向"）
    let bad_ca = pki.dir.join("bad-ca.crt");
    if std::fs::write(&bad_ca, b"not a pem").is_err() {
        return;
    }
    let bad_mtls = OtlpGrpcTlsConfig { client_ca_pem: Some(bad_ca), ..pki.server_tls_config() };
    let resolution = bad_mtls.resolve();
    assert_eq!(resolution.mode, OtlpGrpcTlsMode::Plaintext);
    assert!(resolution.degraded.as_deref().unwrap_or_default().contains(ENV_TLS_CLIENT_CA), "{resolution:?}");
    assert!(OtlpGrpcTlsState::from_config(&bad_mtls).is_err());
}

#[test]
fn certificates_without_the_switch_prevent_startup() {
    let Some(pki) = TempPki::generate("noflag") else { return };
    // 证书齐备但未启用 TLS：拒绝不一致的配置
    let config = OtlpGrpcTlsConfig { enabled: false, ..pki.mutual_tls_config() };
    let resolution = config.resolve();
    assert_eq!(resolution.mode, OtlpGrpcTlsMode::Plaintext);
    assert_eq!(resolution.degraded.as_deref().map(|r| r.contains(ENV_TLS)), Some(true), "{resolution:?}");
    assert!(config.describe().contains("不启用"), "{}", config.describe());
    assert!(OtlpGrpcTlsState::from_config(&config).is_err());
}

#[test]
fn real_material_loads_tls_and_mtls_server_configs() {
    let Some(pki) = TempPki::generate("load") else { return };
    // 单向 TLS：装配成功，模式映射为 ServerTls
    let single = pki.server_tls_config();
    let tls = single.load();
    assert!(tls.is_ok(), "服务端 TLS 装配失败: {tls:?}");
    let Ok(state) = OtlpGrpcTlsState::from_config(&single) else { panic!("Valid TLS rejected") };
    assert_eq!(state.mode, OtlpGrpcTlsMode::ServerTls);
    assert!(state.config.is_some());
    assert!(state.degraded.is_none());

    // mTLS：装配成功，模式映射为 MutualTls
    let mutual = pki.mutual_tls_config();
    let loaded = mutual.load();
    assert!(loaded.is_ok(), "mTLS 装配失败: {loaded:?}");
    let Ok(state) = OtlpGrpcTlsState::from_config(&mutual) else { panic!("Valid mTLS rejected") };
    assert_eq!(state.mode, OtlpGrpcTlsMode::MutualTls);
    assert!(state.config.is_some());
    assert!(state.degraded.is_none());

    // 证书与私钥不匹配（用另一套 PKI 的私钥）⇒ 拒绝启动
    let Some(other) = TempPki::generate("mismatch") else { return };
    let mismatched = OtlpGrpcTlsConfig {
        enabled: true,
        cert_pem: Some(pki.server_cert.clone()),
        key_pem: Some(other.server_key.clone()),
        client_ca_pem: None,
    };
    assert!(OtlpGrpcTlsState::from_config(&mismatched).is_err(), "Mismatched keys must reject startup");

    // 明文 state
    let plain = OtlpGrpcTlsState::plaintext();
    assert_eq!(plain.mode, OtlpGrpcTlsMode::Plaintext);
    assert!(plain.config.is_none());
}

#[tokio::test]
async fn bound_server_reports_its_actual_transport_mode() {
    let Some(pki) = TempPki::generate("bound") else { return };

    // 明文（默认）
    let plain = OtlpGrpcConfig { listen: "127.0.0.1:0".to_string(), ..OtlpGrpcConfig::default() };
    let server = OtlpGrpcServer::bind(&plain.listen, &plain, receiver()).await;
    assert!(server.is_ok(), "{server:?}");
    let Ok(server) = server else { return };
    assert_eq!(server.tls_mode(), OtlpGrpcTlsMode::Plaintext);
    assert!(server.tls_degraded().is_none());

    // mTLS：真实材料 ⇒ 服务端自查为 mtls
    let mutual = OtlpGrpcConfig { tls: pki.mutual_tls_config(), ..plain.clone() };
    let server = OtlpGrpcServer::bind(&mutual.listen, &mutual, receiver()).await;
    assert!(server.is_ok(), "{server:?}");
    let Ok(server) = server else { return };
    assert_eq!(server.tls_mode(), OtlpGrpcTlsMode::MutualTls);
    assert!(server.tls_degraded().is_none());
    assert_ne!(server.local_addr().map(|a| a.port()).unwrap_or(0), 0);

    // 证书路径不存在 ⇒ 拒绝服务并释放绑定端口
    let bad = OtlpGrpcConfig {
        tls: OtlpGrpcTlsConfig {
            enabled: true,
            cert_pem: Some(pki.dir.join("nope.crt")),
            key_pem: Some(pki.dir.join("nope.key")),
            client_ca_pem: None,
        },
        ..plain
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = OtlpGrpcServer::from_listener(listener, &bad, receiver());
    assert!(server.is_err(), "Invalid TLS must reject startup: {server:?}");
    assert!(tokio::net::TcpListener::bind(address).await.is_ok(), "Rejected startup must release the listener");
}
