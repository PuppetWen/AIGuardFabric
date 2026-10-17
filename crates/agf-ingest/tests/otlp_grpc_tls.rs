//! OTLP/gRPC 端口**自身 TLS/mTLS** 的真机用例：真实 `tonic` 客户端 ↔ 真实 gRPC 服务端，
//! 走真实 TCP + 真实 TLS 握手（本机回环，不需要 docker）。
//!
//! 覆盖任务书要求的四件事：
//!
//! | 用例 | 断言 |
//! |---|---|
//! | (a) TLS 单向 | 带 CA 的客户端 `Export` **成功**，且记录真的经同一 pipeline 落库 |
//! | (b) mTLS | 带客户端证书 → 成功；**不带** → 握手被拒（打印原始错误） |
//! | (c) 错 CA | 信任另一个 CA 的客户端 → 握手失败（**不静默降级**） |
//! | (d) 明文 | 未配 TLS 时明文 gRPC 照常可用（向后兼容回归） |
//!
//! PKI 在测试内用 `rcgen` 生成并落盘到临时目录（**不入库、不进仓库**）。
#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used, clippy::print_stdout)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use agf_core::enums::{HealthState, IngestProtocol};
use agf_core::ids::{Id, TenantId};
use agf_core::source::{CollectionMode, LogSource, SourceConnection};
use agf_core::time::Timestamp;
use agf_ingest::bus::NoopEventBus;
use agf_ingest::otlp::OtlpLogsReceiver;
use agf_ingest::otlp_grpc::{OtlpGrpcConfig, OtlpGrpcServer, OtlpGrpcTlsConfig, OtlpGrpcTlsMode};
use agf_ingest::pipeline::{InMemorySink, IngestConfig, IngestPipeline, Sink};
use agf_ingest::registry::ParserRegistry;
use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::collector::logs::v1::logs_service_client::LogsServiceClient;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use opentelemetry_proto::tonic::resource::v1::Resource;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

#[path = "native_transport_security/grpc.rs"]
mod native_security;
#[path = "native_transport_security/syslog.rs"]
mod syslog_security;

// ---------------------------------------------------------------------------
// 夹具
// ---------------------------------------------------------------------------

fn log_source() -> LogSource {
    let now = Timestamp::now();
    LogSource {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        name: "otlp-grpc-tls-live".to_string(),
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

/// 测试 PKI（落盘到临时目录；文件路径正是环境变量会用的那种 PEM 路径）。
struct Pki {
    dir: PathBuf,
    ca: PathBuf,
    server_cert: PathBuf,
    server_key: PathBuf,
    client_cert: PathBuf,
    client_key: PathBuf,
    other_ca: PathBuf,
}

struct Ca {
    params: rcgen::CertificateParams,
    key: rcgen::KeyPair,
    cert_pem: String,
}

fn make_ca(common_name: &str) -> Ca {
    let mut params = rcgen::CertificateParams::new(Vec::new()).expect("CA 参数");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages.push(rcgen::KeyUsagePurpose::KeyCertSign);
    params.distinguished_name.push(rcgen::DnType::CommonName, common_name);
    let key = rcgen::KeyPair::generate().expect("CA 私钥");
    let cert = params.self_signed(&key).expect("自签 CA");
    Ca { params, key, cert_pem: cert.pem() }
}

fn make_leaf(ca: &Ca, common_name: &str, usage: rcgen::ExtendedKeyUsagePurpose) -> (String, String) {
    let issuer = rcgen::Issuer::from_params(&ca.params, &ca.key);
    let mut params =
        rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]).expect("叶子参数");
    params.distinguished_name.push(rcgen::DnType::CommonName, common_name);
    params.extended_key_usages.push(usage);
    let key = rcgen::KeyPair::generate().expect("叶子私钥");
    let cert = params.signed_by(&key, &issuer).expect("签发叶子证书");
    (cert.pem(), key.serialize_pem())
}

/// 生成一套落盘的测试 PKI。
///
/// `tag` **必须每个用例不同**：四个用例在同一个进程里并行跑，若共用目录就会互相覆盖
/// `ca.crt`/`server.key`（"服务端已加载 A 的证书、客户端却读到 B 的 CA" ⇒ 假失败）。
fn make_pki(tag: &str) -> Pki {
    let dir = std::env::current_dir().unwrap().join(".tmp/native-transport-tests").join(format!("{tag}-{}", Id::new()));
    std::fs::create_dir_all(&dir).expect("创建临时 PKI 目录");
    std::fs::write(dir.join("task-owner.txt"), "agf-native-transport-pki").unwrap();
    let ca = make_ca("agf-otlpgrpc-live-ca");
    let other = make_ca("agf-otlpgrpc-live-other-ca");
    let (server_cert, server_key) =
        make_leaf(&ca, "agf-otlpgrpc-live-server", rcgen::ExtendedKeyUsagePurpose::ServerAuth);
    let (client_cert, client_key) =
        make_leaf(&ca, "agf-otlpgrpc-live-client", rcgen::ExtendedKeyUsagePurpose::ClientAuth);
    let write = |name: &str, text: &str| -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, text).expect("写 PEM");
        path
    };
    Pki {
        ca: write("ca.crt", &ca.cert_pem),
        server_cert: write("server.crt", &server_cert),
        server_key: write("server.key", &server_key),
        client_cert: write("client.crt", &client_cert),
        client_key: write("client.key", &client_key),
        other_ca: write("other-ca.crt", &other.cert_pem),
        dir,
    }
}

impl Drop for Pki {
    fn drop(&mut self) {
        let root = std::env::current_dir().unwrap().join(".tmp/native-transport-tests").canonicalize().unwrap();
        let Ok(target) = self.dir.canonicalize() else { return };
        if target.starts_with(&root)
            && target != root
            && std::fs::read_to_string(target.join("task-owner.txt")).ok().as_deref()
                == Some("agf-native-transport-pki")
        {
            let _ = std::fs::remove_dir_all(target);
        }
    }
}

/// 起一个真实的 gRPC 服务端（回环 + 内核选口），返回地址与落库 Sink。
async fn start_server(tls: OtlpGrpcTlsConfig) -> (SocketAddr, Arc<InMemorySink>, OtlpGrpcTlsMode) {
    let sink = Arc::new(InMemorySink::new());
    let pipeline = IngestPipeline::new(
        ParserRegistry::with_builtins(),
        Arc::clone(&sink) as Arc<dyn Sink>,
        Arc::new(NoopEventBus),
        IngestConfig { emit_to_bus: false, ..IngestConfig::default() },
    );
    let receiver = Arc::new(OtlpLogsReceiver::new(Arc::new(pipeline), log_source()));
    let config = OtlpGrpcConfig { listen: "127.0.0.1:0".to_string(), tls, ..OtlpGrpcConfig::default() };
    let server = OtlpGrpcServer::bind(&config.listen, &config, receiver)
        .await
        .expect("回环绑定失败（端口 0 由内核分配，正常不会失败）");
    let mode = server.tls_mode();
    let addr = server.local_addr().expect("获取本地监听地址");
    tokio::spawn(async move {
        if let Err(e) = server.serve().await {
            println!("[tls-live] 服务端退出: {e}");
        }
    });
    (addr, sink, mode)
}

fn request_with(count: usize, tag: &str) -> ExportLogsServiceRequest {
    let records = (0..count)
        .map(|index| LogRecord {
            time_unix_nano: 1_770_985_425_000_000_000 + u64::try_from(index).unwrap_or(0) * 1_000_000,
            observed_time_unix_nano: 0,
            severity_number: 17,
            severity_text: "ERROR".to_string(),
            body: Some(AnyValue {
                value: Some(any_value::Value::StringValue(format!(
                    "<34>Feb 21 10:23:4{index} {tag}-prod-0{index} sshd[2311]: Failed password for root from 203.0.113.7{index} port 5123{index} ssh2"
                ))),
            }),
            attributes: vec![KeyValue {
                key: "e2e.case".to_string(),
                value: Some(AnyValue { value: Some(any_value::Value::StringValue(tag.to_string())) }),
            }],
            dropped_attributes_count: 0,
            flags: 0,
            trace_id: vec![],
            span_id: vec![],
            event_name: String::new(),
        })
        .collect();
    ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: Some(Resource {
                attributes: vec![KeyValue {
                    key: "service.name".to_string(),
                    value: Some(AnyValue { value: Some(any_value::Value::StringValue("agf-tls-live".to_string())) }),
                }],
                dropped_attributes_count: 0,
                entity_refs: vec![],
            }),
            scope_logs: vec![ScopeLogs { scope: None, log_records: records, schema_url: String::new() }],
            schema_url: String::new(),
        }],
    }
}

/// 带 CA（与可选客户端证书）的 TLS gRPC 客户端。
async fn tls_client(
    addr: SocketAddr,
    ca: &Path,
    identity: Option<(&Path, &Path)>,
) -> Result<LogsServiceClient<Channel>, String> {
    let mut tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(std::fs::read(ca).expect("读 CA")))
        .domain_name("127.0.0.1");
    if let Some((cert, key)) = identity {
        tls = tls.identity(Identity::from_pem(
            std::fs::read(cert).expect("读客户端证书"),
            std::fs::read(key).expect("读客户端私钥"),
        ));
    }
    let endpoint = Endpoint::from_shared(format!("https://{addr}"))
        .map_err(|e| format!("endpoint 构造失败: {e}"))?
        .tls_config(tls)
        .map_err(|e| format!("tls_config 失败: {e}"))?;
    let channel = endpoint.connect().await.map_err(|e| format!("TLS 连接失败: {e}"))?;
    Ok(LogsServiceClient::new(channel))
}

// ---------------------------------------------------------------------------
// (a) 单向 TLS：带 CA 的客户端 Export 成功并落库
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tls_server_accepts_client_with_the_right_ca_and_persists_records() {
    let pki = make_pki("case-a");
    let tls = OtlpGrpcTlsConfig {
        enabled: true,
        cert_pem: Some(pki.server_cert.clone()),
        key_pem: Some(pki.server_key.clone()),
        client_ca_pem: None,
    };
    let (addr, sink, mode) = start_server(tls).await;
    assert_eq!(mode, OtlpGrpcTlsMode::ServerTls, "单向 TLS：不要求客户端证书");
    println!("[tls-live][a] server={addr} mode={}", mode.as_str());

    let client = tls_client(addr, &pki.ca, None).await;
    assert!(client.is_ok(), "带正确 CA 的 TLS 客户端必须握手成功: {client:?}");
    let mut client = client.expect("TLS 客户端");
    let response = client.export(request_with(2, "tls")).await.expect("TLS 上 Export 必须成功").into_inner();
    println!("[tls-live][a] partial_success={:?}", response.partial_success);
    assert!(response.partial_success.is_none(), "2 条记录不应被拒");

    let landed = sink.event_count(TenantId::default_tenant()).await.unwrap_or(0);
    println!("[tls-live][a] 落库事件数={landed}");
    assert_eq!(landed, 2, "TLS 通道上的两条 LogRecord 必须经同一 pipeline 落库");
}

// ---------------------------------------------------------------------------
// (b) mTLS：无客户端证书被拒，有证书成功
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mutual_tls_rejects_clients_without_certificate_and_accepts_those_with_one() {
    let pki = make_pki("case-b");
    let tls = OtlpGrpcTlsConfig {
        enabled: true,
        cert_pem: Some(pki.server_cert.clone()),
        key_pem: Some(pki.server_key.clone()),
        client_ca_pem: Some(pki.ca.clone()),
    };
    let (addr, sink, mode) = start_server(tls).await;
    assert_eq!(mode, OtlpGrpcTlsMode::MutualTls, "配了客户端 CA ⇒ mTLS");
    println!("[tls-live][b] server={addr} mode={}", mode.as_str());

    // ① 不带客户端证书：握手/RPC 必须被拒（原始错误照抄）
    //
    // 注意 TLS 1.3 的时序：客户端在收到服务端的 CertificateRequest 后仍会先发 Finished，
    // 因此 `connect()` 可能"看起来成功"，真正的拒绝在服务端 —— 表现为**第一条 RPC 失败**。
    // 因此这里断言"RPC 必须失败"，并把 connect 与 export 两个阶段的原始结果都打出来。
    let without = tls_client(addr, &pki.ca, None).await;
    match without {
        Err(e) => {
            println!("[tls-live][b] 不带客户端证书 ⇒ connect 阶段即被拒: {e}");
        }
        Ok(mut client) => {
            let response = client.export(request_with(1, "no-cert")).await;
            let raw = match &response {
                Ok(_) => "（意外成功：mTLS 未强制！）".to_string(),
                Err(status) => format!("{status}"),
            };
            println!("[tls-live][b] 不带客户端证书 ⇒ connect 成功、Export 被拒: {raw}");
            assert!(response.is_err(), "mTLS 下不带客户端证书的 Export 必须失败，实际: {raw}");
            let lowered = raw.to_lowercase();
            assert!(
                lowered.contains("certificate") || lowered.contains("tls") || lowered.contains("transport"),
                "错误应指向证书/TLS: {raw}"
            );
        }
    }
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.unwrap_or(0), 0, "被拒的调用不得写入任何事件");

    // ② 带客户端证书：成功且落库
    let with = tls_client(addr, &pki.ca, Some((&pki.client_cert, &pki.client_key))).await;
    assert!(with.is_ok(), "带客户端证书必须成功: {with:?}");
    let mut client = with.expect("mTLS 客户端");
    let response = client.export(request_with(2, "mtls")).await.expect("mTLS 上 Export 必须成功").into_inner();
    println!("[tls-live][b] 带客户端证书 ⇒ Export OK, partial_success={:?}", response.partial_success);
    let landed = sink.event_count(TenantId::default_tenant()).await.unwrap_or(0);
    println!("[tls-live][b] 落库事件数={landed}");
    assert_eq!(landed, 2, "mTLS 通道上的记录必须落库");

    // ③ 用**另一个 CA 签发**的客户端证书：同样被拒（我方只信任配置的客户端 CA）
    let Some(foreign_leaf) = other_client_identity(&pki) else { return };
    let refused = match tls_client(addr, &pki.ca, Some((&foreign_leaf.0, &foreign_leaf.1))).await {
        Ok(mut client) => {
            let outcome = client.export(request_with(1, "foreign")).await;
            match &outcome {
                Ok(_) => "（意外成功：非受信客户端证书竟然通过了！）".to_string(),
                Err(status) => format!("Export 被拒: {status}"),
            }
        }
        Err(e) => format!("connect 阶段被拒: {e}"),
    };
    println!("[tls-live][b] 非受信 CA 签发的客户端证书 ⇒ {refused}");
    assert!(!refused.contains("意外成功"), "非受信客户端证书必须被拒: {refused}");
}

/// 用**另一个** CA 签一张客户端证书（用于"非受信客户端"负例）。
fn other_client_identity(pki: &Pki) -> Option<(PathBuf, PathBuf)> {
    let other = make_ca("agf-otlpgrpc-live-other-ca");
    let (cert, key) = make_leaf(&other, "agf-otlpgrpc-live-foreign-client", rcgen::ExtendedKeyUsagePurpose::ClientAuth);
    let cert_path = pki.dir.join("foreign-client.crt");
    let key_path = pki.dir.join("foreign-client.key");
    std::fs::write(&cert_path, cert).ok()?;
    std::fs::write(&key_path, key).ok()?;
    Some((cert_path, key_path))
}

// ---------------------------------------------------------------------------
// (c) 错 CA：握手失败，绝不静默降级
// ---------------------------------------------------------------------------

#[tokio::test]
async fn wrong_ca_fails_the_handshake_instead_of_downgrading() {
    let pki = make_pki("case-c");
    let tls = OtlpGrpcTlsConfig {
        enabled: true,
        cert_pem: Some(pki.server_cert.clone()),
        key_pem: Some(pki.server_key.clone()),
        client_ca_pem: None,
    };
    let (addr, sink, _mode) = start_server(tls).await;

    // 客户端只信任**另一个** CA ⇒ 服务端证书链校验失败
    let wrong = tls_client(addr, &pki.other_ca, None).await;
    let raw = match &wrong {
        Ok(_) => "（意外成功：错 CA 竟然通过了！）".to_string(),
        Err(e) => e.clone(),
    };
    println!("[tls-live][c] 错 CA ⇒ {raw}");
    assert!(wrong.is_err(), "错 CA 必须握手失败（不静默降级）");
    let lowered = raw.to_lowercase();
    assert!(
        lowered.contains("certificate")
            || lowered.contains("unknown")
            || lowered.contains("invalid")
            || lowered.contains("tls"),
        "错误文本应指向证书校验失败: {raw}"
    );
    // 且没有任何数据落库（失败的握手不该产生事件）
    let landed = sink.event_count(TenantId::default_tenant()).await.unwrap_or(0);
    println!("[tls-live][c] 错 CA 情况下落库事件数={landed}");
    assert_eq!(landed, 0, "握手失败不得写入任何事件");
}

// ---------------------------------------------------------------------------
// (d) 明文回归：不配 TLS 时一切照旧
// ---------------------------------------------------------------------------

#[tokio::test]
async fn plaintext_mode_still_serves_grpc() {
    let (addr, sink, mode) = start_server(OtlpGrpcTlsConfig::default()).await;
    assert_eq!(mode, OtlpGrpcTlsMode::Plaintext, "默认必须是明文（向后兼容）");
    println!("[tls-live][d] server={addr} mode={}", mode.as_str());
    let mut client = LogsServiceClient::connect(format!("http://{addr}")).await.expect("明文客户端必须连上");
    let response = client.export(request_with(2, "plain")).await.expect("明文 Export 必须成功").into_inner();
    println!("[tls-live][d] partial_success={:?}", response.partial_success);
    assert!(response.partial_success.is_none());
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.unwrap_or(0), 2, "明文通道必须照常落库");

    // 对**明文**端口发 TLS：必须失败（而不是被当成明文请求混过去）
    let tls_against_plain = tls_client(addr, &make_pki("case-d").ca, None).await;
    println!("[tls-live][d] 对明文端口用 TLS ⇒ {:?}", tls_against_plain.as_ref().err());
    assert!(tls_against_plain.is_err(), "明文端口不接受 TLS 握手（也说明 TLS 确实没被静默打开）");
}
