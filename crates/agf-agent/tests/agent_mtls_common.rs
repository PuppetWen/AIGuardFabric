//! `agent_mtls` 系列集成测试的**共享夹具**：自签 PKI 与进程内 rustls 服务端。
//!
//! 通过 `#[path = "agent_mtls_common.rs"] mod common;` 在多个测试 crate 里复用
//! （Cargo 把 `tests/` 下每个 `.rs` 当独立 crate，因此共享代码只能靠 `#[path]` 引入）。
//!
//! 本文件被 `#[path]` 引入到多个测试 crate，其中的 `pub` 项在"crate 根"看来不可达
//! （`unreachable_pub`），这是 `#[path]` 共享模块的固有形态，显式放行。
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, dead_code, unreachable_pub)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use rustls::pki_types::CertificateDer;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DistinguishedName, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 服务端任务等待上限：握手被拒时不能让测试挂死。
pub const SERVER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// 一套自签 PKI 的磁盘路径。
///
/// `keep_dir` 只用于**持有临时目录的所有权**（drop 时清理）；字段名不能带 `_` 前缀，
/// 否则 `-D warnings` 下会因 `used_underscore_binding` 直接失败。
#[derive(Debug)]
pub struct Pki {
    pub keep_dir: tempfile::TempDir,
    pub ca_pem: PathBuf,
    pub server_cert_pem: PathBuf,
    pub server_key_pem: PathBuf,
    pub client_cert_pem: PathBuf,
    pub client_key_pem: PathBuf,
}

impl Pki {
    /// 服务端 TLS 配置：**强制要求客户端证书**（这才是真正的 mTLS）。
    pub fn server_config(&self) -> ServerConfig {
        let certs = rustls_pemfile::certs(&mut std::fs::read(&self.server_cert_pem).unwrap().as_slice())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key =
            rustls_pemfile::private_key(&mut std::fs::read(&self.server_key_pem).unwrap().as_slice()).unwrap().unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(Arc::new(RecordingClientVerifier))
            .with_single_cert(certs, key)
            .unwrap()
    }

    /// 客户端证书的 SHA-256 指纹（hex，小写）——测试用它证明"服务端看到的确实是这张证书"。
    pub fn client_cert_fingerprint(&self) -> String {
        let der = rustls_pemfile::certs(&mut std::fs::read(&self.client_cert_pem).unwrap().as_slice())
            .next()
            .unwrap()
            .unwrap();
        sha256_hex(der.as_ref())
    }
}

/// 要求客户端证书、并如实记录其 DER 的校验器。
///
/// **本夹具不校验客户端证书的签发链**：rustls 的 `ClientCertVerifier` 契约里没有公开的
/// "按 RootCertStore 校验客户端链"入口（服务端链校验器不可复用）。这里只保证"客户端必须
/// 出示证书"（真正的 mTLS 握手）；链路校验由生产的入口网关承担——这一点如实标注，不假装做了。
#[derive(Debug)]
pub struct RecordingClientVerifier;

impl ClientCertVerifier for RecordingClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

/// SHA-256 hex（小写）。
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// 生成 CA + 服务端证书（SAN: localhost/127.0.0.1）+ 客户端证书。
pub fn make_pki() -> Pki {
    let dir = tempfile::tempdir().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(rcgen::DnType::CommonName, "agf-agent-test-ca");
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    // 用同一份参数 + 同一把 CA 私钥构造 issuer：签发叶子证书时 Issuer 字段必须与 CA 的主体一致。
    let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);

    let mut server_params =
        rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]).unwrap();
    server_params.distinguished_name.push(rcgen::DnType::CommonName, "agf-server-test");
    let server_key = rcgen::KeyPair::generate().unwrap();
    let server_cert = server_params.signed_by(&server_key, &issuer).unwrap();

    let mut client_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    client_params.distinguished_name.push(rcgen::DnType::CommonName, "agf-collector-test");
    client_params.distinguished_name.push(rcgen::DnType::OrganizationName, "agf-test-org");
    client_params.distinguished_name.push(rcgen::DnType::OrganizationalUnitName, "collectors");
    let client_key = rcgen::KeyPair::generate().unwrap();
    let client_cert = client_params.signed_by(&client_key, &issuer).unwrap();

    let write = |name: &str, content: String| -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, content).unwrap();
        path
    };
    Pki {
        ca_pem: write("ca.pem", ca_cert.pem()),
        server_cert_pem: write("server.pem", server_cert.pem()),
        server_key_pem: write("server.key", server_key.serialize_pem()),
        client_cert_pem: write("client.pem", client_cert.pem()),
        client_key_pem: write("client.key", client_key.serialize_pem()),
        keep_dir: dir,
    }
}

/// 起一个只接受一次连接的 mTLS 服务端；返回地址与"服务端看到的客户端证书指纹"句柄。
pub async fn spawn_mtls_server(pki: &Pki) -> (SocketAddr, tokio::task::JoinHandle<Option<String>>) {
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(pki.server_config()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.ok()?;
        let mut tls = acceptor.accept(stream).await.ok()?;
        let mut buf = vec![0_u8; 8192];
        let read = tls.read(&mut buf).await.ok()?;
        let request = String::from_utf8_lossy(&buf[..read]).to_string();
        let response = if request.starts_with("POST ") {
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"
                .to_string()
        } else {
            "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
        };
        tls.write_all(response.as_bytes()).await.ok()?;
        tls.flush().await.ok()?;
        // 服务端侧读到的客户端证书指纹（由 rustls 会话给出，客户端无法伪造）
        let (_, session) = tls.get_ref();
        session.peer_certificates().and_then(|certs| certs.first()).map(|cert| sha256_hex(cert.as_ref()))
    });
    (addr, handle)
}

/// Record the server's handshake failure even if Windows resets TCP before the alert is read.
pub async fn spawn_rejecting_mtls_server(pki: &Pki) -> (SocketAddr, tokio::task::JoinHandle<std::io::Error>) {
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(pki.server_config()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        acceptor.accept(stream).await.expect_err("anonymous handshake must be rejected")
    });
    (addr, task)
}

/// 起一个**不要求**客户端证书的 TLS 服务端（用于"跳过校验"路径）。
pub async fn spawn_server_auth_only(pki: &Pki) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let certs = rustls_pemfile::certs(&mut std::fs::read(&pki.server_cert_pem).unwrap().as_slice())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key =
        rustls_pemfile::private_key(&mut std::fs::read(&pki.server_key_pem).unwrap().as_slice()).unwrap().unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            if let Ok(mut tls) = acceptor.accept(stream).await {
                let mut buf = vec![0_u8; 4096];
                let _ = tls.read(&mut buf).await;
                let _ = tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").await;
                let _ = tls.flush().await;
            }
        }
    });
    (addr, handle)
}
