//! 使用真实回环 TLS 验证生产下载器的证书与传输约束。
use super::*;
use crate::platform;
use std::{fs, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
struct Server {
    url: String,
    ca: std::path::PathBuf,
    task: tokio::task::JoinHandle<Option<String>>,
}
async fn server(dir: &std::path::Path, response: Vec<u8>) -> Server {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca = params.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::from_params(&params, &ca_key);
    let server_key = rcgen::KeyPair::generate().unwrap();
    let certificate =
        rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap().signed_by(&server_key, &issuer).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.der().clone()],
            rustls_pki_types::PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(
                server_key.serialize_der(),
            )),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let ca_path = dir.join(format!("ca-{port}.pem"));
    fs::write(&ca_path, ca.pem()).unwrap();
    let task = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(5), async move {
            let (socket, _) = listener.accept().await.ok()?;
            let mut socket = acceptor.accept(socket).await.ok()?;
            let mut input = Vec::new();
            loop {
                let mut bytes = [0_u8; 1024];
                let size = socket.read(&mut bytes).await.ok()?;
                if size == 0 || input.len() + size > 8192 {
                    return None;
                }
                input.extend_from_slice(&bytes[..size]);
                if input.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    break;
                }
            }
            socket.write_all(&response).await.ok()?;
            socket.shutdown().await.ok()?;
            String::from_utf8(input).ok()
        })
        .await
        .ok()
        .flatten()
    });
    Server { url: format!("https://localhost:{port}/artifact"), ca: ca_path, task }
}
async fn download_fixture(
    server: &Server,
    dir: &std::path::Path,
    trusted_ca: bool,
) -> agf_core::error::DomainResult<()> {
    let (manifest, anchor, mut policy) = regression::signed(b"payload", &server.url);
    if trusted_ca {
        policy.enterprise_ca = Some(server.ca.clone());
    }
    let update =
        verify_release(&manifest, &anchor, policy, "fixture", "1.0.0", platform::current(), platform::current_arch())?
            .expect("Eligible signed fixture");
    download::artifact(&update, &dir.join("download")).await
}
#[tokio::test]
async fn enterprise_ca_real_https_downloads_exact_bytes_and_never_sends_credentials() {
    let dir = regression::temporary_root();
    let server =
        server(dir.path(), b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload".to_vec()).await;
    download_fixture(&server, dir.path(), true).await.unwrap();
    assert_eq!(fs::read(dir.path().join("download")).unwrap(), b"payload");
    let request = server.task.await.unwrap().unwrap().to_ascii_lowercase();
    assert!(request.starts_with("get /artifact http/1.1"));
    assert!(!request.contains("authorization:") && !request.contains("cookie:"));
}
#[tokio::test]
async fn untrusted_tls_wrong_length_sha_and_chunked_over_budget_never_become_installable() {
    for (trusted, response) in [
        (false, "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload"),
        (true, "HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\npayloadx"),
        (true, "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\ncorrupt"),
        (true, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n8\r\npayloadx\r\n0\r\n\r\n"),
    ] {
        let dir = regression::temporary_root();
        let server = server(dir.path(), response.as_bytes().to_vec()).await;
        assert!(download_fixture(&server, dir.path(), trusted).await.is_err());
        let _ = server.task.await.unwrap();
        assert!(!dir.path().join("agent-fixture.exe").exists());
    }
}
#[tokio::test]
async fn redirect_to_another_origin_or_plaintext_is_not_followed() {
    let sink = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dir = regression::temporary_root();
    let response = format!(
        "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:{}/steal\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        sink.local_addr().unwrap().port()
    );
    let server = server(dir.path(), response.into_bytes()).await;
    assert!(download_fixture(&server, dir.path(), true).await.is_err());
    let _ = server.task.await.unwrap();
    assert!(tokio::time::timeout(Duration::from_millis(100), sink.accept()).await.is_err());
    assert!(!dir.path().join("download").exists());
}
