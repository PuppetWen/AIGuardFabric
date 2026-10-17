//! 流式 TLS / UDP 监听器用例：跨批次收帧、半关闭保帧、垃圾 PEM 不 panic 与真实 datagram。

use super::*;

/// 半帧（缺换行/未收全）在连接关闭时**如实计数**为 dropped，不静默消失。
#[tokio::test]
async fn frame_reader_counts_leftover_partial_frame_on_eof() {
    use tokio::io::AsyncWriteExt;
    let (mut client, server) = tokio::io::duplex(4_096);
    let mut reader = FrameReader::new(server, 65_536, 64, std::time::Duration::from_millis(200));
    let mut payload = SyslogFraming::encode_non_transparent(b"<13>first");
    payload.extend_from_slice(b"<13>half-frame-no-newline");
    let write = tokio::spawn(async move {
        let _ = client.write_all(&payload).await;
        let _ = client.flush().await;
        drop(client);
    });
    let mut frames = Vec::new();
    let mut dropped = 0_usize;
    loop {
        let Ok(batch) = reader.read_batch().await else { break };
        dropped += batch.dropped;
        frames.extend(batch.frames);
        if batch.eof || batch.idle_timeout {
            break;
        }
    }
    let _ = write.await;
    assert_eq!(frames.len(), 1, "完整的换行帧必须收到");
    assert_eq!(dropped, 1, "半帧必须计入 dropped（可观测），不得静默丢弃");
}

// ---- Syslog TLS（RFC5425）：端到端 ----

/// 现场生成自签证书 + 私钥（PEM）+ 证书 DER（**不落盘、不入库私钥**）。
fn tls_material() -> Option<(String, String, Vec<u8>)> {
    // 默认 `IsCa::NoCa`：rustls 拒绝"CA 证书当服务端证书"（CaUsedAsEndEntity）
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]).ok()?;
    let key = rcgen::KeyPair::generate().ok()?;
    let cert = params.self_signed(&key).ok()?;
    Some((cert.pem(), key.serialize_pem(), cert.der().to_vec()))
}

/// 连一条信任该自签证书的 TLS 客户端。
async fn tls_client(addr: SocketAddr, cert_der: Vec<u8>) -> Option<tokio_rustls::client::TlsStream<TcpStream>> {
    let mut roots = tokio_rustls::rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(cert_der)).ok()?;
    let provider = std::sync::Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let config = tokio_rustls::rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .ok()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let name = tokio_rustls::rustls::pki_types::ServerName::try_from("localhost").ok()?;
    let tcp = TcpStream::connect(addr).await.ok()?;
    connector.connect(name, tcp).await.ok()
}

/// 收一条 TLS 连接上的全部帧，返回 `(帧数, 丢弃数, 是否干净结束)`。
async fn collect_tls_frames(listener: &SyslogTlsListener, timeout_secs: u64) -> (usize, usize, bool) {
    let accepted = tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        listener.accept_connection(65_536, 64, std::time::Duration::from_millis(300)),
    )
    .await;
    let Ok(Ok((mut conn, _peer))) = accepted else { return (0, 0, false) };
    let mut frames = 0_usize;
    let mut dropped = 0_usize;
    loop {
        let Ok(batch) = conn.read_batch().await else { return (frames, dropped, false) };
        frames += batch.frames.len();
        dropped += batch.dropped;
        if batch.eof {
            return (frames, dropped, true);
        }
        if batch.idle_timeout || frames > 10_000 {
            return (frames, dropped, false);
        }
    }
}

/// 正常关闭（发 `close_notify`）：跨越多个批次（`max_frames_per_read = 64`）也不得丢帧。
#[tokio::test]
async fn tls_listener_receives_all_frames_across_batches() {
    const N: usize = 200;
    let Some((cert_pem, key_pem, cert_der)) = tls_material() else { return };
    let listener = SyslogTlsListener::bind("127.0.0.1:0", cert_pem.as_bytes(), key_pem.as_bytes()).await;
    assert!(listener.is_ok(), "{listener:?}");
    let Ok(listener) = listener else { return };
    let Ok(addr) = listener.local_addr() else { return };
    let sender = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        let Some(mut tls) = tls_client(addr, cert_der).await else { return false };
        for i in 0..N {
            let frame = format!("<34>Feb 21 10:23:45 h app: TLS 第 {i} 条");
            let bytes = SyslogFraming::encode_octet_counting(frame.as_bytes());
            let cut = bytes.len() / 2;
            if tls.write_all(bytes.get(..cut).unwrap_or_default()).await.is_err() {
                return false;
            }
            if tls.write_all(bytes.get(cut..).unwrap_or_default()).await.is_err() {
                return false;
            }
        }
        tls.flush().await.is_ok() && tls.shutdown().await.is_ok()
    });
    let (frames, dropped, clean) = collect_tls_frames(&listener, 10).await;
    assert!(sender.await.unwrap_or(false), "TLS 客户端发送/正常关闭失败");
    assert_eq!(frames, N, "TLS 单连接 {N} 帧必须全部收到（每批 64 帧，必须跨批次）");
    assert_eq!(dropped, 0, "不应有丢弃");
    assert!(clean, "对端发了 close_notify，必须干净结束（EOF）");
}

/// **模拟器实测缺陷的回归**：客户端发完帧后**半关闭 TCP 而不发 `close_notify`**
/// （`tools/simulators/syslog_tls.py send` 就是这么做的）。
///
/// 修复前：rustls 抛 `UnexpectedEof`，tokio-rustls 在"已解密明文仍在缓冲里"时就返回错误，
/// 整批帧被丢弃（实测 7 帧全丢、且上层只看到"读取失败"）。现在必须**一帧不少且干净结束**。
#[tokio::test]
async fn tls_listener_keeps_frames_when_peer_half_closes_without_close_notify() {
    const N: usize = 7;
    let Some((cert_pem, key_pem, cert_der)) = tls_material() else { return };
    let listener = SyslogTlsListener::bind("127.0.0.1:0", cert_pem.as_bytes(), key_pem.as_bytes()).await;
    assert!(listener.is_ok(), "{listener:?}");
    let Ok(listener) = listener else { return };
    let Ok(addr) = listener.local_addr() else { return };
    let sender = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        let Some(mut tls) = tls_client(addr, cert_der).await else { return false };
        for i in 0..N {
            let frame = format!("<34>Feb 21 10:23:45 h app: 半关闭前第 {i} 帧");
            let bytes = SyslogFraming::encode_octet_counting(frame.as_bytes());
            if tls.write_all(&bytes).await.is_err() {
                return false;
            }
        }
        if tls.flush().await.is_err() {
            return false;
        }
        // 关键：只对**底层 TCP** 半关闭（不发 close_notify）
        let (io, _session) = tls.get_mut();
        io.shutdown().await.is_ok()
    });
    let (frames, dropped, clean) = collect_tls_frames(&listener, 10).await;
    assert!(sender.await.unwrap_or(false), "TLS 客户端写入失败");
    assert_eq!(frames, N, "半关闭不带 close_notify 时**不得丢帧**（修复前这里收到 0 帧）");
    assert_eq!(dropped, 0);
    assert!(clean, "对端 FIN 必须归一为干净 EOF，而不是读取失败");
}

#[tokio::test]
async fn tls_listener_rejects_garbage_pem_without_panicking() {
    let err = SyslogTlsListener::bind("127.0.0.1:0", b"not a pem at all", b"nope").await;
    assert!(matches!(err, Err(DomainError::Config(_))), "非法 PEM 必须返回 Config 错误: {err:?}");
    let no_block = SyslogTlsListener::bind("127.0.0.1:0", b"-----BEGIN CERTIFICATE-----\n!!!\n", b"x").await;
    assert!(matches!(no_block, Err(DomainError::Config(_))), "{no_block:?}");
}

#[test]
fn pem_parsers_extract_der_and_reject_junk() {
    // 证书块：base64 解出 6 字节 DER（内容不参与校验，只验解析路径）
    let cert_pem = b"-----BEGIN CERTIFICATE-----\nQUJDREVG\n-----END CERTIFICATE-----\n";
    let certs = parse_certificates(cert_pem);
    assert!(certs.is_ok(), "{certs:?}");
    assert_eq!(certs.map(|c| c.len()), Ok(1));
    assert!(parse_certificates(b"-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----\n").is_err());
    assert!(parse_certificates(&[0xff, 0xfe]).is_err(), "非 UTF-8 必须报错而不是 panic");

    // 私钥块：PKCS#8 / PKCS#1 / SEC1 三种 label 都要认
    for label in ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"] {
        let pem = format!("-----BEGIN {label}-----\nQUJDREVG\n-----END {label}-----\n");
        assert!(parse_private_key(pem.as_bytes()).is_ok(), "{label} 应被识别");
    }
    assert!(parse_private_key(b"-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n").is_err());
}

#[tokio::test]
async fn udp_listener_receives_datagram() {
    let listener = SyslogUdpListener::bind("127.0.0.1:0").await;
    assert!(listener.is_ok(), "{listener:?}");
    let Ok(listener) = listener else { return };
    let Ok(addr) = listener.local_addr() else { return };
    let socket = UdpSocket::bind("127.0.0.1:0").await;
    let Ok(socket) = socket else { return };
    let sent = socket.send_to(b"<13>Feb 21 10:23:45 udp-host app: hello", addr).await;
    assert!(sent.is_ok());
    let got = listener.recv_datagram(65_536, 5_000).await;
    assert!(got.is_ok(), "{got:?}");
    let Ok((bytes, _peer)) = got else { return };
    let parsed = parse_bytes(&bytes);
    assert_eq!(parsed.map(|m| m.msg), Ok("hello".to_string()));
    let timeout = listener.recv_datagram(65_536, 50).await;
    assert!(matches!(timeout, Err(DomainError::Timeout(_))), "{timeout:?}");
}
