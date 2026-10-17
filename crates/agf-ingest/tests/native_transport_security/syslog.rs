//! A certificate accepted by rustls is the only source of the Syslog mTLS flag.
use super::*;
use agf_ingest::syslog::{SyslogTlsListener, parse_certificates, parse_private_key};
use tokio::io::AsyncWriteExt;
use tokio_rustls::rustls::{ClientConfig, RootCertStore, crypto::ring, pki_types::ServerName};

#[tokio::test]
async fn stalled_handshake_does_not_block_a_second_connection() {
    let pki = make_pki("syslog-concurrency");
    let listener = SyslogTlsListener::bind(
        "127.0.0.1:0",
        &std::fs::read(&pki.server_cert).unwrap(),
        &std::fs::read(&pki.server_key).unwrap(),
    )
    .await
    .unwrap();
    let address = listener.local_addr().unwrap();
    let (stalled_socket, pending) = tokio::join!(tokio::net::TcpStream::connect(address), listener.accept_handshake());
    let stalled_socket = stalled_socket.unwrap();
    let pending = pending.unwrap();
    let stalled = tokio::spawn(async move { pending.complete(4096, 64, std::time::Duration::from_secs(1)).await });
    let (sent, received) = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        tokio::join!(
            client(&pki, address, None),
            listener.accept_connection(4096, 64, std::time::Duration::from_secs(1))
        )
    })
    .await
    .unwrap();
    sent.unwrap();
    let (connection, _) = received.unwrap();
    assert!(!connection.transport_peer().mutual_tls);
    assert!(!stalled.is_finished());
    stalled.abort();
    let _ = stalled.await;
    drop(stalled_socket);
}

async fn client(pki: &Pki, address: SocketAddr, trusted: Option<bool>) -> Result<(), String> {
    let mut roots = RootCertStore::empty();
    for cert in parse_certificates(&std::fs::read(&pki.ca).unwrap()).unwrap() {
        roots.add(cert).unwrap();
    }
    let builder = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots);
    let config = if let Some(trusted) = trusted {
        let (cert, key) = if trusted {
            (pki.client_cert.clone(), pki.client_key.clone())
        } else {
            other_client_identity(pki).unwrap()
        };
        builder
            .with_client_auth_cert(
                parse_certificates(&std::fs::read(cert).unwrap()).unwrap(),
                parse_private_key(&std::fs::read(key).unwrap()).unwrap(),
            )
            .unwrap()
    } else {
        builder.with_no_client_auth()
    };
    let stream = tokio::net::TcpStream::connect(address).await.map_err(|e| e.to_string())?;
    let mut tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("localhost").unwrap(), stream)
        .await
        .map_err(|e| e.to_string())?;
    tls.write_all(b"<13>trusted syslog\n").await.map_err(|e| e.to_string())?;
    tls.flush().await.map_err(|e| e.to_string())?;
    tls.shutdown().await.map_err(|e| e.to_string())
}

#[tokio::test]
async fn syslog_checks_client_ca_and_transports_verified_identity_to_pipeline() {
    let pki = make_pki("syslog-policy");
    let listener = SyslogTlsListener::bind_with_client_ca(
        "127.0.0.1:0",
        &std::fs::read(&pki.server_cert).unwrap(),
        &std::fs::read(&pki.server_key).unwrap(),
        Some(&std::fs::read(&pki.ca).unwrap()),
    )
    .await
    .unwrap();
    let address = listener.local_addr().unwrap();
    for trusted in [None, Some(false), Some(true)] {
        let (sent, accepted) = tokio::join!(
            client(&pki, address, trusted),
            listener.accept_connection(4096, 64, std::time::Duration::from_secs(2))
        );
        if trusted != Some(true) {
            assert!(accepted.is_err(), "missing/foreign certificate must fail the handshake");
            continue;
        }
        sent.unwrap();
        let (mut connection, _) = accepted.unwrap();
        let peer = connection.transport_peer();
        assert_eq!(peer.ip, Some("127.0.0.1".parse().unwrap()));
        assert!(peer.mutual_tls);
        let batch = connection.read_batch().await.unwrap();
        assert_eq!(batch.frames.len(), 1);
        let sink = Arc::new(InMemorySink::new());
        let pipeline = IngestPipeline::in_memory(sink.clone());
        let mut source = log_source();
        source.require_mtls = true;
        source.allowed_cidrs = vec!["127.0.0.1/32".into()];
        pipeline.ingest_raw_from(&source, IngestProtocol::Syslog, &batch.frames[0], "payload", peer).await.unwrap();
        assert_eq!(sink.raws().unwrap().len(), 1);
    }
    assert!(
        SyslogTlsListener::bind_with_client_ca(
            "127.0.0.1:0",
            &std::fs::read(&pki.server_cert).unwrap(),
            &std::fs::read(&pki.server_key).unwrap(),
            Some(b"invalid CA")
        )
        .await
        .is_err()
    );
}
