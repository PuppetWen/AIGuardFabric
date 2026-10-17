//! 真实本地 TLS 和已拥有子进程的副作用门禁；不访问外部平台、不附着内核。
use super::*;
use crate::client::TlsConfig;
use agf_core::{enums::PolicyAction, process_hook::ProcessReceipt, time::Timestamp};
use std::{
    fs,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
fn temporary_root() -> tempfile::TempDir {
    let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/test-data/process-hook");
    fs::create_dir_all(&parent).unwrap();
    tempfile::tempdir_in(parent).unwrap()
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reply {
    Allow,
    Deny,
    Quota,
    DryRun,
    Uncommitted,
    Expired,
    WrongNonce,
    WrongHash,
    Redirect,
    Timeout,
}
async fn server(dir: &Path, reply: Reply) -> (ProcessClient, Arc<AtomicBool>, tokio::task::JoinHandle<()>) {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca = params.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::from_params(&params, &ca_key);
    let key = rcgen::KeyPair::generate().unwrap();
    let certificate =
        rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap().signed_by(&key, &issuer).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.der().clone()],
            rustls_pki_types::PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let ca_path = dir.join(format!("ca-{port}.pem"));
    fs::write(&ca_path, ca.pem()).unwrap();
    let tls = TlsConfig { ca_pem: Some(ca_path), ..TlsConfig::default() };
    let client =
        ProcessClient::new(&format!("https://localhost:{port}"), "agf_owned_fixture".to_owned().into(), &tls).unwrap();
    let observed = Arc::new(AtomicBool::new(false));
    let seen = observed.clone();
    let marker = dir.join("side-effect.marker");
    let task = tokio::spawn(async move {
        let result=tokio::time::timeout(Duration::from_secs(10),async move{
            let(socket,_)=listener.accept().await.unwrap();let mut stream=acceptor.accept(socket).await.unwrap();
            let mut bytes=Vec::new();let end=loop{
                let mut buffer=[0_u8;1024];let n=stream.read(&mut buffer).await.unwrap();assert!(n>0 && bytes.len()+n<=32768);
                bytes.extend_from_slice(&buffer[..n]);if let Some(end)=bytes.windows(4).position(|v|v==b"\r\n\r\n"){break end+4;}
            };
            let head=std::str::from_utf8(&bytes[..end]).unwrap();
            assert!(head.starts_with("POST /api/v1/runtime/process/check HTTP/1.1"));
            assert!(head.to_ascii_lowercase().contains("x-agf-key: agf_owned_fixture"));
            let length=head.lines().find_map(|line|line.split_once(':').filter(|(k,_)|k.eq_ignore_ascii_case("content-length")).map(|(_,v)|v.trim().parse::<usize>().unwrap())).unwrap();
            while bytes.len()<end+length{let mut chunk=[0_u8;4096];let n=stream.read(&mut chunk).await.unwrap();assert!(n>0);bytes.extend_from_slice(&chunk[..n]);}
            let request:ProcessRequest=serde_json::from_slice(&bytes[end..end+length]).unwrap();request.validate().unwrap();
            assert!(!marker.exists(),"子进程不得在平台提交放行回执之前产生副作用");seen.store(true,Ordering::Release);
            if reply==Reply::Timeout{tokio::time::sleep(Duration::from_secs(4)).await;return;}
            let response=if reply==Reply::Redirect{b"HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:1/steal\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()}else{
                let receipt=ProcessReceipt{request_id:if reply==Reply::WrongNonce{Id::new()}else{request.request_id},agent_id:request.agent_id,
                    request_sha256:if reply==Reply::WrongHash{"0".repeat(64)}else{request.digest().unwrap()},mode:request.mode,
                    launch_allowed:matches!(reply,Reply::Allow|Reply::DryRun|Reply::Uncommitted|Reply::Expired|Reply::WrongNonce|Reply::WrongHash),
                    action:if reply==Reply::Quota{PolicyAction::Quota}else if matches!(reply,Reply::Deny|Reply::DryRun){PolicyAction::Deny}else{PolicyAction::Allow},
                    dry_run:reply==Reply::DryRun,audit_committed:reply!=Reply::Uncommitted,audit_id:Id::new(),
                    expires_at_ms:Timestamp::now().unix_millis()+if reply==Reply::Expired{-1}else{3000},enforced:false};
                let body=serde_json::to_vec(&receipt).unwrap();let mut out=format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).into_bytes();out.extend(body);out
            };
            stream.write_all(&response).await.unwrap();let _=stream.shutdown().await;
        }).await;
        assert!(result.is_ok(), "受控 TLS 任务不能无限等待");
    });
    (client, observed, task)
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_tls_committed_admission_is_required_before_a_benign_owned_child_can_create_its_marker() {
    for reply in [
        Reply::Deny,
        Reply::Quota,
        Reply::Uncommitted,
        Reply::Expired,
        Reply::WrongNonce,
        Reply::WrongHash,
        Reply::Redirect,
        Reply::Timeout,
        Reply::Allow,
        Reply::DryRun,
    ] {
        let dir = temporary_root();
        let image = dir.path().join("owned-process-helper.exe");
        fs::copy(std::env::current_exe().unwrap(), &image).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&image, fs::Permissions::from_mode(0o755)).unwrap();
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;
            if fs::metadata(&image).unwrap().uid() != 0 {
                let denied_client = ProcessClient::new(
                    "https://localhost:1",
                    "agf_owned_fixture".to_owned().into(),
                    &TlsConfig::default(),
                )
                .unwrap();
                assert!(run_managed(&denied_client, Id::new(), &image, &[]).await.is_err());
                return;
            }
        }
        let (client, seen, task) = server(dir.path(), reply).await;
        let args = vec![
            "--exact".into(),
            "process_hook::tests::managed_child_side_effect".into(),
            "--ignored".into(),
            "--nocapture".into(),
        ];
        let result = run_managed(&client, Id::new(), &image, &args).await;
        if matches!(reply, Reply::Allow | Reply::DryRun) {
            let mut child = result.unwrap();
            assert!(child.wait().unwrap().success());
            assert!(dir.path().join("side-effect.marker").exists());
        } else {
            assert!(result.is_err());
            assert!(!dir.path().join("side-effect.marker").exists());
        }
        task.await.unwrap();
        assert!(seen.load(Ordering::Acquire));
    }
}
