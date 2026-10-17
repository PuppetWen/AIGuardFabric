//! 真实 Agent 启动与 TLS 上报回归；仅验证健康确认链，不冒充完整发布安装验收。
use agf_agent::selfupdate::sha256_hex;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

struct Platform {
    origin: String,
    ca: PathBuf,
    peer: tokio::task::JoinHandle<Option<String>>,
}

async fn platform(root: &Path, status: u16) -> Platform {
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
    let ca_file = root.join("platform-ca.pem");
    fs::write(&ca_file, ca.pem()).unwrap();
    let peer = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(15), async move {
            let (socket, _) = listener.accept().await.ok()?;
            let mut socket = acceptor.accept(socket).await.ok()?;
            let mut request = Vec::new();
            loop {
                let mut buffer = [0_u8; 4096];
                let length = socket.read(&mut buffer).await.ok()?;
                if length == 0 || request.len() + length > 1024 * 1024 {
                    return None;
                }
                request.extend_from_slice(&buffer[..length]);
                if let Some(end) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                    let headers = std::str::from_utf8(&request[..end]).ok()?;
                    let size = headers.lines().find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })?;
                    if request.len() >= end + 4 + size {
                        break;
                    }
                }
            }
            let request = String::from_utf8(request).ok()?;
            // 本测试平台只接受这把临时注册凭据，先检验请求再发成功回执。
            if !request.starts_with("POST /api/v1/ingest/agent HTTP/1.1\r\n")
                || !request.contains("X-AGF-Key: agf_owned-update-health-fixture\r\n")
                || !request.contains("X-AGF-Agent-Id: owned-update-health-agent\r\n")
            {
                return None;
            }
            let response = format!("HTTP/1.1 {status} Fixture\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}");
            socket.write_all(response.as_bytes()).await.ok()?;
            socket.shutdown().await.ok()?;
            Some(request)
        })
        .await
        .ok()
        .flatten()
    });
    Platform { origin: format!("https://localhost:{port}"), ca: ca_file, peer }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn installed_real_agent_records_health_only_after_verified_tls_authorized_response_and_queue_commit() {
    for (status, trust_ca, healthy) in [(200, true, true), (401, true, false), (200, false, false)] {
        let dir = super::temporary_root();
        let target = dir.path().join("installed-agent.exe");
        fs::copy(env!("CARGO_BIN_EXE_agf-agent"), &target).unwrap();
        let digest = sha256_hex(&fs::read(&target).unwrap());
        let transaction = Uuid::new_v4();
        let nonce = Uuid::new_v4();
        let history = dir.path().join(".agf-updates").join(transaction.to_string());
        fs::create_dir_all(&history).unwrap();
        let deadline =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64 + 60_000;
        // 这里建立已安装事务上下文；发布验签、下载和替换由独立回归验证。
        let journal = serde_json::json!({
            "transaction":transaction,"target_name":"installed-agent.exe",
            "original_sha256":"0".repeat(64),"candidate_sha256":digest,
            "candidate_size":fs::metadata(&target).unwrap().len(),"manifest_sha256":"1".repeat(64),
            "key_id":"fixture","target_version":"99.0.0","phase":"awaiting_health",
            "nonce":nonce,"health_deadline_ms":deadline,"failure":null,
        });
        fs::write(history.join("journal.json"), serde_json::to_vec(&journal).unwrap()).unwrap();
        let platform = platform(dir.path(), status).await;
        let home = dir.path().join("empty-home");
        let data = dir.path().join("agent-data");
        fs::create_dir(&home).unwrap();
        let mut command = tokio::process::Command::new(&target);
        command.env_clear();
        if let Some(system_root) = std::env::var_os("SystemRoot") {
            command.env("SystemRoot", system_root);
        }
        // 只为本轮测试保留计数路径；无此变量时仍保持原空环境隔离。
        if let Some(profile_file) = std::env::var_os("LLVM_PROFILE_FILE") {
            command.env("LLVM_PROFILE_FILE", profile_file);
        }
        command
            .args(["run", "--once", "--no-system-probes", "--server", &platform.origin])
            .arg("--home")
            .arg(&home)
            .arg("--data-dir")
            .arg(&data)
            .env("AGF_MOCK_MODE", "0")
            .env("AGF_AGENT_ID", "owned-update-health-agent")
            .env("AGF_AGENT_TOKEN", "agf_owned-update-health-fixture")
            .env("AGF_UPDATE_INSTALL_ROOT", dir.path())
            .env("AGF_UPDATE_TARGET_NAME", "installed-agent.exe")
            .env("AGF_UPDATE_TRANSACTION", transaction.to_string())
            .env("AGF_UPDATE_HEALTH_NONCE", nonce.to_string())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        if trust_ca {
            command.env("AGF_AGENT_TLS_CA", &platform.ca);
        }
        let child = command.spawn().unwrap();
        let output = tokio::time::timeout(Duration::from_secs(20), child.wait_with_output())
            .await
            .expect("只有本测试持有的子进程，超时后 kill_on_drop 退出")
            .unwrap();
        assert_eq!(output.status.success(), healthy, "{}", String::from_utf8_lossy(&output.stderr));
        let request = platform.peer.await.unwrap();
        let heartbeat_file = history.join("heartbeat.json");
        assert_eq!(heartbeat_file.exists(), healthy);
        if healthy {
            let heartbeat: serde_json::Value = serde_json::from_slice(&fs::read(&heartbeat_file).unwrap()).unwrap();
            assert_eq!(heartbeat["transaction"], transaction.to_string());
            assert_eq!(heartbeat["nonce"], nonce.to_string());
            assert_eq!(heartbeat["executable_sha256"], digest);
            assert!(heartbeat["observed_ms"].as_u64().unwrap() <= deadline);
            assert!(request.unwrap().contains("owned-update-health-agent"));
            let queue = agf_agent::queue::LocalQueue::load(
                agf_agent::queue::QueueConfig::default().with_path(data.join("uplink-queue.jsonl")),
            )
            .unwrap();
            assert_eq!(queue.len(), 0, "平台成功回执后先持久化队列，再确认健康");
        } else if trust_ca {
            assert!(request.is_some(), "401 是已完成 TLS 后的真实鉴权拒绝");
            let queue = agf_agent::queue::LocalQueue::load(
                agf_agent::queue::QueueConfig::default().with_path(data.join("uplink-queue.jsonl")),
            )
            .unwrap();
            assert!(!queue.is_empty(), "失败快照必须保留供补传");
        } else {
            assert!(request.is_none(), "未受信任 TLS 服务不能收到凭据或上报正文");
        }
    }
}
