//! 由 `http_vendors.rs` 拆分：`isolate_message` 等 8 个函数（纯搬移，逻辑不变）。
use super::*;

// ---------------------------------------------------------------------------
// EDR：隔离指令下发
// ---------------------------------------------------------------------------

pub(crate) fn isolate_message() -> AdapterMessage {
    AdapterMessage::event("enforce.isolate", Severity::Critical, "隔离受控主机", "检出 C2 回连", json!({}))
        .with_label("action", "isolate")
        .with_label("host_id", "host-42")
}

#[tokio::test]
pub(crate) async fn edr_posts_isolate_command_with_bearer_and_dry_run_headers() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/hosts/host-42/isolate"))
        .and(header("authorization", "Bearer edr-token-abcdef"))
        .and(header("X-AGF-EDR-Vendor", "generic-edr"))
        .and(header("X-AGF-Dry-Run", "false"))
        .and(body_partial_json(json!({
            "action": "isolate",
            "host_id": "host-42",
            "dry_run": false,
            "requested_by": "aiguardfabric",
        })))
        .respond_with(ResponseTemplate::new(202).set_body_json(json!({"task_id": "task-9", "status": "accepted"})))
        .expect(1)
        .mount(&server)
        .await;

    let endpoint = server.uri();
    let mut edr = adapter::<EdrIsolation>(
        &[("endpoint", json!(endpoint)), ("dry_run", json!(false))],
        &[("api_token", "edr-token-abcdef")],
        5,
        retry_once(),
        circuit(3, 30),
        false,
    )
    .await;

    let receipt = edr.send(&isolate_message()).await.expect("真实 HTTP 下发应成功");
    assert_eq!(receipt.remote_id.as_deref(), Some("task-9"), "远端任务 id 必须来自响应体");
    assert_eq!(receipt.origin, format!("{}/v1/hosts/host-42/isolate", server.uri()));
    server.verify().await;
}

#[tokio::test]
pub(crate) async fn edr_rejects_payload_without_target_host_before_any_request() {
    let server = MockServer::start().await;
    Mock::given(any()).respond_with(ResponseTemplate::new(202)).expect(0).mount(&server).await;

    let endpoint = server.uri();
    let mut edr = adapter::<EdrIsolation>(
        &[("endpoint", json!(endpoint))],
        &[("api_token", "t")],
        5,
        retry_once(),
        circuit(3, 30),
        false,
    )
    .await;

    let no_host = AdapterMessage::event("enforce.isolate", Severity::High, "隔离", "缺目标", json!({}))
        .with_label("action", "isolate");
    let error = edr.send(&no_host).await.expect_err("缺目标主机必须拒绝");
    assert!(matches!(error, DomainError::Validation(_)), "{error}");
    server.verify().await;
}

// ---------------------------------------------------------------------------
// Syslog：真实 UDP/TCP 回环
// ---------------------------------------------------------------------------

pub(crate) fn policy_message() -> AdapterMessage {
    AdapterMessage::event("ai.policy.denied", Severity::High, "策略拒绝", "命中 PA-DENY-002", json!({}))
        .with_asset("gw-1")
}

#[tokio::test]
pub(crate) async fn syslog_udp_roundtrip_delivers_rfc5424_datagram() {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("绑定本地 UDP");
    let port = socket.local_addr().expect("本地地址").port();
    let endpoint = format!("udp://127.0.0.1:{port}");

    let mut syslog =
        adapter::<SyslogForwarder>(&[("endpoint", json!(endpoint))], &[], 5, retry_once(), circuit(3, 30), false).await;
    assert_eq!(syslog.mode(), AdapterMode::Live);

    let receipt = syslog.send(&policy_message()).await.expect("真实 UDP 发包应成功");
    assert!(receipt.accepted && !receipt.mocked);

    let mut buf = vec![0_u8; 2048];
    let (len, _) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
        .await
        .expect("应在 2s 内收到 syslog 报文")
        .expect("UDP 读取成功");
    let line = String::from_utf8_lossy(&buf[..len]).to_string();
    assert!(line.starts_with("<84>1 "), "facility=10 + severity=4(Warning) ⇒ PRI 84: {line}");
    assert!(line.contains(" agf-event "), "{line}");
    assert!(line.contains("event_type=\"ai.policy.denied\""), "{line}");
    assert!(line.contains("asset=\"gw-1\""), "{line}");
}

#[tokio::test]
pub(crate) async fn syslog_tcp_roundtrip_delivers_newline_framed_line() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("绑定本地 TCP 监听");
    let port = listener.local_addr().expect("本地地址").port();
    let endpoint = format!("tcp://127.0.0.1:{port}");

    let mut syslog =
        adapter::<SyslogForwarder>(&[("endpoint", json!(endpoint))], &[], 5, retry_once(), circuit(3, 30), false).await;
    let receipt = syslog.send(&policy_message()).await.expect("真实 TCP 发包应成功");
    assert!(receipt.accepted && !receipt.mocked);

    let (mut stream, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
        .await
        .expect("应在 2s 内建立 TCP 连接")
        .expect("accept 成功");
    let mut buf = vec![0_u8; 2048];
    let len = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .expect("应在 2s 内读到报文")
        .expect("TCP 读取成功");
    let line = String::from_utf8_lossy(&buf[..len]).to_string();
    assert!(line.starts_with("<84>1 "), "{line}");
    assert!(line.ends_with('\n'), "RFC 6587 非透明分帧必须以 LF 结尾: {line:?}");
    assert!(line.contains("命中 PA-DENY-002"), "{line}");
}

// ---------------------------------------------------------------------------
// email：已实现真实 SMTP 投递（会话往返见 `tests/email_smtp.rs`）+ Mock 零网络
// ---------------------------------------------------------------------------

#[tokio::test]
pub(crate) async fn email_live_mode_has_real_smtp_transport() {
    // 旧的"如实未实现"断言已被真实投递取代：email 现在覆写 `invoke_live` 走真实 SMTP 会话。
    // 这里指向一个本机不可达端口，断言"真的去建连了"（而非诚实返回 NotImplemented）。
    let mut email = adapter::<Email>(
        &[
            ("smtp_host", json!("127.0.0.1")),
            ("smtp_port", json!(1)),
            ("smtp_security", json!("none")),
            ("from", json!("agf@example.invalid")),
            ("to", json!(["soc@example.invalid"])),
        ],
        &[],
        2,
        retry_once(),
        circuit(3, 30),
        false,
    )
    .await;

    assert_eq!(email.mode(), AdapterMode::Live);
    assert!(email.descriptor().real_implementation, "email 已实现真实投递，必须如实登记");
    let record = email.build_record();
    assert_eq!(record.status, agf_adapters::HealthStatus::Available, "已实现真实传输且无失败 ⇒ 可用");
    assert!(!record.message.unwrap_or_default().contains("TODO("), "不得再有未实现锚点");

    // 编码本身（离线）必须可用，且报文是真实投递的输入
    let request = email.encode(&alerts()).expect("SMTP 编码应成功");
    assert_eq!(request.method, "SMTP-SEND");
    assert_eq!(request.endpoint, "smtp://127.0.0.1:1");
    assert!(request.body["raw"].as_str().unwrap_or_default().contains("Subject: "));

    // 真实建连被拒 ⇒ 可重试的依赖不可用（而不是 NotImplemented，也不是"假装成功"）
    let error = email.send(&alerts()).await.expect_err("不可达 SMTP 目标必须如实报错");
    assert!(!matches!(error, DomainError::NotImplemented(_)), "{error}");
    assert!(!error.to_string().contains("TODO("), "{error}");
    assert!(error.is_degradable() || matches!(error, DomainError::Timeout(_)), "网络类失败必须可重试: {error}");
}

#[tokio::test]
pub(crate) async fn mock_mode_never_touches_the_network() {
    let server = MockServer::start().await;
    Mock::given(any()).respond_with(ResponseTemplate::new(200).set_body_string("ok")).expect(0).mount(&server).await;

    let hook = format!("{}/open-apis/bot/v2/hook/mock", server.uri());
    let mut feishu = adapter::<Feishu>(
        &[("allow_custom_host", json!(true))],
        &[("webhook_url", &hook)],
        5,
        retry_once(),
        circuit(3, 30),
        true,
    )
    .await;
    assert_eq!(feishu.mode(), AdapterMode::Mocked);
    let receipt = feishu.send(&alerts()).await.expect("Mock 发送应成功");
    assert!(receipt.mocked && receipt.origin.starts_with("mock://"));

    let mut webhook = adapter::<Webhook>(&[], &[("webhook_url", &hook)], 5, retry_once(), circuit(3, 30), true).await;
    assert!(webhook.send(&alerts()).await.expect("Mock 发送应成功").mocked);

    server.verify().await;
    assert!(requests(&server).await.is_empty(), "Mock 模式必须零网络");
}
