//! 由 `email_smtp.rs` 拆分：`impl_SmtpBehavior`/`impl_SmtpSession` 等 19 项（纯搬移，逻辑不变）。
use super::*;

impl Default for SmtpBehavior {
    fn default() -> Self {
        Self { advertise_auth: false, auth_code: 235, mail_code: 250 }
    }
}

impl SmtpSession {
    /// DATA 正文原文（含 CRLF，可直接断言换行合规）。
    pub(crate) fn data_text(&self) -> String {
        self.data.concat()
    }

    /// DATA 正文行（去掉行尾 CRLF，便于人读打印）。
    pub(crate) fn data_lines(&self) -> Vec<String> {
        self.data.iter().map(|line| line.trim_end_matches(['\r', '\n']).to_string()).collect()
    }
}

/// 起一个假 SMTP 服务器，返回监听端口与会话记录表。
pub(crate) async fn fake_smtp(behavior: SmtpBehavior) -> (u16, Sessions) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("绑定本地 SMTP 监听");
    let port = listener.local_addr().expect("本地地址").port();
    let sessions: Sessions = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&sessions);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { break };
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                let mut session = SmtpSession::default();
                if let Err(e) = serve(stream, behavior, &mut session).await {
                    session.io_error = Some(e.to_string());
                }
                log.lock().expect("会话记录锁").push(session);
            });
        }
    });
    (port, sessions)
}

/// 读一行（**保留 CRLF 原文**；EOF 返回 `None`）。
pub(crate) async fn read_line(
    reader: &mut BufReader<OwnedReadHalf>,
    buf: &mut Vec<u8>,
) -> std::io::Result<Option<String>> {
    buf.clear();
    if reader.read_until(b'\n', buf).await? == 0 {
        return Ok(None);
    }
    Ok(Some(String::from_utf8_lossy(buf).to_string()))
}

/// 单次会话的状态机（最小可用 SMTP：够真客户端跑完一轮）。
pub(crate) async fn serve(stream: TcpStream, behavior: SmtpBehavior, session: &mut SmtpSession) -> std::io::Result<()> {
    let (half, mut writer) = stream.into_split();
    let mut reader = BufReader::new(half);
    let mut buf = Vec::new();

    let greeting = "220 fake.example.invalid ESMTP AGF-TEST\r\n";
    writer.write_all(greeting.as_bytes()).await?;
    session.greeting = greeting.trim_end().to_string();

    loop {
        let Some(raw) = read_line(&mut reader, &mut buf).await? else { break };
        let line = raw.trim_end_matches(['\r', '\n']).to_string();
        let upper = line.to_ascii_uppercase();
        if upper.starts_with("EHLO ") || upper.starts_with("HELO ") {
            session.ehlo = line;
            let mut caps = vec![
                "250-fake.example.invalid".to_string(),
                "250-PIPELINING".to_string(),
                // 报文含非 ASCII（中文告警）：lettre 要求服务端声明 8BITMIME（RFC 6152）
                "250-8BITMIME".to_string(),
            ];
            if behavior.advertise_auth {
                caps.push("250-AUTH PLAIN LOGIN".to_string());
            }
            caps.push("250 SIZE 10485760".to_string());
            let banner = format!("{}\r\n", caps.join("\r\n"));
            writer.write_all(banner.as_bytes()).await?;
            session.capabilities = caps.join(" | ");
        } else if upper.starts_with("AUTH ") {
            session.auth_lines.push(line.clone());
            let mechanism = line.split_whitespace().nth(1).unwrap_or_default().to_ascii_uppercase();
            if behavior.auth_code != 235 {
                let failure = format!("{} 5.7.8 Authentication credentials invalid\r\n", behavior.auth_code);
                writer.write_all(failure.as_bytes()).await?;
                continue;
            }
            if mechanism == "PLAIN" {
                let payload = match line.split_whitespace().nth(2) {
                    Some(inline) => inline.to_string(),
                    None => {
                        writer.write_all(b"334 \r\n").await?;
                        let challenge = read_line(&mut reader, &mut buf).await?.unwrap_or_default();
                        session.auth_lines.push(challenge.clone());
                        challenge
                    }
                };
                session.auth_plain_decoded = base64::engine::general_purpose::STANDARD
                    .decode(payload.trim())
                    .ok()
                    .and_then(|decoded| String::from_utf8(decoded).ok());
            } else {
                // LOGIN：两轮挑战（本适配器默认选 PLAIN，这里仅保证协议完整）
                writer.write_all(b"334 VXNlcm5hbWU6\r\n").await?;
                let user = read_line(&mut reader, &mut buf).await?.unwrap_or_default();
                session.auth_lines.push(user);
                writer.write_all(b"334 UGFzc3dvcmQ6\r\n").await?;
                let password = read_line(&mut reader, &mut buf).await?.unwrap_or_default();
                session.auth_lines.push(password);
            }
            writer.write_all(b"235 2.7.0 Authentication successful\r\n").await?;
        } else if upper.starts_with("MAIL FROM") {
            session.mail_from.push(line);
            let reply = if behavior.mail_code == 250 {
                "250 2.1.0 Ok\r\n".to_string()
            } else {
                format!("{} 5.7.1 Relay access denied (AGF-TEST)\r\n", behavior.mail_code)
            };
            writer.write_all(reply.as_bytes()).await?;
        } else if upper.starts_with("RCPT TO") {
            session.rcpt_to.push(line);
            writer.write_all(b"250 2.1.5 Ok\r\n").await?;
        } else if upper == "DATA" {
            writer.write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n").await?;
            loop {
                let Some(body) = read_line(&mut reader, &mut buf).await? else { break };
                if body.trim_end_matches(['\r', '\n']) == "." {
                    break;
                }
                session.data.push(body);
            }
            writer.write_all(b"250 2.0.0 Ok: queued as AGF-TEST-0001\r\n").await?;
        } else if upper.starts_with("QUIT") {
            writer.write_all(b"221 2.0.0 Bye\r\n").await?;
            break;
        } else {
            writer.write_all(b"250 2.0.0 Ok\r\n").await?;
        }
    }
    Ok(())
}

/// 等待至少 `expected` 个会话落账（服务器在客户端断开后才写记录，存在毫秒级竞态）。
pub(crate) async fn wait_sessions(sessions: &Sessions, expected: usize) -> Vec<SmtpSession> {
    for _ in 0..250 {
        let snapshot = { sessions.lock().expect("会话记录锁").clone() };
        if snapshot.len() >= expected {
            return snapshot;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let snapshot = { sessions.lock().expect("会话记录锁").clone() };
    assert!(snapshot.len() >= expected, "等待 {expected} 个 SMTP 会话超时，实际 {} 个", snapshot.len());
    snapshot
}

/// 静置一段时间的会话数（Mock/未配置用例断言"仍然零连接"）。
pub(crate) async fn count_after_grace(sessions: &Sessions) -> usize {
    tokio::time::sleep(Duration::from_millis(300)).await;
    sessions.lock().expect("会话记录锁").len()
}

// ---------------------------------------------------------------------------
// 构造辅助（与 `http_vendors.rs` 口径一致）
// ---------------------------------------------------------------------------

/// 单次尝试（不重试）。
pub(crate) fn retry_once() -> RetryConfig {
    RetryConfig { max_attempts: 1, initial_backoff_ms: 1, multiplier: 1.0, max_backoff_ms: 2, jitter: false }
}

/// 指定尝试次数的重试配置（退避压到 1ms）。
pub(crate) fn retry(max_attempts: u32) -> RetryConfig {
    RetryConfig { max_attempts, initial_backoff_ms: 1, multiplier: 1.0, max_backoff_ms: 2, jitter: false }
}

/// 熔断配置。
pub(crate) fn circuit(failure_threshold: u32, open_secs: i64) -> CircuitBreakerConfig {
    CircuitBreakerConfig { enabled: true, failure_threshold, open_secs, half_open_probes: 1 }
}

/// 内存凭据。
pub(crate) fn secrets(pairs: &[(&str, &str)]) -> StaticSecrets {
    let mut lookup = StaticSecrets::new();
    for (key, value) in pairs {
        lookup = lookup.with(key, value);
    }
    lookup
}

/// SMTP 适配器配置（明文 `none` + 本机端口）。
pub(crate) fn smtp_config(port: u16, settings: &[(&str, Value)], retry_cfg: RetryConfig, mock: bool) -> AdapterConfig {
    let now = Timestamp::now();
    let mut map: BTreeMap<String, Value> = BTreeMap::new();
    for (key, value) in [
        ("smtp_host", json!("127.0.0.1")),
        ("smtp_port", json!(port)),
        ("smtp_security", json!("none")),
        ("from", json!("agf@example.invalid")),
        ("to", json!(["soc@example.invalid", "ciso@example.invalid"])),
    ] {
        map.insert(key.to_string(), value);
    }
    for (key, value) in settings {
        map.insert((*key).to_string(), value.clone());
    }
    AdapterConfig {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        adapter: Email::NAME.to_string(),
        display_name: "email-test".to_string(),
        enabled: true,
        settings: map,
        secret_refs: BTreeMap::new(),
        circuit_breaker: circuit(3, 30),
        retry: retry_cfg,
        timeout_secs: 5,
        mock,
        is_default: true,
        created_at: now,
        updated_at: now,
    }
}

/// 初始化后的适配器。
pub(crate) async fn email_adapter(
    port: u16,
    settings: &[(&str, Value)],
    secret_pairs: &[(&str, &str)],
    retry_cfg: RetryConfig,
    mock: bool,
) -> VendorAdapterImpl<Email> {
    let config = smtp_config(port, settings, retry_cfg, mock);
    let mut adapter = VendorAdapterImpl::<Email>::new();
    adapter.init_with(&config, &secrets(secret_pairs), false).await.expect("合法 SMTP 配置必须可初始化");
    adapter
}

/// 告警载荷（含中文，覆盖 8BITMIME 路径）。
pub(crate) fn alerts() -> AdapterMessage {
    AdapterMessage::notification("磁盘水位告警", "节点 node-1 根分区使用率 92%").with_severity(Severity::Critical)
}

// ---------------------------------------------------------------------------
// 端到端往返
// ---------------------------------------------------------------------------

#[tokio::test]
pub(crate) async fn plain_roundtrip_delivers_rfc5322_data_over_a_real_smtp_session() {
    let (port, sessions) = fake_smtp(SmtpBehavior::default()).await;
    let mut email = email_adapter(port, &[], &[], retry_once(), false).await;

    assert_eq!(email.mode(), AdapterMode::Live);
    let receipt = email.send(&alerts()).await.expect("真实 SMTP 投递必须成功");
    assert!(receipt.accepted);
    assert!(!receipt.mocked, "回执不得是 Mock——必须真的走了 SMTP 会话");
    assert_eq!(receipt.origin, format!("smtp://127.0.0.1:{port}"));
    assert!(receipt.remote_id.unwrap_or_default().contains("250"), "远端回执应带服务器接受应答");

    let sessions = wait_sessions(&sessions, 1).await;
    assert_eq!(sessions.len(), 1, "恰好一次 SMTP 会话");
    let session = &sessions[0];
    assert_eq!(session.greeting, "220 fake.example.invalid ESMTP AGF-TEST", "必须先收到 220 问候");
    assert!(session.ehlo.starts_with("EHLO "), "客户端必须发 EHLO: {:?}", session.ehlo);
    assert!(session.capabilities.contains("250-8BITMIME"), "服务器声明的能力: {}", session.capabilities);
    assert_eq!(session.mail_from.len(), 1, "一次会话一个 MAIL FROM");
    assert!(session.mail_from[0].contains("MAIL FROM:<agf@example.invalid>"), "{:?}", session.mail_from);
    assert_eq!(session.rcpt_to.len(), 2, "两个收件人 ⇒ 两条 RCPT TO");
    assert!(session.rcpt_to[0].contains("RCPT TO:<soc@example.invalid>"), "{:?}", session.rcpt_to);
    assert!(session.rcpt_to[1].contains("RCPT TO:<ciso@example.invalid>"), "{:?}", session.rcpt_to);
    assert!(session.io_error.is_none(), "会话不得中断: {:?}", session.io_error);

    let data = session.data_text();
    // ---- 服务器收到的 DATA 逐项断言（证明"真的发出了 SMTP 会话，不是 Mock"）----
    assert!(data.contains("From: agf@example.invalid\r\n"), "DATA 必须含 CRLF 结尾的 From: {data}");
    assert!(data.contains("To: soc@example.invalid, ciso@example.invalid\r\n"), "DATA 必须含收件人：{data}");
    assert!(data.contains("Subject: [AIGuardFabric] 【critical】磁盘水位告警\r\n"), "DATA 必须含主题：{data}");
    assert!(data.contains("MIME-Version: 1.0\r\n"), "DATA 必须含 MIME 版本：{data}");
    assert!(data.contains("Content-Type: text/plain; charset=utf-8\r\n"), "DATA 必须含 MIME 类型：{data}");
    assert!(data.contains("节点 node-1 根分区使用率 92%"), "DATA 必须含正文明细：{data}");
    assert!(data.contains("event=notify.alert"), "DATA 必须含事件类型：{data}");

    // 证据输出（`cargo test -- --nocapture` 可见）：服务器视角的完整会话
    println!("=== 假 SMTP 服务器收到的会话（email 适配器真实投递证据）===");
    println!("S: {}", session.greeting);
    println!("C: {}", session.ehlo);
    println!("S: {}", session.capabilities);
    for line in &session.mail_from {
        println!("C: {line}");
    }
    for line in &session.rcpt_to {
        println!("C: {line}");
    }
    println!("C: DATA");
    for line in session.data_lines() {
        println!("  | {line}");
    }
    println!("=== DATA 共 {} 行：From/To/Subject/正文/CRLF 断言全部通过 ===", session.data.len());
}

#[tokio::test]
pub(crate) async fn html_template_roundtrip_delivers_multipart_alternative() {
    let (port, sessions) = fake_smtp(SmtpBehavior::default()).await;
    let mut email = email_adapter(
        port,
        &[("html_template", json!("<h2>{{title}}</h2><p>{{summary}}</p><p>{{severity}}/{{event_type}}</p>"))],
        &[],
        retry_once(),
        false,
    )
    .await;

    let receipt = email.send(&alerts()).await.expect("multipart 投递必须成功");
    assert!(!receipt.mocked);

    let sessions = wait_sessions(&sessions, 1).await;
    let session = &sessions[0];
    let data = session.data_text();
    assert!(data.contains("Content-Type: multipart/alternative; boundary=\"=_agf_"), "{data}");
    assert!(data.contains("Content-Type: text/plain; charset=utf-8\r\n"), "{data}");
    assert!(data.contains("Content-Type: text/html; charset=utf-8\r\n"), "{data}");
    assert!(data.contains("<h2>磁盘水位告警</h2>"), "HTML 部分必须套上模板: {data}");
    assert!(data.contains("<p>节点 node-1 根分区使用率 92%</p>"), "{data}");
    assert!(data.contains("critical/notify.alert"), "{data}");
    assert!(data.contains("节点 node-1 根分区使用率 92%"), "纯文本降级副本也必须在: {data}");

    // MIME 报文完整性：必须以结束分界行 `--<boundary>--` 收尾
    let closing = session.data_lines().into_iter().rev().find(|line| !line.is_empty()).unwrap_or_default();
    assert!(closing.starts_with("--=_agf_") && closing.ends_with("--"), "缺少结束分界行: {closing:?}");
}

#[tokio::test]
pub(crate) async fn authenticated_roundtrip_sends_auth_plain_and_keeps_password_out_of_data() {
    let (port, sessions) = fake_smtp(SmtpBehavior { advertise_auth: true, ..SmtpBehavior::default() }).await;
    let password = "smtp-secret-9f8e7d6c";
    let mut email = email_adapter(
        port,
        &[("smtp_user", json!("agf-alerts@example.invalid"))],
        &[("smtp_password", password)],
        retry_once(),
        false,
    )
    .await;

    let receipt = email.send(&alerts()).await.expect("带认证的真实投递必须成功");
    assert!(!receipt.mocked);

    let sessions = wait_sessions(&sessions, 1).await;
    let session = &sessions[0];
    assert!(session.capabilities.contains("250-AUTH PLAIN LOGIN"), "必须声明 AUTH 能力: {}", session.capabilities);
    let expected = format!("\u{0}agf-alerts@example.invalid\u{0}{password}");
    assert_eq!(
        session.auth_plain_decoded.as_deref(),
        Some(expected.as_str()),
        "服务器解码出的 AUTH PLAIN 载荷必须与 settings/凭据表逐字节一致: {:?}",
        session.auth_lines
    );
    // 凭据只在 AUTH 阶段出现，绝不进入报文
    let data = session.data_text();
    assert!(!data.contains(password), "DATA 绝不能包含 SMTP 密码: {data}");
    assert!(!data.contains("agf-alerts@example.invalid"), "用户名同样不应进入报文: {data}");
    assert!(data.contains("Subject: [AIGuardFabric] 【critical】磁盘水位告警\r\n"), "{data}");
    println!("=== 认证会话证据：AUTH 载荷解码 == {expected:?}；DATA 中不含密码 ===");
}

#[tokio::test]
pub(crate) async fn smtp_5xx_is_retried_and_classified_as_dependency_unavailable() {
    let (port, sessions) = fake_smtp(SmtpBehavior { mail_code: 550, ..SmtpBehavior::default() }).await;
    // max_attempts=3 ⇒ 5xx 属"可重试的外部依赖不可用"，必须重试到底（3 次全新会话）
    let mut email = email_adapter(port, &[], &[], retry(3), false).await;

    let error = email.send(&alerts()).await.expect_err("550 必须如实报错，绝不假装成功");
    assert!(matches!(error, DomainError::DependencyUnavailable { .. }), "{error}");
    assert!(error.is_degradable(), "5xx 必须可重试: {error}");
    assert!(error.to_string().contains("550"), "错误文本应带 SMTP 返回码: {error}");

    let observed = wait_sessions(&sessions, 3).await;
    assert_eq!(count_after_grace(&sessions).await, 3, "max_attempts=3 ⇒ 恰好 3 次会话（不多不少）");
    for session in &observed {
        assert!(session.mail_from[0].contains("MAIL FROM:<agf@example.invalid>"), "每次都重发了信封");
        assert!(session.data.is_empty(), "被 550 拒绝时不得进入 DATA 阶段");
    }
    assert_eq!(email.build_record().consecutive_failures, 1, "一次 send（含重试）记一次连续失败");
}

#[tokio::test]
pub(crate) async fn smtp_auth_failure_is_unauthenticated_and_not_retried() {
    let (port, sessions) =
        fake_smtp(SmtpBehavior { advertise_auth: true, auth_code: 535, ..SmtpBehavior::default() }).await;
    // 即便给了 3 次重试额度，认证失败也**只能尝试一次**（凭据错重试无意义）
    let mut email = email_adapter(
        port,
        &[("smtp_user", json!("agf-alerts@example.invalid"))],
        &[("smtp_password", "wrong-password")],
        retry(3),
        false,
    )
    .await;

    let error = email.send(&alerts()).await.expect_err("535 必须报认证失败");
    assert!(matches!(error, DomainError::Unauthenticated(_)), "{error}");
    assert!(!error.is_degradable(), "认证失败不得重试: {error}");
    assert!(error.to_string().contains("535"), "错误文本应带返回码: {error}");
    assert!(!error.to_string().contains("wrong-password"), "错误文本绝不能含凭据: {error}");
    assert!(AUTH_FAILURE_CODES.contains(&535));

    let observed = wait_sessions(&sessions, 1).await;
    assert_eq!(count_after_grace(&sessions).await, 1, "认证失败只尝试一次，3 次重试额度也不生效");
    assert!(observed[0].data.is_empty(), "认证未通过不得进入 DATA 阶段");
    println!("=== 535 认证失败证据：错误分类 = {error} ===");
}
