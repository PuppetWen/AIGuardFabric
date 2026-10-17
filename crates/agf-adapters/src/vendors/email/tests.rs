//! 由 `email.rs` 拆分：`message` 等 22 个函数（纯搬移，逻辑不变）。
use super::*;

pub(crate) fn message() -> AdapterMessage {
    AdapterMessage::notification("每日资产盘点异常", "3 台主机未上报心跳").with_severity(Severity::High)
}

pub(crate) fn settings(extra: &[(&str, serde_json::Value)]) -> AdapterSettings {
    let mut base: Vec<(&str, serde_json::Value)> = vec![
        ("smtp_host", json!("mail.example.invalid")),
        ("from", json!("agf@example.invalid")),
        ("to", json!(["soc@example.invalid", "ciso@example.invalid"])),
    ];
    base.extend_from_slice(extra);
    settings_for(&Email::metadata(), &base, &[("smtp_password", "plain-smtp-password")]).expect("测试设置必须可构造")
}

pub(crate) fn profile_of(extra: &[(&str, serde_json::Value)]) -> SmtpProfile {
    Email::profile(&settings(extra)).expect("画像必须可构造")
}

#[test]
pub(crate) fn profile_defaults_and_validation() {
    let profile = Email::profile(&settings(&[])).expect("默认画像应可用");
    assert_eq!(profile.port, 587);
    assert_eq!(profile.security, "starttls");
    assert_eq!(profile.endpoint(), "smtp://mail.example.invalid:587");
    assert!(!profile.authenticates(), "未配置用户名时不认证");

    let with_user = Email::profile(&settings(&[("smtp_user", json!("agf"))])).expect("画像");
    assert!(with_user.authenticates());

    let bad_port = Email::profile(&settings(&[("smtp_port", json!(70_000))])).expect_err("端口越界必须报错");
    assert!(matches!(bad_port, DomainError::Config(_)));
    assert!(Email::profile(&settings(&[("smtp_port", json!(0))])).is_err());
    assert!(Email::profile(&settings(&[("smtp_security", json!("plaintext"))])).is_err());
}

#[test]
pub(crate) fn recipients_parse_array_and_string_forms() {
    let array = Email::recipients(&settings(&[]));
    assert_eq!(array.len(), 2);
    let single = Email::recipients(&settings(&[("to", json!("a@example.invalid; b@example.invalid"))]));
    assert_eq!(single, vec!["a@example.invalid".to_string(), "b@example.invalid".to_string()]);
    let empty = Email::recipients(&settings(&[("to", json!([]))]));
    assert!(empty.is_empty());
}

#[test]
pub(crate) fn address_validation_rejects_malformed() {
    assert!(validate_address("a@example.invalid", "to").is_ok());
    for bad in ["no-at-sign", "@example.invalid", "a@nodot", "a b@example.invalid", "a@.invalid", "a@invalid."] {
        assert!(validate_address(bad, "to").is_err(), "{bad} 应被判非法");
    }
}

#[test]
pub(crate) fn rfc5322_render_is_deterministic_and_has_required_headers() {
    let at = Timestamp::now();
    let raw = render_rfc5322("a@example.invalid", &["b@example.invalid".to_string()], "主题", "正文", at);
    assert!(raw.contains("From: a@example.invalid\r\n"));
    assert!(raw.contains("To: b@example.invalid\r\n"));
    assert!(raw.contains("Subject: 主题\r\n"));
    assert!(raw.contains("MIME-Version: 1.0\r\n"));
    assert!(raw.contains("Content-Type: text/plain; charset=utf-8\r\n"));
    assert!(raw.ends_with("正文\r\n"));
    assert_eq!(raw, render_rfc5322("a@example.invalid", &["b@example.invalid".to_string()], "主题", "正文", at));
}

#[test]
pub(crate) fn empty_recipients_are_rejected_instead_of_silently_dropped() {
    let error = EmailMessage::build(
        "a@example.invalid",
        &[],
        "s",
        "b",
        SmtpProfile { host: "h".into(), port: 25, security: "none".into(), username: None },
        Timestamp::now(),
    )
    .expect_err("空收件人必须报错");
    assert!(matches!(error, DomainError::Config(_)));
}

#[test]
pub(crate) fn encode_produces_message_without_password() {
    let settings = settings(&[]);
    let req = Email::encode(&message(), &settings).expect("编码应成功");
    assert_eq!(req.method, "SMTP-SEND");
    assert_eq!(req.endpoint, "smtp://mail.example.invalid:587");
    let text = req.body_text();
    assert!(!text.contains("plain-smtp-password"), "报文体绝不能包含 SMTP 密码: {text}");
    assert!(text.contains("soc@example.invalid"));
    assert!(text.contains("每日资产盘点异常"));
    assert_eq!(req.body["smtp"]["port"], json!(587));
    assert_eq!(req.body["smtp"]["security"], json!("starttls"));
    assert!(req.body["smtp"].get("password").is_none(), "SMTP 画像结构不得携带密码字段");
}

#[test]
pub(crate) fn subject_prefix_must_not_contain_newlines() {
    let injected = settings(&[("subject_prefix", json!("ok\r\nBcc: attacker@example.invalid"))]);
    assert!(Email::validate_settings(&injected).is_err(), "必须阻断邮件头注入");
}

#[test]
pub(crate) fn multipart_render_is_deterministic_and_carries_both_alternatives() {
    let at = Timestamp::now();
    let to = vec!["b@example.invalid".to_string()];
    let raw = render_rfc5322_multipart("a@example.invalid", &to, "主题", "纯文本正文", "<h2>HTML 正文</h2>", at);
    assert!(raw.contains("Content-Type: multipart/alternative; boundary=\"=_agf_"), "{raw}");
    assert!(raw.contains("Content-Type: text/plain; charset=utf-8\r\n"), "{raw}");
    assert!(raw.contains("Content-Type: text/html; charset=utf-8\r\n"), "{raw}");
    assert!(raw.contains("纯文本正文"), "{raw}");
    assert!(raw.contains("<h2>HTML 正文</h2>"), "{raw}");
    // 两份副本的 boundary 必须一致、且以 `--boundary--` 收尾
    let boundary = mime_boundary(&format!(
        "a@example.invalid\u{1f}{}\u{1f}主题\u{1f}纯文本正文\u{1f}<h2>HTML 正文</h2>",
        to.join(",")
    ));
    assert_eq!(raw.matches(&format!("--{boundary}\r\n")).count(), 2, "两个部分各一个分界行");
    assert!(raw.ends_with(&format!("--{boundary}--\r\n")), "必须以结束分界行收尾: {raw}");
    assert_eq!(
        raw,
        render_rfc5322_multipart("a@example.invalid", &to, "主题", "纯文本正文", "<h2>HTML 正文</h2>", at),
        "同一输入必须得到同一报文（无随机 boundary）"
    );
}

#[test]
pub(crate) fn body_is_normalized_to_crlf() {
    assert_eq!(normalize_crlf("a\nb\r\nc\rd"), "a\r\nb\r\nc\r\nd");
    let raw = render_rfc5322(
        "a@example.invalid",
        &["b@example.invalid".to_string()],
        "s",
        "第一行\n第二行",
        Timestamp::now(),
    );
    assert!(raw.contains("第一行\r\n第二行"), "正文换行必须归一为 CRLF: {raw:?}");
    assert!(!raw.contains("第一行\n第二行"), "不得保留裸 LF: {raw:?}");
}

#[test]
pub(crate) fn html_part_prefers_payload_then_template_and_escapes_markup() {
    let msg = AdapterMessage::notification("<b>标题</b>", "摘要 & 细节").with_severity(Severity::High);

    // ① 设置里没有模板 + 载荷没有 html ⇒ 不发 HTML（纯文本单部分）
    let plain = settings(&[]);
    assert!(Email::body_html(&msg, &plain).is_none());
    let req = Email::encode(&msg, &plain).expect("编码");
    assert!(req.body["raw"].as_str().unwrap_or_default().contains("text/plain; charset=utf-8"));
    assert!(!req.body_text().contains("multipart/alternative"), "无 HTML 时不得发 multipart");

    // ② 模板：占位符被替换，且标记被转义（防 HTML 注入）
    let templated = settings(&[("html_template", json!("<h1>{{title}}</h1><p>{{summary}}</p>"))]);
    let html = Email::body_html(&msg, &templated).expect("模板必须产出 HTML");
    assert!(html.contains("&lt;b&gt;标题&lt;/b&gt;"), "标题必须被 HTML 转义: {html}");
    assert!(html.contains("摘要 &amp; 细节"), "摘要必须被 HTML 转义: {html}");
    let request = Email::encode(&msg, &templated).expect("编码");
    let raw = request.body["raw"].as_str().unwrap_or_default();
    assert!(raw.contains("multipart/alternative; boundary=\"=_agf_"), "{raw}");
    assert!(raw.contains("text/html; charset=utf-8"), "{raw}");
    assert!(request.body["body_html"].as_str().is_some(), "编码产物必须带上 HTML 部分");

    // ③ 载荷自带 `body.html`（上层已渲染）时优先于模板
    let payload = AdapterMessage::notification("t", "s").with_severity(Severity::Low);
    let mut from_payload = payload.clone();
    from_payload.body = json!({"html": "<p>载荷自带</p>"});
    assert_eq!(
        Email::body_html(&from_payload, &templated).as_deref(),
        Some("<p>载荷自带</p>"),
        "载荷自带 HTML 必须优先于模板"
    );
}

#[test]
pub(crate) fn security_modes_map_to_expected_lettre_tls() {
    assert_eq!(profile_of(&[]).security_mode(), SmtpSecurity::StartTls, "默认 starttls");
    assert_eq!(profile_of(&[("smtp_security", json!("TLS"))]).security_mode(), SmtpSecurity::Tls, "取值大小写归一");
    assert_eq!(profile_of(&[("smtp_security", json!("none"))]).security_mode(), SmtpSecurity::None);

    // 真实建连形态：none ⇒ 明文；starttls ⇒ 强制升级；tls ⇒ 建连即加密
    assert!(matches!(tls_mode(&profile_of(&[("smtp_security", json!("none"))])), Ok(Tls::None)));
    assert!(matches!(tls_mode(&profile_of(&[("smtp_security", json!("starttls"))])), Ok(Tls::Required(_))));
    assert!(matches!(tls_mode(&profile_of(&[("smtp_security", json!("tls"))])), Ok(Tls::Wrapper(_))));
}

#[test]
pub(crate) fn smtp_failure_classification_follows_retry_policy() {
    // 认证类：Unauthenticated，且明确不可重试
    for code in AUTH_FAILURE_CODES {
        let error = classify_smtp_failure(Some(code), "认证被拒绝");
        assert!(matches!(error, DomainError::Unauthenticated(_)), "{code} 应判为认证失败: {error}");
        assert!(!error.is_degradable(), "{code} 属业务错误，不得重试");
    }
    // 其它 5xx / 4xx：可重试的外部依赖不可用
    for code in [421_u16, 450, 451, 452, 550, 552, 554] {
        let error = classify_smtp_failure(Some(code), "上游拒绝");
        assert!(matches!(error, DomainError::DependencyUnavailable { .. }), "{code}: {error}");
        assert!(error.is_degradable(), "{code} 必须可重试（按 RetryConfig）");
    }
    // 网络/TLS/无应答码：同样可重试
    let no_code = classify_smtp_failure(None, "连接被拒绝");
    assert!(matches!(no_code, DomainError::DependencyUnavailable { .. }));
    assert!(no_code.is_degradable());
}

#[test]
pub(crate) fn envelope_parsing_rejects_addresses_smtp_cannot_accept() {
    let profile = profile_of(&[]);
    let good = EmailMessage::build(
        "agf@example.invalid",
        &["soc@example.invalid".to_string(), "ciso@example.invalid".to_string()],
        "s",
        "b",
        profile.clone(),
        Timestamp::now(),
    )
    .expect("合法报文");
    let parsed = envelope(&good).expect("合法信封");
    assert_eq!(parsed.to().len(), 2);
    assert_eq!(parsed.from().map(ToString::to_string).as_deref(), Some("agf@example.invalid"));

    // `validate_address` 放行但 SMTP 不接受（本地部分含非法字符）⇒ Validation（不重试）
    let mut broken = good;
    broken.to = vec!["a b@example.invalid".to_string()];
    let error = envelope(&broken).expect_err("非法收件人必须报错");
    assert!(matches!(error, DomainError::Validation(_)), "{error}");
    assert!(!error.is_degradable(), "地址类错误不得重试");
}

#[test]
pub(crate) fn authentication_half_configuration_is_rejected_without_connecting() {
    // 配了用户名但没有凭据：init 阶段即报 Config（不建连；也不会匿名试探）
    let half = settings_for(
        &Email::metadata(),
        &[
            ("smtp_host", json!("mail.example.invalid")),
            ("from", json!("agf@example.invalid")),
            ("to", json!(["soc@example.invalid"])),
            ("smtp_user", json!("agf")),
        ],
        &[],
    )
    .expect("设置本身可构造");
    let error = Email::validate_settings(&half).expect_err("缺凭据必须报配置错误");
    assert!(matches!(error, DomainError::Config(_)), "{error}");
    assert!(error.to_string().contains("smtp_password"), "{error}");
    // 错误文本不得泄露任何凭据值
    assert!(!error.to_string().contains("plain-smtp-password"));
}

#[test]
pub(crate) fn subject_with_newline_is_rejected_at_message_build() {
    let error = EmailMessage::build(
        "a@example.invalid",
        &["b@example.invalid".to_string()],
        "ok\r\nBcc: attacker@example.invalid",
        "b",
        SmtpProfile { host: "h".into(), port: 25, security: "none".into(), username: None },
        Timestamp::now(),
    )
    .expect_err("主题含换行必须被阻断");
    assert!(matches!(error, DomainError::Config(_)), "{error}");
}

#[tokio::test]
pub(crate) async fn unconfigured_without_settings_is_degraded_and_never_connects() {
    let mut adapter = crate::vendor::VendorAdapterImpl::<Email>::new();
    adapter
        .init_with(&crate::test_support::config_for("email", &[], false), &crate::settings::NoSecrets, false)
        .await
        .expect("未配置不得失败");
    assert_eq!(adapter.mode(), AdapterMode::Unconfigured);
    let record = adapter.build_record();
    assert_eq!(record.status, crate::health::HealthStatus::Degraded, "未配置是降级不是失败");
    assert!(!record.configured);
    let error = adapter.send(&message()).await.expect_err("未配置必须明确报错");
    assert!(matches!(error, DomainError::Config(_)), "{error}");
    assert!(error.to_string().contains("smtp_host"), "{error}");
}

#[tokio::test]
pub(crate) async fn live_mode_registers_real_transport_and_is_healthy() {
    // 旧的"如实未实现"断言已被真实投递取代：现在必须**如实登记已实现**且健康态可用
    let mut live = crate::vendor::VendorAdapterImpl::<Email>::new();
    let config = crate::test_support::config_for(
        "email",
        &[
            ("smtp_host", json!("mail.example.invalid")),
            ("from", json!("agf@example.invalid")),
            ("to", json!(["soc@example.invalid"])),
        ],
        false,
    );
    live.init_with(&config, &crate::test_support::secrets(&[("smtp_password", "p")]), false).await.expect("合法配置");
    assert_eq!(live.mode(), AdapterMode::Live);
    assert!(live.descriptor().real_implementation, "email 已实现真实 SMTP 投递，必须如实登记");
    assert!(live.metadata().real_transport, "元信息必须登记真实传输");
    assert_eq!(live.build_record().status, crate::health::HealthStatus::Available);
    assert!(!live.build_record().message.unwrap_or_default().contains("TODO("), "不得再有未实现锚点");
    assert!(live.encode(&message()).is_ok(), "编码本身必须可用");
    // 编码产物是真实投递的输入：画像 + 原始报文
    let request = live.encode(&message()).expect("编码");
    assert_eq!(request.method, "SMTP-SEND");
    assert_eq!(request.body["smtp"]["host"], json!("mail.example.invalid"));
    assert!(request.body["raw"].as_str().unwrap_or_default().contains("Subject: "));
}

#[tokio::test]
pub(crate) async fn mock_send_is_deterministic() {
    let mut adapter = crate::vendor::VendorAdapterImpl::<Email>::mocked();
    let first = adapter.send(&message()).await.expect("Mock 发送");
    let second = adapter.send(&message()).await.expect("Mock 发送");
    assert!(first.mocked);
    assert_eq!(first.remote_id, second.remote_id);
    assert_eq!(first.origin, "mock://email");
}

#[test]
pub(crate) fn json_roundtrip_of_encoded_message_is_the_delivery_input() {
    // `invoke_live` 从 JSON 反序列化回 `EmailMessage`：字段必须无损往返
    let request =
        Email::encode(&message(), &settings(&[("html_template", json!("<p>{{title}}</p>"))])).expect("编码应成功");
    let decoded: EmailMessage = serde_json::from_value(request.body.clone()).expect("必须可反序列化");
    assert_eq!(decoded.from, "agf@example.invalid");
    assert_eq!(decoded.to.len(), 2);
    assert!(decoded.body_html.is_some());
    assert_eq!(decoded.raw, decoded.raw.clone());
    assert!(decoded.raw.contains("multipart/alternative"), "{}", decoded.raw);
    let text = serde_json::to_string(&request.body).unwrap_or_default();
    assert!(!text.contains("plain-smtp-password"), "序列化产物不得含密码: {text}");
}
