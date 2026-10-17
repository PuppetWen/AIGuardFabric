//! 由 `email.rs` 拆分：`Email` 的实现（纯搬移，逻辑不变）。
use super::*;
use lettre::{AsyncTransport as _, Tokio1Executor};

impl Email {
    /// 收件人（设置 `to`，字符串数组；兼容单字符串）。
    #[must_use]
    pub fn recipients(settings: &AdapterSettings) -> Vec<String> {
        match settings.settings.get("to") {
            Some(serde_json::Value::Array(items)) => items
                .iter()
                .filter_map(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToString::to_string)
                .collect(),
            Some(serde_json::Value::String(single)) => {
                single.split([',', ';']).map(str::trim).filter(|s| !s.is_empty()).map(ToString::to_string).collect()
            }
            _ => Vec::new(),
        }
    }

    /// SMTP 画像。
    ///
    /// # Errors
    /// 端口/安全模式非法、必需设置缺失时返回 `DomainError::Config`。
    pub fn profile(settings: &AdapterSettings) -> DomainResult<SmtpProfile> {
        let host = crate::vendors::require_setting(settings, "smtp_host")?;
        if host.chars().any(char::is_whitespace) {
            return Err(DomainError::Config(format!("smtp_host 非法: {host:?}")));
        }
        let port: u16 = match settings.settings.get("smtp_port").and_then(serde_json::Value::as_u64) {
            Some(0) => return Err(DomainError::Config("smtp_port 不能为 0".to_string())),
            Some(value) => u16::try_from(value)
                .map_err(|_| DomainError::Config(format!("smtp_port 越界: {value}（允许 1..=65535）")))?,
            None => 587,
        };
        let security = settings.get_str("smtp_security").unwrap_or("starttls").to_ascii_lowercase();
        if !ALLOWED_SECURITY.contains(&security.as_str()) {
            return Err(DomainError::Config(format!("smtp_security 非法: {security:?}（允许 {ALLOWED_SECURITY:?}）")));
        }
        Ok(SmtpProfile { host, port, security, username: settings.get_str("smtp_user").map(ToString::to_string) })
    }

    /// 正文（纯文本）。
    #[must_use]
    pub fn body_text(msg: &AdapterMessage) -> String {
        msg.render_text()
    }

    /// HTML 正文（可选）：优先取载荷自带的 `body.html`（上层已渲染），否则用 `html_template` 套模板。
    #[must_use]
    pub fn body_html(msg: &AdapterMessage, settings: &AdapterSettings) -> Option<String> {
        if let Some(html) = msg.body.get("html").and_then(serde_json::Value::as_str) {
            if !html.trim().is_empty() {
                return Some(html.to_string());
            }
        }
        let template = settings.get_str("html_template")?;
        (!template.trim().is_empty()).then(|| render_html_template(template, msg))
    }

    /// 真实 SMTP 投递（**唯一网络出口**）：`EHLO` → 可选 `STARTTLS` → 可选 `AUTH` → `MAIL/RCPT/DATA`。
    ///
    /// 报文按 [`EmailMessage::raw`] 原样投递，因此离线编码断言与上线字节一致。
    ///
    /// # Errors
    /// - `smtp_user` 已配置但凭据 `smtp_password` 缺失：`Config`（**不建连**）；
    /// - TLS 参数非法：`Config`；地址不被 SMTP 接受：`Validation`；
    /// - 会话失败：`Timeout` / `DependencyUnavailable` / `Unauthenticated`（见 [`classify_smtp_failure`]）。
    pub(crate) async fn deliver(message: &EmailMessage, settings: &AdapterSettings) -> DomainResult<Option<String>> {
        let password = settings.secret_raw("smtp_password").filter(|p| !p.trim().is_empty());
        let credentials = match (message.smtp.username.as_deref(), password) {
            (Some(user), Some(password)) => Some(Credentials::new(user.to_string(), password.to_string())),
            (Some(_), None) => {
                return Err(DomainError::Config(format!(
                    "适配器 email 配置了 smtp_user 但缺少凭据 smtp_password（凭据请走凭据表或 {}）",
                    crate::settings::env_key_for("AGF_ADAPTER", Self::NAME, "smtp_password")
                )));
            }
            (None, _) => None,
        };
        let mut builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(message.smtp.host.clone())
            .port(message.smtp.port)
            .tls(tls_mode(&message.smtp)?)
            .timeout(Some(Duration::from_secs(settings.timeout_secs)));
        if let Some(credentials) = credentials {
            builder = builder.credentials(credentials);
        }
        let transport = builder.build();
        let envelope = envelope(message)?;
        let response = transport
            .send_raw(&envelope, message.raw.as_bytes())
            .await
            .map_err(|e| map_smtp_error(e, &message.smtp.endpoint()))?;
        let code = u16::from(response.code());
        let remote_id = response.first_line().map_or_else(|| code.to_string(), |line| format!("{code} {line}"));
        Ok(Some(remote_id))
    }
}

// 覆写 `invoke_live` 必须用 `#[async_trait]`（默认实现走 HTTP，SMTP 是独立会话协议）
#[async_trait::async_trait]
impl VendorSpec for Email {
    const NAME: &'static str = "email";
    const REAL_TRANSPORT: bool = true;
    const REQUIRED_SETTINGS: &'static [&'static str] = &["smtp_host", "from"];

    fn metadata() -> AdapterMetadata {
        AdapterMetadata::new("email", "邮件（SMTP）", "标准协议", AdapterCategory::Notification)
            .with_secrets(&[], &["smtp_password"])
            .with_capabilities(crate::vendors::notify_capabilities())
            .with_semantics(crate::contract::SemanticProfile::send_only(
                crate::vendors::EMAIL_PUSH_UNSUPPORTED,
                crate::vendors::EMAIL_READ_UNSUPPORTED,
                crate::vendors::EMAIL_READ_UNSUPPORTED,
            ))
            .with_degradation(
                "未配置 smtp_host / from 时不下发任何邮件（事件照常落库并在控制台可见）；\
                 收件人为空时明确报配置错误而不是静默丢信；smtp_user 已配置但缺 smtp_password 时 init 即报配置错误（不建连）；\
                 未配置 smtp_user 时按匿名中继发送",
            )
            .with_mock_location("crates/agf-adapters/src/vendors/email.rs#MockEmailAdapter")
            .with_real_transport(true)
    }

    fn validate_settings(settings: &AdapterSettings) -> DomainResult<()> {
        // 只在值存在时校验形态；缺失由 REQUIRED_SETTINGS 判定为未配置（不是错误）
        if settings.get_str("from").is_some() {
            validate_address(crate::vendors::require_setting(settings, "from")?.as_str(), "from")?;
        }
        if settings.get_str("smtp_host").is_some() {
            let profile = Self::profile(settings)?;
            crate::settings::validate_endpoint(&profile.endpoint())?;
        }
        // 认证半配置是"存在但非法"：配了用户名却没凭据，与其匿名试探（大概率被 530 拒绝），不如 fail fast
        if settings.get_str("smtp_user").is_some() && !settings.has_secret("smtp_password") {
            return Err(DomainError::Config(format!(
                "适配器 email 配置了 smtp_user 但缺少凭据 smtp_password（凭据请走凭据表或 {}）",
                crate::settings::env_key_for("AGF_ADAPTER", Self::NAME, "smtp_password")
            )));
        }
        for recipient in Self::recipients(settings) {
            validate_address(&recipient, "to")?;
        }
        if let Some(prefix) = settings.get_str("subject_prefix") {
            if prefix.contains(['\r', '\n']) {
                return Err(DomainError::Config("subject_prefix 不得包含换行（防邮件头注入）".to_string()));
            }
        }
        Ok(())
    }

    fn is_configured(settings: &AdapterSettings) -> bool {
        !Self::recipients(settings).is_empty()
    }

    fn encode(msg: &AdapterMessage, settings: &AdapterSettings) -> DomainResult<VendorRequest> {
        let profile = Self::profile(settings)?;
        let from = crate::vendors::require_setting(settings, "from")?;
        let recipients = Self::recipients(settings);
        let prefix = settings.get_str("subject_prefix").unwrap_or("[AIGuardFabric]");
        let subject = format!("{prefix} 【{}】{}", msg.severity.as_str(), msg.title);
        let html = Self::body_html(msg, settings);
        let message = EmailMessage::build_with_html(
            &from,
            &recipients,
            &subject,
            &Self::body_text(msg),
            html.as_deref(),
            profile,
            msg.occurred_at,
        )?;
        let endpoint = message.smtp.endpoint();
        // 报文体只含画像与原始报文；密码不出现在任何字段中
        let body = serde_json::to_value(&message).unwrap_or(serde_json::Value::Null);
        Ok(VendorRequest::channel("SMTP-SEND", endpoint, body))
    }

    /// 真实投递（覆写默认 HTTP 实现：SMTP 是独立会话协议，非 HTTP）。
    ///
    /// # Errors
    /// 见 [`Email::deliver`]。
    async fn invoke_live(req: &VendorRequest, settings: &AdapterSettings) -> DomainResult<Option<String>> {
        let message: EmailMessage = serde_json::from_value(req.body.clone())
            .map_err(|e| DomainError::Validation(format!("email：SMTP 请求体不是合法报文编码产物: {e}")))?;
        Self::deliver(&message, settings).await
    }
}
