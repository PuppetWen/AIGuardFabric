//! 由 `email.rs` 拆分：`impl_SmtpProfile`/`impl_EmailMessage` 等 14 项（纯搬移，逻辑不变）。
use super::*;
use lettre::Address;

impl SmtpProfile {
    /// 是否需要认证（有用户名即需要）。
    #[must_use]
    pub const fn authenticates(&self) -> bool {
        self.username.is_some()
    }

    /// 安全模式枚举（[`Email::profile`] 已保证取值合法，非法值只会出现在手改结构体上）。
    #[must_use]
    pub fn security_mode(&self) -> SmtpSecurity {
        match self.security.as_str() {
            "none" => SmtpSecurity::None,
            "tls" => SmtpSecurity::Tls,
            _ => SmtpSecurity::StartTls,
        }
    }

    /// endpoint 形态（真实传输层据此建连；密码在握手时另行注入）。
    #[must_use]
    pub fn endpoint(&self) -> String {
        format!("smtp://{}:{}", self.host, self.port)
    }
}

impl EmailMessage {
    /// 构造纯文本报文。
    ///
    /// # Errors
    /// 收件人为空、发件人/收件人地址非法时返回 `DomainError::Config`。
    pub fn build(
        from: &str,
        to: &[String],
        subject: &str,
        body: &str,
        smtp: SmtpProfile,
        at: Timestamp,
    ) -> DomainResult<Self> {
        Self::build_with_html(from, to, subject, body, None, smtp, at)
    }

    /// 构造报文；`body_html` 非空时产出 `multipart/alternative`（纯文本 + HTML 双副本）。
    ///
    /// # Errors
    /// 收件人为空、发件人/收件人地址非法时返回 `DomainError::Config`。
    pub fn build_with_html(
        from: &str,
        to: &[String],
        subject: &str,
        body: &str,
        body_html: Option<&str>,
        smtp: SmtpProfile,
        at: Timestamp,
    ) -> DomainResult<Self> {
        if to.is_empty() {
            return Err(DomainError::Config("邮件收件人为空：拒绝静默丢信".to_string()));
        }
        // 邮件头注入防护：主题（含 subject_prefix）与地址都不得含换行
        if subject.contains(['\r', '\n']) {
            return Err(DomainError::Config("邮件主题不得包含换行（防邮件头注入）".to_string()));
        }
        validate_address(from, "from")?;
        for recipient in to {
            validate_address(recipient, "to")?;
        }
        let html = body_html.filter(|html| !html.trim().is_empty());
        let raw = match html {
            Some(html) => render_rfc5322_multipart(from, to, subject, body, html, at),
            None => render_rfc5322(from, to, subject, body, at),
        };
        Ok(Self {
            from: from.to_string(),
            to: to.to_vec(),
            subject: subject.to_string(),
            raw,
            body_html: html.map(ToString::to_string),
            smtp,
        })
    }
}

/// 校验邮件地址（保守规则：本地部分非空、域名含 `.` 且无空白）。
///
/// # Errors
/// 地址形态非法时返回 `DomainError::Config`。
pub fn validate_address(address: &str, field: &str) -> DomainResult<()> {
    let trimmed = address.trim();
    let Some((local, domain)) = trimmed.split_once('@') else {
        return Err(DomainError::Config(format!("{field} 非法邮件地址（缺少 @）: {trimmed:?}")));
    };
    if local.is_empty()
        || domain.is_empty()
        || !domain.contains('.')
        || trimmed.chars().any(char::is_whitespace)
        || domain.starts_with('.')
        || domain.ends_with('.')
    {
        return Err(DomainError::Config(format!("{field} 非法邮件地址: {trimmed:?}")));
    }
    Ok(())
}

/// 正文换行归一为 CRLF（RFC 5322 要求；避免裸 LF 在严格 MTA 上被改写或截断）。
#[must_use]
pub fn normalize_crlf(body: &str) -> String {
    let mut out = String::with_capacity(body.len() + 16);
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push_str("\r\n");
            }
            '\n' => out.push_str("\r\n"),
            _ => out.push(c),
        }
    }
    out
}

/// 渲染 RFC 5322 纯文本报文（确定性：时间取事件发生时间，不含随机 boundary）。
#[must_use]
pub fn render_rfc5322(from: &str, to: &[String], subject: &str, body: &str, at: Timestamp) -> String {
    let body = normalize_crlf(body);
    let mut out = String::with_capacity(body.len() + 256);
    out.push_str(&format!("From: {from}\r\n"));
    out.push_str(&format!("To: {}\r\n", to.join(", ")));
    out.push_str(&format!("Subject: {subject}\r\n"));
    out.push_str(&format!("Date: {}\r\n", at.to_rfc3339()));
    out.push_str("MIME-Version: 1.0\r\n");
    out.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    out.push_str("Content-Transfer-Encoding: 8bit\r\n");
    out.push_str("\r\n");
    out.push_str(&body);
    out.push_str("\r\n");
    out
}

/// 确定性 MIME boundary（由内容派生，**不含随机源**，因此同一事件重放得到同一报文）。
#[must_use]
pub fn mime_boundary(seed: &str) -> String {
    format!("=_agf_{}", crate::transport::deterministic_token("email-mime", seed))
}

/// 渲染 RFC 5322 `multipart/alternative` 报文（纯文本 + HTML 两份等价副本）。
///
/// 邮件客户端优先渲染 HTML 部分，纯文本部分作为降级/无障碍副本。
#[must_use]
pub fn render_rfc5322_multipart(
    from: &str,
    to: &[String],
    subject: &str,
    body_text: &str,
    body_html: &str,
    at: Timestamp,
) -> String {
    let boundary =
        mime_boundary(&format!("{from}\u{1f}{}\u{1f}{subject}\u{1f}{body_text}\u{1f}{body_html}", to.join(",")));
    let text = normalize_crlf(body_text);
    let html = normalize_crlf(body_html);
    let mut out = String::with_capacity(text.len() + html.len() + 512);
    out.push_str(&format!("From: {from}\r\n"));
    out.push_str(&format!("To: {}\r\n", to.join(", ")));
    out.push_str(&format!("Subject: {subject}\r\n"));
    out.push_str(&format!("Date: {}\r\n", at.to_rfc3339()));
    out.push_str("MIME-Version: 1.0\r\n");
    out.push_str(&format!("Content-Type: multipart/alternative; boundary=\"{boundary}\"\r\n"));
    out.push_str("\r\n");
    out.push_str(&format!("--{boundary}\r\n"));
    out.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    out.push_str("Content-Transfer-Encoding: 8bit\r\n");
    out.push_str("\r\n");
    out.push_str(&text);
    out.push_str("\r\n");
    out.push_str(&format!("--{boundary}\r\n"));
    out.push_str("Content-Type: text/html; charset=utf-8\r\n");
    out.push_str("Content-Transfer-Encoding: 8bit\r\n");
    out.push_str("\r\n");
    out.push_str(&html);
    out.push_str("\r\n");
    out.push_str(&format!("--{boundary}--\r\n"));
    out
}

/// HTML 转义（防告警内容里的标记/脚本注入邮件客户端）。
#[must_use]
pub fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 16);
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// 用模板渲染 HTML 正文（占位符见模块文档；替换值一律 HTML 转义）。
#[must_use]
pub fn render_html_template(template: &str, msg: &AdapterMessage) -> String {
    let labels: Vec<String> =
        msg.labels.iter().map(|(k, v)| format!("{}={}", escape_html(k), escape_html(v))).collect();
    let mut out = template.to_string();
    for (token, value) in [
        ("{{title}}", escape_html(&msg.title)),
        ("{{summary}}", escape_html(&msg.summary).replace('\n', "<br>")),
        ("{{severity}}", escape_html(msg.severity.as_str())),
        ("{{event_type}}", escape_html(&msg.event_type)),
        ("{{asset}}", escape_html(msg.asset.as_deref().unwrap_or_default())),
        ("{{occurred_at}}", escape_html(&msg.occurred_at.to_rfc3339())),
        ("{{labels}}", labels.join(" ")),
    ] {
        out = out.replace(token, &value);
    }
    out
}

/// SMTP 返回码 → 领域错误（纯函数，离线可覆盖全矩阵）。
///
/// 分类与 [`DomainError::is_degradable`]（`invoke_with_policy` 的重试判据）刻意对齐：
/// 只有认证类返回码**不可重试**，其余 4xx/5xx 都按"外部依赖不可用"重试。
#[must_use]
pub fn classify_smtp_failure(code: Option<u16>, detail: &str) -> DomainError {
    match code {
        Some(code) if AUTH_FAILURE_CODES.contains(&code) => DomainError::Unauthenticated(format!(
            "SMTP 认证失败（{code}）：{detail}；请核对 smtp_user 与凭据 smtp_password（凭据值不会出现在日志/错误文本中）"
        )),
        Some(code) => DomainError::DependencyUnavailable {
            dependency: "email".to_string(),
            cause: format!("SMTP 上游返回 {code}：{detail}"),
        },
        None => DomainError::DependencyUnavailable {
            dependency: "email".to_string(),
            cause: format!("SMTP 会话失败（无应答码）：{detail}"),
        },
    }
}

/// 安全模式 → `lettre` 的 TLS 形态（纯函数；`none` 为明文）。
///
/// # Errors
/// 主机名无法用于 TLS 参数构造（rustls 拒绝）时返回 `DomainError::Config`，**不建连**。
pub(crate) fn tls_mode(profile: &SmtpProfile) -> DomainResult<Tls> {
    let params = || {
        TlsParameters::new_rustls(profile.host.clone())
            .map_err(|e| DomainError::Config(format!("SMTP TLS 参数非法（{}）: {e}", profile.host)))
    };
    match profile.security_mode() {
        SmtpSecurity::None => Ok(Tls::None),
        SmtpSecurity::StartTls => Ok(Tls::Required(params()?)),
        SmtpSecurity::Tls => Ok(Tls::Wrapper(params()?)),
    }
}

/// 解析 SMTP 信封（`From` + 全部 `Rcpt`）；地址不被 SMTP 接受即 `Validation`（**不重试、不建连**）。
///
/// # Errors
/// 地址不被 `lettre` 接受时返回 `DomainError::Validation`。
pub(crate) fn envelope(message: &EmailMessage) -> DomainResult<Envelope> {
    let from = parse_address(&message.from, "from")?;
    let mut recipients = Vec::with_capacity(message.to.len());
    for recipient in &message.to {
        recipients.push(parse_address(recipient, "to")?);
    }
    Envelope::new(Some(from), recipients)
        .map_err(|e| DomainError::Validation(format!("SMTP 信封非法（{}）: {e}", message.smtp.endpoint())))
}

/// 单个地址 → SMTP 地址（错误文本只带字段名与地址本身，不含任何凭据）。
pub(crate) fn parse_address(address: &str, field: &str) -> DomainResult<Address> {
    address
        .trim()
        .parse::<Address>()
        .map_err(|e| DomainError::Validation(format!("{field} 地址不被 SMTP 接受: {address:?}（{e}）")))
}

/// 底层 SMTP 错误 → 领域错误（超时单列，其余按返回码分类）。
pub(crate) fn map_smtp_error(error: SmtpError, target: &str) -> DomainError {
    let detail = format!("{target}: {error}");
    if error.is_timeout() {
        return DomainError::Timeout(format!("SMTP 会话超时（{detail}）"));
    }
    classify_smtp_failure(error.status().map(u16::from), &detail)
}
