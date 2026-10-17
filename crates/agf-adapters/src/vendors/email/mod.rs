//! 邮件（SMTP）适配器：**真实 SMTP 投递**（`lettre` + rustls，配置齐全即真实发信）。
//!
//! | 项 | 值 |
//! |---|---|
//! | 通道 | SMTP（`smtp://<host>:<port>`，安全模式 `starttls`（默认，强制升级）/ `tls`（SMTPS 直连加密）/ `none`（明文，仅限受信内网中继））——**真实投递** |
//! | 凭据 | `smtp_password`（可选：配了 `smtp_user` 就必须有；未配 `smtp_user` 时按匿名/中继发送） |
//! | 设置 | `smtp_host`（必需）、`from`（必需）、`smtp_port`（默认 587）、`smtp_security`、`smtp_user`（配置即启用 AUTH）、`to`（收件人数组，或 `,`/`;` 分隔字符串）、`subject_prefix`、`html_template`（可选，HTML 正文模板） |
//! | 报文 | 手写 RFC 5322（CRLF 归一）：纯文本为 `text/plain; charset=utf-8`；带 HTML 时为 `multipart/alternative`（`text/plain` + `text/html`），boundary 由内容**确定性派生**（无随机源） |
//! | 投递 | [`VendorSpec::invoke_live`] 覆写为真实 SMTP 会话：`EHLO` → （可选 `STARTTLS`）→ （可选 `AUTH`）→ `MAIL FROM` / `RCPT TO` / `DATA`，报文按 [`EmailMessage::raw`] **原样投递**（`send_raw`），因此离线断言的报文 == 上线字节 |
//!
//! ## 凭据来源（**绝不硬编码、绝不进日志/错误文本**）
//!
//! SMTP 密码只有一个来源：`AdapterSettings` 的凭据表（键 `smtp_password`，由
//! [`secrecy::SecretString`] 承载，`Debug` 恒为 `[REDACTED]`），按 `crate::settings` 的既定优先级解析：
//!
//! 1. 注入的 [`crate::settings::SecretLookup`]（生产：`credentials` 表解密后的内存凭据）；
//! 2. 环境变量 `AGF_ADAPTER_EMAIL_SMTP_PASSWORD`（运维兜底，由 `EnvSecrets` 按
//!    `AGF_ADAPTER_<适配器名>_<凭据键>` 规则组装）；
//! 3. 两处都没有 → 不认证（匿名/中继发送）；若同时配置了 `smtp_user`，`init()` 直接报 `Config`（**不建连**）。
//!
//! 明文只在真实握手那一刻取出并交给 `lettre` 的 `AUTH` 命令；[`EmailMessage`] / [`SmtpProfile`]
//! 都不含密码字段，错误文本只带 SMTP 返回码、主机与端口。
//!
//! ## 企业怎么配（可直接照抄）
//!
//! 在控制台"接入管理"新增 `email` 适配器（或经 `AdapterConfig.settings` 落库），填写：
//!
//! | 设置键 | 示例 | 说明 |
//! |---|---|---|
//! | `smtp_host` | `smtp.qiye.aliyun.com` | SMTP 服务器（必需，不得含空白） |
//! | `smtp_port` | `587` | 默认 587；`smtp_security=none` 常见 25，`smtp_security=tls` 常见 465 |
//! | `smtp_security` | `starttls` | `starttls`（默认，强制 STARTTLS，服务端不支持即失败）/ `tls`（建连即 TLS）/ `none`（明文） |
//! | `smtp_user` | `alerts@corp.example` | 配置即启用认证；留空则匿名/中继发送 |
//! | `smtp_password` | （**凭据**，不写进明文设置） | 走凭据表 / `AGF_ADAPTER_EMAIL_SMTP_PASSWORD` |
//! | `from` | `agf-alert@corp.example` | 发件人（必需，须通过服务器的发信校验） |
//! | `to` | `["soc@corp.example","ciso@corp.example"]` | 收件人（数组，或 `,` / `;` 分隔字符串；为空即未配置） |
//! | `subject_prefix` | `[AIGuardFabric]` | 主题前缀（不得含换行，防邮件头注入） |
//! | `html_template` | `<h2>{{title}}</h2><p>{{summary}}</p>` | 可选；提供即发 `multipart/alternative`。占位符：`{{title}}` `{{summary}}` `{{severity}}` `{{event_type}}` `{{asset}}` `{{occurred_at}}` `{{labels}}`（替换值全部 HTML 转义） |
//!
//! 环境变量名与 `.env.example` 第 14 节「通知渠道」既有变量对齐：
//! `AGF_NOTIFY_SMTP_HOST` / `AGF_NOTIFY_SMTP_PORT` / `AGF_NOTIFY_SMTP_USER` /
//! `AGF_NOTIFY_SMTP_PASSWORD` / `AGF_NOTIFY_SMTP_FROM`；凭据解析口另有
//! `AGF_ADAPTER_EMAIL_SMTP_PASSWORD`。若走环境变量供参，建议在 `.env.example` 第 14 节补
//! `AGF_NOTIFY_SMTP_TO`、`AGF_NOTIFY_SMTP_SECURITY`、`AGF_NOTIFY_SMTP_SUBJECT_PREFIX`
//! 与 `AGF_ADAPTER_EMAIL_SMTP_PASSWORD`（本适配器不改动该文件）。
//!
//! ## 未配置时的降级行为
//!
//! | 情况 | 行为 |
//! |---|---|
//! | 未配置 `smtp_host` / `from` | 模式为 `Unconfigured`；`health_check()` 为 `Degraded`（映射 `HealthState::Unconfigured`）；`send()` 返回 `Config` 错误并列出缺项，**不建连、不发包**；事件照常落库 |
//! | 收件人为空 | `is_configured()` 为 `false`（未配置）；即使强行编码也返回 `Config` 错误，**拒绝静默丢信** |
//! | `AGF_MOCK_MODE=1` 或 `config.mock=true` | 返回确定性 Mock 回执，**绝不发起任何 SMTP 会话（零网络）** |
//! | 配置齐全但 `smtp_user` 有、`smtp_password` 无 | `init()` 返回 `Config`（**不建连**），旧配置保持不变 |
//! | 配置齐全且已实现真实投递 | `health_check()` 为 `Available`；`send()` 真实建连投递，5xx/4xx/网络错误按 `RetryConfig` 重试，认证失败（530/534/535/538）**不重试**，连续失败由熔断器开路 |
//! | `smtp_port` 越界 / `smtp_security` 非法 / `subject_prefix` 含换行 | `init()` 返回 `Config`（含邮件头注入防护），旧配置保持不变 |
//! | `from`/`to` 形态合法但不被 SMTP 接受（如带非 ASCII 本地部分） | `Validation`（**不重试**），在建立连接**之前**返回 |
//!
//! ## 错误分类（与其它适配器的 `is_degradable()` 重试口径一致）
//!
//! | SMTP 情形 | 领域错误 | 可重试 |
//! |---|---|---|
//! | 认证类 5xx（530/534/535/538） | [`DomainError::Unauthenticated`]（只带返回码与文本） | ❌ 凭据错重试无意义 |
//! | 其它 5xx（如 550 relay denied）与 4xx（421/450/451/452） | [`DomainError::DependencyUnavailable`] | ✅ 按 `RetryConfig` |
//! | 连接/网络/TLS/超时 | `DependencyUnavailable` / [`DomainError::Timeout`] | ✅ |
//! | 协议/能力协商失败（无应答码：服务端不支持 `STARTTLS` 或 `8BITMIME`、无可兼容认证机制） | `DependencyUnavailable` | ✅（重试通常不会变好，但归因于依赖侧能力问题，不掩盖为业务错误） |
//! | 地址不被 SMTP 接受 | `Validation` | ❌ |
//!
//! ## 已知限制（如实登记）
//!
//! SMTP 只有**投递方向**，因此 `push`/`pull`/`sync` 三条语义**协议上不适用**，登记为
//! `Unsupported` 并给出原因（运行时返回不可重试的 `Validation`，**不是** `NotImplemented` 占位）：
//!
//! - `push`：SMTP 没有"更新/撤回已投递邮件"的语义（重发 = 再调用一次 `send`，不属于状态回写）；
//! - `pull`/`sync`：收取邮件需 IMAP/POP3，本适配器未配置该类通道，无读取语义。
//!
//! 详见 [`crate::vendors::EMAIL_PUSH_UNSUPPORTED`] 与能力矩阵
//! （`crates/agf-adapters/CAPABILITY-MATRIX.md`）。
//!
//! TLS 信任锚是**编译内置的 webpki（Mozilla）根证书集**（`lettre` 的 `rustls-tls` 特性）：
//! 公信证书的 SMTP 服务器（Exchange Online / 阿里云邮 / 腾讯企业邮等）可直接使用；
//! 内网自签或私有 CA 签发证书的 SMTP 服务器**当前无法接入**——适配器刻意不提供
//! "跳过证书校验"的开关（那会把一次安全降级变成一行配置），需要私有 CA 时应改为可注入
//! CA 的 `TlsParameters`（落点在 [`tls_mode`]）。
//!
//! 报文头与正文以 UTF-8（8bit）投递，不生成 `=?utf-8?` 编码字：服务端需支持 `8BITMIME`
//! （RFC 6152，现代 MTA 的默认能力）；服务端未声明该能力时 `lettre` 会**明确报错而不发半成品**。

pub(crate) use std::time::Duration;

pub(crate) use agf_core::error::DomainError;
pub(crate) use agf_core::error::DomainResult;

pub(crate) use agf_core::time::Timestamp;

pub(crate) use lettre::address::Envelope;

pub(crate) use lettre::transport::smtp::authentication::Credentials;

pub(crate) use lettre::transport::smtp::client::Tls;
pub(crate) use lettre::transport::smtp::client::TlsParameters;

pub(crate) use lettre::transport::smtp::AsyncSmtpTransport;
pub(crate) use lettre::transport::smtp::Error as SmtpError;

pub(crate) use serde::Deserialize;
pub(crate) use serde::Serialize;

pub(crate) use crate::contract::AdapterCategory;
pub(crate) use crate::contract::AdapterMessage;
pub(crate) use crate::contract::AdapterMetadata;

pub(crate) use crate::settings::AdapterSettings;

pub(crate) use crate::transport::VendorRequest;

pub(crate) use crate::vendor::VendorSpec;

#[cfg(test)]
pub(crate) use crate::contract::VendorAdapter;

#[cfg(test)]
pub(crate) use crate::settings::AdapterMode;

#[cfg(test)]
pub(crate) use crate::test_support::settings_for;

#[cfg(test)]
pub(crate) use agf_core::enums::Severity;

#[cfg(test)]
pub(crate) use serde_json::json;

#[allow(unused_imports)]
pub use impl_smtp_profile::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 允许的 SMTP 安全模式。
pub const ALLOWED_SECURITY: [&str; 3] = ["starttls", "tls", "none"];

/// 认证类 SMTP 返回码（RFC 4954 及其配套：认证失败/机制不足/要求认证/要求加密后认证）。
///
/// 这些码归 [`DomainError::Unauthenticated`]——凭据或认证策略问题，**重试不会变好**。
pub const AUTH_FAILURE_CODES: [u16; 4] = [530, 534, 535, 538];

/// SMTP 安全模式（[`ALLOWED_SECURITY`] 的三态形态）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SmtpSecurity {
    /// 明文连接后强制 `STARTTLS` 升级（默认；服务端不支持即失败，**不退化为明文**）。
    StartTls,
    /// 建连即 TLS（SMTPS，通常 465）。
    Tls,
    /// 明文（仅限受信内网/本机中继）。
    None,
}

/// SMTP 连接画像（**不含密码**）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmtpProfile {
    /// 主机。
    pub host: String,
    /// 端口。
    pub port: u16,
    /// 安全模式（`starttls` / `tls` / `none`）。
    pub security: String,
    /// 用户名（可选；密码永不进入本结构）。
    pub username: Option<String>,
}

/// 邮件报文（RFC 5322 文本 + 投递画像）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailMessage {
    /// 发件人。
    pub from: String,
    /// 收件人。
    pub to: Vec<String>,
    /// 主题。
    pub subject: String,
    /// 原始报文（CRLF 分隔；**真实投递的就是这段字节**）。
    pub raw: String,
    /// HTML 替代部分（`None` 表示只发纯文本）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_html: Option<String>,
    /// SMTP 画像。
    pub smtp: SmtpProfile,
}

/// 邮件适配器标记类型。
#[derive(Debug)]
pub struct Email;

/// Mock 实现（真实传输由 [`crate::vendor::VendorAdapterImpl`] 统一接管，Mock 时由 `mock_mode` 短路）。
pub type MockEmailAdapter = crate::vendor::VendorAdapterImpl<Email>;

mod impl_email;
mod impl_smtp_profile;
#[cfg(test)]
mod tests;
