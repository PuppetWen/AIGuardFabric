#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used, clippy::print_stdout)]
//! 集成测试：email 适配器的**真实 SMTP 会话往返**（本机假 SMTP 服务器，零外网）。
//!
//! 与 `http_vendors.rs` 的分工：那边覆盖 HTTP 厂商的真实往返；这边用 `tokio::net::TcpListener`
//! 起一个最小 SMTP 服务端（`220` 问候 → `EHLO` 多行能力 → 可选 `AUTH` → `MAIL FROM`/`RCPT TO`/`DATA`
//! → `250 queued`），断言**客户端真的完成了一次 SMTP 会话**，并逐字节检查服务器收到的 DATA
//! 含 `From` / `To` / `Subject` 与正文（DATA 行保留 CRLF 原文，因此同时证明换行合规）。
//!
//! 关键结论：
//!
//! 1. **不是 Mock 的旁证**：`receipt.mocked == false`，且假服务器确实收到了会话（Mock 用例则断言零连接）；
//! 2. **凭据来源可证**：认证用例把服务器收到的 `AUTH PLAIN` 载荷解码，逐字节比对
//!    `\0<user>\0<password>`——证明密码来自 `AdapterSettings` 的凭据表，且**没有出现在 DATA 里**；
//! 3. **错误分类可证**：550 → 可重试的 `DependencyUnavailable`（按 `RetryConfig` 重试到底）；
//!    535 → 不可重试的 `Unauthenticated`（只尝试一次）；服务端不支持 STARTTLS 时**拒绝明文降级**。

pub(crate) use std::collections::BTreeMap;

pub(crate) use std::sync::Arc;
pub(crate) use std::sync::Mutex;

pub(crate) use std::time::Duration;

pub(crate) use agf_adapters::contract::VendorAdapter;

pub(crate) use agf_adapters::settings::StaticSecrets;

pub(crate) use agf_adapters::vendor::VendorAdapterImpl;
pub(crate) use agf_adapters::vendor::VendorSpec;

pub(crate) use agf_adapters::vendors::email::AUTH_FAILURE_CODES;
pub(crate) use agf_adapters::vendors::email::Email;
pub(crate) use agf_adapters::vendors::email::SmtpSecurity;

pub(crate) use agf_adapters::AdapterMessage;
pub(crate) use agf_adapters::AdapterMode;

pub(crate) use agf_core::adapter::AdapterConfig;
pub(crate) use agf_core::adapter::CircuitBreakerConfig;
pub(crate) use agf_core::adapter::RetryConfig;

pub(crate) use agf_core::enums::Severity;

pub(crate) use agf_core::error::DomainError;

pub(crate) use agf_core::ids::Id;
pub(crate) use agf_core::ids::TenantId;

pub(crate) use agf_core::time::Timestamp;

use base64::Engine as _;

pub(crate) use serde_json::Value;
pub(crate) use serde_json::json;

pub(crate) use tokio::io::AsyncBufReadExt;
pub(crate) use tokio::io::AsyncWriteExt;
pub(crate) use tokio::io::BufReader;

pub(crate) use tokio::net::tcp::OwnedReadHalf;

pub(crate) use tokio::net::TcpListener;
pub(crate) use tokio::net::TcpStream;

#[allow(unused_imports)]
pub(crate) use impl_smtp_behavior::*;
#[allow(unused_imports)]
pub(crate) use mock_mode_opens_no_smtp_session_at_all::*;

// ---------------------------------------------------------------------------
// 最小假 SMTP 服务器
// ---------------------------------------------------------------------------

/// 假服务器应答策略。
#[derive(Debug, Clone, Copy)]
struct SmtpBehavior {
    /// `EHLO` 是否声明 `AUTH PLAIN LOGIN`（客户端配了 `smtp_user` 时才需要）。
    advertise_auth: bool,
    /// `AUTH` 的应答码（235 成功；535 认证失败）。
    auth_code: u16,
    /// `MAIL FROM` 的应答码（550 用于验证 5xx 可重试）。
    mail_code: u16,
}

/// 一次 SMTP 会话的观测记录（服务器视角）。
#[derive(Debug, Clone, Default)]
struct SmtpSession {
    /// 服务器发出的 `220` 问候。
    greeting: String,
    /// 客户端发来的 `EHLO` 行。
    ehlo: String,
    /// 服务器声明的能力行（多行应答的原文）。
    capabilities: String,
    /// `AUTH` 命令行与挑战应答行。
    auth_lines: Vec<String>,
    /// `AUTH PLAIN` 载荷解码后的明文（**仅测试内存**，用于证明凭据流向）。
    auth_plain_decoded: Option<String>,
    /// `MAIL FROM` 命令行。
    mail_from: Vec<String>,
    /// `RCPT TO` 命令行。
    rcpt_to: Vec<String>,
    /// DATA 阶段的正文行（**保留 CRLF 原文**）。
    data: Vec<String>,
    /// 会话中途的 I/O 错误（客户端提前断开时记录）。
    io_error: Option<String>,
}

/// 会话记录表。
type Sessions = Arc<Mutex<Vec<SmtpSession>>>;

mod impl_smtp_behavior;
mod mock_mode_opens_no_smtp_session_at_all;
