//! Syslog 接入：RFC3164 / RFC5424 解析 + TCP / UDP 监听（§4.5 协议接入）。
//!
//! ## 覆盖范围
//!
//! | 能力 | 状态 |
//! |---|---|
//! | RFC5424（PRI / VERSION / TIMESTAMP / HOSTNAME / APP-NAME / PROCID / MSGID / STRUCTURED-DATA / MSG） | 已实现 |
//! | RFC3164（PRI / TIMESTAMP 无年份 / HOSTNAME / TAG[PID]: CONTENT） | 已实现 |
//! | RFC3164 带年份 / ISO8601 时间戳（部分设备变体） | 已实现（自动识别） |
//! | TCP 分帧：octet-counting 与 non-transparent framing | 已实现（[`SyslogFraming`]） |
//! | UDP 报文接收 | 已实现（[`SyslogUdpListener`]） |
//! | TCP 连接**持续收帧**（不按每连接帧数上限截断） | 已实现（[`FrameReader`] / [`SyslogConnection`]） |
//! | TLS（RFC5425，TLS over TCP 6514） | 已实现（[`SyslogTlsListener`]，证书由调用方注入） |
//!
//! 解析失败一律返回 [`SyslogParseError`]，**不 panic**：畸形报文是最常见的现实输入
//! （设备断电截断、MTU 分片、非 syslog 文本误投 514 端口）。

use std::net::SocketAddr;
use std::time::Duration;

use agf_core::enums::Severity;
use agf_core::error::{DomainError, DomainResult};
use agf_core::time::Timestamp;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use chrono::{Datelike, NaiveDateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};
use tokio_rustls::server::TlsStream;
use tracing::{debug, warn};

mod frame_reader;
mod framing;
mod listener;
mod message;
mod parse;
mod tls_stream;
mod udp;

#[cfg(test)]
mod tests;

pub use frame_reader::*;
pub use framing::*;
pub use listener::*;
pub use message::*;
pub use parse::*;
pub use tls_stream::*;
pub use udp::*;
