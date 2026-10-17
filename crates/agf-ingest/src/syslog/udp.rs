//! Syslog UDP 监听器与字节流入口（NUL/CRLF 裁剪）。

use super::*;

/// Syslog UDP 监听器（RFC5424 §6.2：一个数据报承载一条报文）。
#[derive(Debug)]
pub struct SyslogUdpListener {
    socket: UdpSocket,
}

impl SyslogUdpListener {
    /// 绑定监听地址。
    ///
    /// # Errors
    /// 地址非法或端口被占用。
    pub async fn bind(addr: &str) -> DomainResult<Self> {
        let socket = UdpSocket::bind(addr).await.map_err(|e| DomainError::DependencyUnavailable {
            dependency: "syslog-udp".to_string(),
            cause: format!("绑定 {addr} 失败: {e}"),
        })?;
        debug!(addr, "Syslog UDP 监听已启动");
        Ok(Self { socket })
    }

    /// 实际监听地址。
    ///
    /// # Errors
    /// 取本地地址失败。
    pub fn local_addr(&self) -> DomainResult<SocketAddr> {
        self.socket.local_addr().map_err(|e| DomainError::Internal(format!("读取监听地址失败: {e}")))
    }

    /// 接收一个数据报（带超时，避免测试/停机时无限阻塞）。
    ///
    /// # Errors
    /// 超时或接收失败；超长数据报被截断后仍返回（UDP 语义）。
    pub async fn recv_datagram(
        &self,
        max_message_bytes: usize,
        timeout_ms: u64,
    ) -> DomainResult<(Vec<u8>, SocketAddr)> {
        let mut buf = vec![0_u8; max_message_bytes.max(512)];
        let fut = self.socket.recv_from(&mut buf);
        let (n, peer) = tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), fut)
            .await
            .map_err(|_| DomainError::Timeout(format!("UDP 接收超时（{timeout_ms} ms）")))?
            .map_err(|e| DomainError::Internal(format!("UDP 接收失败: {e}")))?;
        buf.truncate(n);
        Ok((buf, peer))
    }
}

/// 去除 NUL 填充（部分 UDP syslog 发送端会补齐定长缓冲）。
#[must_use]
pub fn trim_nul(bytes: &[u8]) -> &[u8] {
    let end = bytes.iter().rposition(|b| *b != 0).map_or(0, |i| i + 1);
    bytes.get(..end).unwrap_or_default()
}

/// 一站式解析：字节输入 → [`SyslogMessage`]，自动去 NUL 并识别 RFC。
///
/// # Errors
/// 报文为空或两种 RFC 均解析失败。
pub fn parse_bytes(bytes: &[u8]) -> Result<SyslogMessage, SyslogParseError> {
    let text = String::from_utf8_lossy(trim_nul(bytes));
    parse_auto(text.trim_end_matches(['\r', '\n']))
}
