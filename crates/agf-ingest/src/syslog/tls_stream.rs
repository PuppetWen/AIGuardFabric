//! TLS 流适配（半关闭/FIN 处理）与 PEM 证书/私钥解析（`AGF_SYSLOG_TLS_CERT/KEY`）。

use super::*;

/// 把"对端 FIN（半关闭）"**推迟一轮**再报给 rustls 的 TCP 包装。
///
/// ## 为什么必需（实测缺陷）
///
/// rustls 0.23 在"对端关闭 TCP 但没有发 `close_notify`"时会让 `read_tls` 返回
/// `io::ErrorKind::UnexpectedEof`；而 `tokio-rustls` 的 `poll_fill_buf` 一旦 `read_io`
/// 出错就**立刻**把错误抛给调用方 —— 哪怕它的解密缓冲里还压着刚解密好的明文：
///
/// ```text
/// while !self.eof && self.session.wants_read() {
///     match self.read_io(cx) { Poll::Ready(Err(err)) => return Poll::Ready(Err(err)), ... }
/// }
/// match self.session.reader().into_first_chunk() { ... }   // ← 到不了这里
/// ```
///
/// 后果：客户端"发完最后一批帧就断开"时**整批帧被丢弃**（`tools/simulators/syslog_tls.py send`
/// 实测 7 帧全部丢失）。本包装把 FIN 延迟一轮：第一次探测到 FIN 返回 `Pending` 并唤醒自己，
/// 让 rustls 有机会把已解密的明文交出来；下一次 poll 才如实返回 EOF。
#[derive(Debug)]
pub(super) struct FinHidingStream {
    inner: TcpStream,
    /// 已经探测到对端 FIN（下一轮如实报 EOF）。
    fin_seen: bool,
}

impl FinHidingStream {
    /// 包装一条 TCP 连接。
    pub(super) const fn new(inner: TcpStream) -> Self {
        Self { inner, fin_seen: false }
    }
}

impl AsyncRead for FinHidingStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.fin_seen {
            // 明文已在上一轮交给 rustls，这里如实返回 EOF（ReadBuf 未被填充 = EOF）
            return std::task::Poll::Ready(Ok(()));
        }
        let before = buf.filled().len();
        match std::pin::Pin::new(&mut this.inner).poll_read(cx, buf) {
            std::task::Poll::Ready(Ok(())) if buf.filled().len() == before => {
                this.fin_seen = true;
                // 唤醒自己：下一轮（新的 poll）才把 EOF 交给 rustls，
                // 本轮 rustls 先把已解密的明文返回给上层。
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            }
            other => other,
        }
    }
}

impl AsyncWrite for FinHidingStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Syslog TLS 连接流：把 rustls 的 `UnexpectedEof` 归一为**干净 EOF**。
///
/// 配合 [`FinHidingStream`]：所有**已解密**的明文都会先被交出来，之后才可能出现
/// "对端没发 `close_notify` 就关闭"的 `UnexpectedEof` —— 那时缓冲区已空，
/// 把错误当 EOF 处理既正确又不会丢数据（也让"读取失败"告警只留给真正的故障）。
#[derive(Debug)]
pub struct TlsFrameStream {
    inner: TlsStream<FinHidingStream>,
}

impl TlsFrameStream {
    /// 组装（`accept_connection` 内部使用）。
    pub(super) const fn new(inner: TlsStream<FinHidingStream>) -> Self {
        Self { inner }
    }
}

impl AsyncRead for TlsFrameStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match std::pin::Pin::new(&mut self.get_mut().inner).poll_read(cx, buf) {
            std::task::Poll::Ready(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                std::task::Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl AsyncWrite for TlsFrameStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// 提取 PEM 中指定 label 的全部 base64 块并解码为 DER。
fn pem_blocks(text: &str, label: &str) -> Vec<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(&begin) {
        let after = rest.get(start + begin.len()..).unwrap_or_default();
        let Some(stop) = after.find(&end) else { break };
        let body: String = after.get(..stop).unwrap_or_default().chars().filter(|c| !c.is_whitespace()).collect();
        if let Ok(der) = B64.decode(body.as_bytes()) {
            out.push(der);
        }
        rest = after.get(stop + end.len()..).unwrap_or_default();
    }
    out
}

/// PEM → 证书链。
///
/// # Errors
/// PEM 不是 UTF-8，或没有任何 `CERTIFICATE` 块。
pub fn parse_certificates(pem: &[u8]) -> DomainResult<Vec<CertificateDer<'static>>> {
    let text = std::str::from_utf8(pem).map_err(|e| DomainError::Config(format!("证书 PEM 不是合法 UTF-8: {e}")))?;
    let blocks = pem_blocks(text, "CERTIFICATE");
    if blocks.is_empty() {
        return Err(DomainError::Config("证书 PEM 中未找到 -----BEGIN CERTIFICATE----- 块".to_string()));
    }
    Ok(blocks.into_iter().map(CertificateDer::from).collect())
}

/// PEM → 私钥（依次接受 PKCS#8 / PKCS#1 / SEC1）。
///
/// # Errors
/// PEM 不是 UTF-8，或没有任何受支持的私钥块。
pub fn parse_private_key(pem: &[u8]) -> DomainResult<PrivateKeyDer<'static>> {
    let text = std::str::from_utf8(pem).map_err(|e| DomainError::Config(format!("私钥 PEM 不是合法 UTF-8: {e}")))?;
    if let Some(der) = pem_blocks(text, "PRIVATE KEY").into_iter().next() {
        return Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der)));
    }
    if let Some(der) = pem_blocks(text, "RSA PRIVATE KEY").into_iter().next() {
        return Ok(PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(der)));
    }
    if let Some(der) = pem_blocks(text, "EC PRIVATE KEY").into_iter().next() {
        return Ok(PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(der)));
    }
    Err(DomainError::Config("私钥 PEM 中未找到 PRIVATE KEY / RSA PRIVATE KEY / EC PRIVATE KEY 块".to_string()))
}
