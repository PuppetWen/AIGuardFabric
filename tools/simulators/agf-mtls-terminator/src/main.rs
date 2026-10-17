//! # agf-mtls-terminator — 本地 mTLS 终结器（**仅测试/联调**）
//!
//! ## 为什么需要它
//!
//! `agf-server` 自身**不终结 TLS**（与生产部署一致：TLS/mTLS 由入口网关承担，证书身份经
//! 请求头透传给应用）。因此要在本机做"采集器 mTLS 上行"的端到端验证，就需要一个
//! **真实的 TLS 终结者**：它校验客户端证书、把证书与校验结论透传给后端，
//! 行为与 nginx 的
//! `proxy_set_header X-SSL-Client-Verify $ssl_client_verify;`
//! `proxy_set_header X-SSL-Client-Cert $ssl_client_escaped_cert;`
//! 完全一致。
//!
//! ## 与生产网关的差异（**如实标注**）
//!
//! - 只做**单跳** HTTP/1.1 转发（不做 keep-alive 池、不做 HTTP/2、不做超时分层）；
//! - 客户端证书链校验交给 rustls 的 `WebPkiClientVerifier`（信任锚 = `--ca`）；
//! - 不做限流/访问日志/请求头清洗（那是网关的活）。
//!
//! ## 用法
//!
//! ```text
//! agf-mtls-terminator --listen 127.0.0.1:8443 --upstream 127.0.0.1:8080 \
//!     --ca tools/simulators/agent-mtls-certs/ca.crt \
//!     --cert tools/simulators/agent-mtls-certs/server.crt \
//!     --key tools/simulators/agent-mtls-certs/server.key
//! ```

#![forbid(unsafe_code)]
// 本工具是**给人看的**联调模拟器：它的会话与错误摘要必须打到控制台，
// 而不是走 tracing（workspace 的 `print_stdout/print_stderr` 门禁按此显式放行）。
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::net::SocketAddr;
use std::sync::Arc;

use rustls::pki_types::CertificateDer;
use rustls::pki_types::PrivateKeyDer;
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

/// 请求头上限（防御畸形请求；单次上行信封远小于此）。
const MAX_REQUEST_BYTES: usize = 16 * 1024 * 1024;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut listen = "127.0.0.1:8443".to_string();
    let mut upstream = "127.0.0.1:8080".to_string();
    let mut ca = String::new();
    let mut cert = String::new();
    let mut key = String::new();

    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let value = args.next().unwrap_or_default();
        match flag.as_str() {
            "--listen" => listen = value,
            "--upstream" => upstream = value,
            "--ca" => ca = value,
            "--cert" => cert = value,
            "--key" => key = value,
            other => return Err(format!("未知参数 {other}（见文件头用法）").into()),
        }
    }
    if ca.is_empty() || cert.is_empty() || key.is_empty() {
        return Err("必须提供 --ca / --cert / --key（先用 tools/simulators/gen_agent_mtls_certs.py 生成）".into());
    }
    // rustls 0.23 要求**显式**选定进程级 CryptoProvider（工作区同时存在 ring / aws-lc-rs 两套特性）。
    // 显式安装 ring，避免"Could not automatically determine the process-level CryptoProvider"。
    if rustls::crypto::ring::default_provider().install_default().is_err() {
        eprintln!("警告：CryptoProvider 已被其它代码安装，沿用既有提供者");
    }

    let config = server_config(&ca, &cert, &key)?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(&listen).await?;
    println!("agf-mtls-terminator listening on {listen} -> upstream {upstream} (mTLS required)");

    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let upstream = upstream.clone();
        tokio::spawn(async move {
            if let Err(error) = handle(stream, acceptor, &upstream, peer).await {
                eprintln!("connection {peer} failed: {error}");
            }
        });
    }
}

/// 装配服务端 TLS（**要求并校验证书链**：`WebPkiClientVerifier` + `--ca` 信任锚）。
fn server_config(ca: &str, cert: &str, key: &str) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let mut roots = RootCertStore::empty();
    let ca_pem = std::fs::read(ca)?;
    let added =
        roots.add_parsable_certificates(rustls_pemfile::certs(&mut ca_pem.as_slice()).collect::<Result<Vec<_>, _>>()?);
    if added.0 == 0 {
        return Err("--ca 中没有可用证书".into());
    }
    let verifier =
        WebPkiClientVerifier::builder(Arc::new(roots)).build().map_err(|e| format!("客户端证书校验器装配失败: {e}"))?;

    let cert_pem = std::fs::read(cert)?;
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_pem.as_slice()).collect::<Result<Vec<_>, _>>()?;
    let key_pem = std::fs::read(key)?;
    let private_key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut key_pem.as_slice())?.ok_or("--key 中没有私钥")?;

    let config = ServerConfig::builder().with_client_cert_verifier(verifier).with_single_cert(certs, private_key)?;
    Ok(config)
}

async fn handle(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    upstream: &str,
    peer: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut tls = acceptor.accept(stream).await?;
    let (_, session) = tls.get_ref();
    let protocol = session.protocol_version().map(|v| format!("{v:?}")).unwrap_or_default();
    let cipher = session.negotiated_cipher_suite().map(|c| format!("{:?}", c.suite())).unwrap_or_default();
    let client_der = session
        .peer_certificates()
        .and_then(|certs| certs.first())
        .map(|cert| cert.as_ref().to_vec())
        .ok_or("客户端未出示证书（rustls 已要求）")?;
    println!("mTLS ok peer={peer} proto={protocol} cipher={cipher} client_cert={} bytes", client_der.len());

    let (head, body) = read_request(&mut tls).await?;
    let forwarded = build_forwarded_request(&head, &body, &client_der)?;
    let response = forward(upstream, forwarded).await?;
    tls.write_all(&response).await?;
    tls.flush().await?;
    let _ = tls.shutdown().await;
    Ok(())
}

/// 读到请求头结束，再按 `Content-Length` 收满请求体。
async fn read_request(
    tls: &mut tokio_rustls::server::TlsStream<TcpStream>,
) -> Result<(String, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
    let mut buffer: Vec<u8> = Vec::new();
    let mut chunk = vec![0_u8; 16 * 1024];
    let mut head_end: Option<usize> = None;
    let mut want_total: Option<usize> = None;
    loop {
        let read = tls.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > MAX_REQUEST_BYTES {
            return Err("请求超过 16 MiB 上限".into());
        }
        if head_end.is_none() {
            if let Some(position) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                let end = position + 4;
                head_end = Some(end);
                want_total = Some(end + content_length_of(&buffer[..end]));
            }
        }
        if let Some(total) = want_total {
            if buffer.len() >= total {
                break;
            }
        }
    }
    let Some(end) = head_end else { return Err("请求头不完整".into()) };
    let head = String::from_utf8_lossy(&buffer[..end]).to_string();
    Ok((head, buffer[end..].to_vec()))
}

fn content_length_of(head: &[u8]) -> usize {
    String::from_utf8_lossy(head)
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse().ok())
        .unwrap_or(0)
}

/// 重写请求：保留方法/路径与业务头，注入证书身份头，强制 `Connection: close`。
///
/// **安全要点**：先剥掉客户端自带的 `x-ssl-client-*` / `x-agf-client-cert-der`，
/// 再注入网关自己的结论——否则客户端可以伪造"网关已校验"的头部。
fn build_forwarded_request(
    head: &str,
    body: &[u8],
    client_der: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or("请求行为空")?;
    let path = request_line.split_whitespace().nth(1).unwrap_or("/").to_string();
    if !path.starts_with('/') {
        return Err(format!("请求目标非法: {path}").into());
    }
    let mut out = format!("POST {path} HTTP/1.1\r\n");
    let mut host_seen = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else { continue };
        let lower = name.trim().to_ascii_lowercase();
        // 剥掉客户端可控的身份头与连接控制头
        if lower.starts_with("x-ssl-client") || lower == "x-agf-client-cert-der" || lower == "connection" {
            continue;
        }
        if lower == "host" {
            host_seen = true;
        }
        out.push_str(&format!("{}: {}\r\n", name.trim(), value.trim()));
    }
    if !host_seen {
        out.push_str("Host: agf-server\r\n");
    }
    out.push_str("Connection: close\r\n");
    out.push_str(&format!(
        "X-SSL-Client-Verify: SUCCESS\r\nX-AGF-Client-Cert-Der: {}\r\n",
        base64_encode::encode(client_der)
    ));
    out.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(body);
    Ok(bytes)
}

/// 单跳转发（读到后端关闭为止）。
async fn forward(upstream: &str, request: Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let mut stream = TcpStream::connect(upstream).await?;
    stream.write_all(&request).await?;
    stream.flush().await?;
    let mut response = Vec::new();
    let mut chunk = vec![0_u8; 16 * 1024];
    loop {
        let read = match stream.read(&mut chunk).await {
            Ok(0) => break,
            Ok(read) => read,
            // 后端按 Connection: close 关闭；已经收到字节时不把 reset 当失败
            Err(_) if !response.is_empty() => break,
            Err(error) => return Err(error.into()),
        };
        response.extend_from_slice(&chunk[..read]);
    }
    Ok(response)
}

/// base64（只用标准字母表 + `=` 填充；不引入依赖）。
mod base64_encode {
    /// 编码为 base64 文本。
    pub(super) fn encode(input: &[u8]) -> String {
        const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
        for chunk in input.chunks(3) {
            let b0 = u32::from(chunk[0]);
            let b1 = chunk.get(1).copied().map(u32::from);
            let b2 = chunk.get(2).copied().map(u32::from);
            let triple = (b0 << 16) | (b1.unwrap_or(0) << 8) | b2.unwrap_or(0);
            out.push(TABLE[((triple >> 18) & 0x3f) as usize] as char);
            out.push(TABLE[((triple >> 12) & 0x3f) as usize] as char);
            out.push(if b1.is_some() { TABLE[((triple >> 6) & 0x3f) as usize] as char } else { '=' });
            out.push(if b2.is_some() { TABLE[(triple & 0x3f) as usize] as char } else { '=' });
        }
        out
    }
}
