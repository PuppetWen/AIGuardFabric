//! `ReqwestTransport` 的 TLS 行为端到端证明（模拟器实测缺口的回归）。
//!
//! ## 背景（`tools/simulators/README.md` 第 7 节第 2 条）
//!
//! `tools/simulators/fake_aliyun_api.py` 用自签证书提供 HTTPS 假 OpenAPI，
//! 而 `ReqwestTransport` 走 rustls 默认校验链 ⇒ `CERTIFICATE_VERIFY_FAILED`，
//! Rust 侧真实 RPC 路径**打不到本机模拟器**。
//!
//! ## 本测试证明什么
//!
//! 1. **默认拒绝自签**（`ReqwestTransport::new`）：请求必然失败，且原因是证书校验；
//! 2. **放开之后可连**（`with_tls_options(.., Some(ca_pem), ..)`，且 `AGF_ENV=dev`
//!    或 `AGF_ALIYUN_ALLOW_INSECURE_TLS=1`）：同一台自签服务端返回 200 且响应体被正确解析；
//! 3. 不应期：非 dev 环境下 `ca_pem` 被忽略 ⇒ 依旧拒绝（`tls_policy()` 为 `verify-chain`）。
//!
//! 第 2 条需要"放开"生效，因此：
//!
//! ```powershell
//! # 默认运行：第 1、3 条断言 + 打印"第 2 条未启用"的说明
//! cargo test -p agf-alicloud --test tls_selfsigned -- --nocapture
//! # 显式 dev 开关：额外跑通"放开后可连"
//! $env:AGF_ENV='dev'; cargo test -p agf-alicloud --test tls_selfsigned -- --nocapture
//! ```
//!
//! 证书在测试内用 `rcgen` 现场生成（**不落盘、不入库任何私钥**）。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::print_stdout)]

use std::collections::BTreeMap;
use std::sync::Arc;

use agf_alicloud::http::{ReqwestTransport, RpcRequest, SignStyle, TlsPolicy, tls_override_allowed};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

/// 现场生成的自签证书 + 私钥（PEM）。
struct SelfSigned {
    /// 证书 PEM（既当服务端证书，也当客户端信任锚）。
    cert_pem: String,
    /// 私钥（PKCS#8 DER）。
    key_der: Vec<u8>,
    /// 服务端证书 DER（构造 rustls ServerConfig 用）。
    cert_der: Vec<u8>,
}

fn self_signed() -> SelfSigned {
    // 注意：**不能**把服务端证书设成 `IsCa::Ca` —— rustls/webpki 会以
    // `CaUsedAsEndEntity` 拒绝"CA 证书当服务端证书"。自签 EE 证书本身即可作为信任锚
    // （与 rcgen + rustls 的官方测试同口径）。
    let mut params = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string(), "localhost".to_string()])
        .expect("构造证书参数失败");
    params.is_ca = rcgen::IsCa::NoCa;
    params.distinguished_name.push(rcgen::DnType::CommonName, "agf-alicloud-tls-test");
    let key = rcgen::KeyPair::generate().expect("生成密钥对失败");
    let cert = params.self_signed(&key).expect("自签失败");
    SelfSigned { cert_pem: cert.pem(), key_der: key.serialize_der(), cert_der: cert.der().to_vec() }
}

/// 起一个**只服务一次**的 HTTPS 响应端：读完请求头就回 200 + JSON。
async fn spawn_tls_server(material: &SelfSigned) -> std::net::SocketAddr {
    // 显式指定 ring provider：工作区同时启用了 ring 与 aws-lc-rs，
    // `ServerConfig::builder()` 在"没有进程默认 provider"时会 panic（rustls crypto/mod.rs）。
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("TLS 协议版本配置失败")
        .with_no_client_auth()
        .with_single_cert(
            vec![tokio_rustls::rustls::pki_types::CertificateDer::from(material.cert_der.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(material.key_der.clone())),
        )
        .expect("TLS 服务端配置失败");
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("绑定失败");
    let addr = listener.local_addr().expect("取本地地址失败");
    tokio::spawn(async move {
        loop {
            let Ok((stream, _peer)) = listener.accept().await else { break };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else { return };
                let mut buf = vec![0_u8; 4_096];
                let _ = tls.read(&mut buf).await;
                let body = r#"{"RequestId":"SIM-TLS","Code":"200","Success":true}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = tls.write_all(response.as_bytes()).await;
                let _ = tls.flush().await;
                let _ = tls.shutdown().await;
            });
        }
    });
    addr
}

fn request(addr: std::net::SocketAddr) -> RpcRequest {
    RpcRequest {
        method: "GET".to_string(),
        url: format!("https://{addr}/"),
        style: SignStyle::Rpc,
        query: String::new(),
        headers: BTreeMap::new(),
        body: String::new(),
    }
}

#[tokio::test]
async fn default_transport_rejects_self_signed_but_custom_ca_connects() {
    let material = self_signed();
    let addr = spawn_tls_server(&material).await;

    // 1) 默认（生产口径）：自签证书必须被拒绝，且失败原因是证书校验
    let strict = ReqwestTransport::new(5);
    assert!(strict.is_ok(), "{strict:?}");
    let Ok(strict) = strict else { return };
    assert_eq!(strict.tls_policy(), &TlsPolicy::VerifyChain);
    let rejected = strict.send_async(&request(addr)).await;
    let detail = format!("{rejected:?}");
    assert!(rejected.is_err(), "默认必须拒绝自签证书，实际：{detail}");
    let lower = detail.to_lowercase();
    assert!(
        lower.contains("certificate") || lower.contains("cert") || lower.contains("unknownissuer"),
        "失败原因必须是证书校验（而不是连不上/超时）：{detail}"
    );

    // 2) 放开分支：dev / 显式开关下信任该自签 CA ⇒ 必须能连上并解析响应
    let relaxed = ReqwestTransport::with_tls_options(5, Some(material.cert_pem.clone().into_bytes()), false);
    assert!(relaxed.is_ok(), "{relaxed:?}");
    let Ok(relaxed) = relaxed else { return };
    if tls_override_allowed() {
        assert_eq!(relaxed.tls_policy(), &TlsPolicy::CustomCa);
        let ok = relaxed.send_async(&request(addr)).await;
        assert!(ok.is_ok(), "放开后必须能连上自签服务端：{ok:?}");
        let Ok(response) = ok else { return };
        assert_eq!(response.status, 200);
        assert_eq!(response.body.get("Success").and_then(serde_json::Value::as_bool), Some(true));
        println!("[OK] AGF_ENV=dev：custom-ca 策略下自签服务端返回 200 且响应体已解析");
    } else {
        // 非 dev：ca_pem 必须被忽略（策略仍是 verify-chain），请求仍然失败
        assert_eq!(relaxed.tls_policy(), &TlsPolicy::VerifyChain, "非 dev 环境必须忽略 ca_pem（生产默认关闭放松开关）");
        assert!(relaxed.send_async(&request(addr)).await.is_err(), "被忽略后仍应拒绝自签证书");
        println!(
            "[SKIP] 未设置 AGF_ENV=dev / AGF_ALIYUN_ALLOW_INSECURE_TLS=1：\
             '放开后可连' 分支未执行（上面的默认拒绝 + 忽略断言已通过）"
        );
    }
}

#[tokio::test]
async fn insecure_switch_still_connects_when_allowed() {
    if !tls_override_allowed() {
        println!("[SKIP] 非 dev 环境：allow_insecure_tls 按设计不生效");
        return;
    }
    let material = self_signed();
    let addr = spawn_tls_server(&material).await;
    let insecure = ReqwestTransport::with_tls_options(5, None, true);
    assert!(insecure.is_ok(), "{insecure:?}");
    let Ok(insecure) = insecure else { return };
    assert_eq!(insecure.tls_policy(), &TlsPolicy::Insecure);
    let ok = insecure.send_async(&request(addr)).await;
    assert!(ok.is_ok(), "allow_insecure_tls 打开后必须能连上：{ok:?}");
    assert_eq!(ok.map(|r| r.status), Ok(200));
}
