//! 采集器上行端点的 **mTLS 身份侧**集成测试：证书头解析、主体映射、跳过校验门禁。
//!
//! 分为两半：
//! - **纯函数**部分（证书解析 / 通配映射 / 门禁开关）——不起 HTTP，直接断言解析与授权策略；
//! - **环境变量门禁**部分——走子进程跑 `agf-agent tls-check`，因为集成测试进程不能安全地改
//!   自己的环境（workspace 的 `unsafe_code = "forbid"` 覆盖集成测试目标，`forbid` 无法被 `allow` 覆盖）。
//!
//! 端点本身的 HTTP 行为（401/403/幂等/落 Sink/OpenAPI）在 `tests/ingest_agent.rs`；
//! 完整的"证书 → 200"真机链路见 `tools/simulators/run_agent_mtls_e2e.ps1`。
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines)]
// 未构建 agf-agent 时用 println! 提示"跳过"，这是集成测试的正常输出。
#![allow(clippy::print_stdout)]

mod common;

use common::*;

use agf_api::routes::ingest::{PrincipalMap, cert_from_headers, parse_client_cert_der_b64, parse_client_cert_pem};
use agf_api::routes::ingest::{pattern_matches, required, trust_proxy};

// ---------------------------------------------------------------------------
// 环境变量门禁：AGF_ENV / 跳过校验（走**子进程**验证真实读取路径）
// ---------------------------------------------------------------------------

/// 在**子进程**里跑 `agf-agent tls-check --json`，返回其 JSON 输出；二进制不存在时返回 `None`。
///
/// 这是 `AGF_ENV` / `AGF_AGENT_TLS_INSECURE_SKIP_VERIFY` 生效路径的真实验证：
/// 生产里读的就是 `std::env`，而集成测试进程不能安全地改自己的环境
/// （workspace 的 `unsafe_code = "forbid"` 覆盖集成测试目标，`forbid` 无法被 `allow` 覆盖）。
fn run_tls_check(env: &[(&str, &str)]) -> Option<Value> {
    // `CARGO_BIN_EXE_*` 只在"同包"的原生测试里可用，这里用工作区 target 目录定位二进制。
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent()?.parent()?;
    let exe = if cfg!(windows) { "agf-agent.exe" } else { "agf-agent" };
    let target =
        std::env::var_os("CARGO_TARGET_DIR").map(std::path::PathBuf::from).unwrap_or_else(|| workspace.join("target"));
    let target = if target.is_absolute() { target } else { workspace.join(target) };
    let binary = target.join("debug").join(exe);
    if !binary.exists() {
        // 未构建 agf-agent 时**跳过**（不假装通过）：真正的门禁由 E2E 脚本覆盖
        return None;
    }
    let mut command = std::process::Command::new(binary);
    command.arg("tls-check").arg("--json");
    for (key, value) in env {
        command.env(key, value);
    }
    let output = command.output().expect("spawn agf-agent tls-check");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    Some(serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("tls-check 输出不是 JSON ({e}): {stdout}")))
}

/// `AGF_ENV=dev` 门禁在**真实进程环境**里的生效路径（代理层纯函数测试之外的另一半）。
///
/// 走子进程而不是 `std::env::set_var`：workspace 的 `unsafe_code = "forbid"` 覆盖集成测试目标，
/// 而 Rust 2024 里改环境变量必须 `unsafe`；子进程既绕开这条限制，又验证了真实的读环境路径。
#[test]
fn agent_tls_check_subprocess_reads_agf_env_gate() {
    // ① AGF_ENV=prod 且请求跳过校验 ⇒ 配置不健康（明确报错，不静默忽略）
    //    注意必须给 https 地址：明文地址下 TLS 材料根本不参与装配，无从谈"跳过校验"。
    let Some(denied) = run_tls_check(&[
        ("AGF_ENV", "prod"),
        ("AGF_AGENT_SERVER_URL", "https://127.0.0.1:9/x"),
        ("AGF_AGENT_TLS_INSECURE_SKIP_VERIFY", "1"),
        ("AGF_AGENT_TLS_ALLOW_INSECURE", "0"),
    ]) else {
        println!("skip: agf-agent 未构建（target/debug/agf-agent 不存在）");
        return;
    };
    assert_eq!(denied["insecure_allowed"], false, "{denied}");
    assert_eq!(denied["insecure_skip_verify"], false, "{denied}");
    assert_eq!(denied["error_kind"], "config", "{denied}");

    // ② AGF_ENV=dev ⇒ 放行，且健康画像如实标注"已跳过"
    let allowed = run_tls_check(&[
        ("AGF_ENV", "dev"),
        ("AGF_AGENT_SERVER_URL", "https://127.0.0.1:9/x"),
        ("AGF_AGENT_TLS_INSECURE_SKIP_VERIFY", "1"),
    ])
    .expect("第一次调用已确认二进制存在");
    assert_eq!(allowed["insecure_allowed"], true, "{allowed}");
    assert_eq!(allowed["insecure_skip_verify"], true, "{allowed}");
    assert_eq!(allowed["error_kind"], serde_json::Value::Null, "{allowed}");
    assert_eq!(allowed["env_name"], "dev", "{allowed}");

    // ③ 未配置 mTLS 且地址是明文 http ⇒ 明文模式（不是"未实现"，也不是错误）
    let plain = run_tls_check(&[("AGF_AGENT_SERVER_URL", "http://127.0.0.1:9/x")]).expect("二进制存在");
    assert_eq!(plain["mode"], "plaintext", "{plain}");
    assert_eq!(plain["error_kind"], serde_json::Value::Null, "{plain}");
}

// ---------------------------------------------------------------------------
// ⑥ mTLS 证书身份的解析与映射（纯函数；HTTP 层的 401/403 由上一节覆盖，
//    完整的"证书 → 200"链路见 tools/simulators/run_agent_mtls_e2e.ps1 的真机端到端）
// ---------------------------------------------------------------------------

/// 取证书 DER 的 base64（与 terminator 透传的头部同形式）。
fn cert_der_b64(common_name: &str, org: &str) -> String {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("cert params");
    params.distinguished_name.push(rcgen::DnType::CommonName, common_name);
    params.distinguished_name.push(rcgen::DnType::OrganizationName, org);
    params.distinguished_name.push(rcgen::DnType::OrganizationalUnitName, "collectors");
    let key = rcgen::KeyPair::generate().expect("key pair");
    let cert = params.self_signed(&key).expect("self signed");
    let der = cert.der();
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(der.as_ref())
}

#[test]
fn mtls_cert_identity_and_mapping_resolve_to_tenant_and_role() {
    let encoded = cert_der_b64("agf-collector-it", "agf-test-org");
    let cert = parse_client_cert_der_b64(&encoded).expect("证书必须可解析");
    assert_eq!(cert.common_name.as_deref(), Some("agf-collector-it"));
    assert_eq!(cert.organization.as_deref(), Some("agf-test-org"));
    assert_eq!(cert.organizational_units, vec!["collectors".to_string()]);
    assert!(cert.subject.starts_with("CN=agf-collector-it,OU=collectors,O=agf-test-org"), "{}", cert.subject);
    assert_eq!(cert.fingerprint_sha256.len(), 64, "SHA-256 指纹应为 64 位 hex");
    assert!(cert.fingerprint_sha256.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    assert_eq!(cert.identity, cert.subject);

    // 映射：命中 ⇒ 角色 + 租户（规则里的 subject 自带 `=`，验证按最后一个 `=` 切分）
    // 注意：无 `*` 的模式是**全等**匹配；证书 subject 后面还跟着 OU/O，所以这里用前缀通配。
    assert!(pattern_matches("CN=agf-collector-it*", &cert.subject), "pattern 应命中 {}", cert.subject);
    let map = PrincipalMap::from_lookup(|key| match key {
        "AGF_AGENT_MTLS_MAP" => Some("CN=agf-collector-it*=tenant-admin".to_string()),
        _ => None,
    });
    let resolved = map.resolve(&cert).unwrap_or_else(|| panic!("映射应命中：subject={}", cert.subject));
    assert_eq!(resolved.0, "tenant-admin");
    assert_eq!(resolved.1, TenantId::default_tenant());

    // 无 `*` 的模式 = 全等匹配（写全整个 subject 才命中）
    let entry = format!("{}=viewer", cert.subject);
    let exact = PrincipalMap::from_lookup(|key| match key {
        "AGF_AGENT_MTLS_MAP" => Some(entry.clone()),
        _ => None,
    });
    assert_eq!(
        exact.resolve(&cert).map(|(role, _)| role),
        Some("viewer".to_string()),
        "entry={entry} subject={} exact_match={}",
        cert.subject,
        pattern_matches(&cert.subject, &cert.subject)
    );

    // 映射：未命中且无默认角色 ⇒ 拒绝（**不默认全权**）
    let empty = PrincipalMap::from_lookup(|_| None);
    assert!(empty.resolve(&cert).is_none(), "无映射必须拒绝");

    // 通配匹配（大小写不敏感；`*.corp.example` 这类主机名规则同样可用）
    let wildcard = PrincipalMap::from_lookup(|key| match key {
        "AGF_AGENT_MTLS_MAP" => Some("CN=AGF-COLLECTOR*=soc-analyst".to_string()),
        _ => None,
    });
    assert_eq!(wildcard.resolve(&cert).map(|(role, _)| role), Some("soc-analyst".to_string()));
    assert!(pattern_matches("*.corp.example", "collector.corp.example"));
    assert!(pattern_matches("collector.corp.*", "collector.corp.example"));
    assert!(!pattern_matches("*.corp.example", "collector.other.example"));
    assert!(pattern_matches("CN=exact", "cn=EXACT"));
    assert!(pattern_matches("CN=agf-*-it*", "CN=agf-collector-it,OU=collectors"));
    assert!(!pattern_matches("CN=agf-*-it", "CN=agf-collector-it,OU=collectors"), "后缀必须落在末尾");
}

#[test]
fn mtls_trust_and_required_flags_are_explicit() {
    // 默认**不信任**代理头
    assert!(!trust_proxy(|_| None));
    assert!(!required(|_| None));
    let on =
        |key: &str| (key == "AGF_AGENT_MTLS_TRUST_PROXY" || key == "AGF_AGENT_MTLS_REQUIRED").then(|| "1".to_string());
    assert!(trust_proxy(on));
    assert!(required(on));
    let off = |key: &str| (key == "AGF_AGENT_MTLS_TRUST_PROXY").then(|| "false".to_string());
    assert!(!trust_proxy(off));
}

#[test]
fn mtls_cert_header_requires_verify_success() {
    let encoded = cert_der_b64("header-collector", "agf-test-org");
    let mut headers = HeaderMap::new();
    // ① 只有证书头、没有校验结论 ⇒ 401（不得拿证书当免认证通行证）
    headers.insert("x-agf-client-cert-der", encoded.parse().expect("header value"));
    let error = cert_from_headers(&headers).expect_err("缺少校验结论必须拒绝");
    assert_eq!(error.status, StatusCode::UNAUTHORIZED, "{error:?}");
    // ② 网关标记失败 ⇒ 仍然 401
    headers.insert("x-ssl-client-verify", "FAILED".parse().expect("header value"));
    assert!(cert_from_headers(&headers).is_err());
    // ③ 网关标记成功 ⇒ 解析出证书身份
    headers.insert("x-ssl-client-verify", "SUCCESS".parse().expect("header value"));
    let cert = cert_from_headers(&headers).expect("应解析成功").expect("应有证书");
    assert_eq!(cert.common_name.as_deref(), Some("header-collector"));
    // ④ 没有任何证书头 ⇒ None（回落 Bearer）
    assert!(cert_from_headers(&HeaderMap::new()).expect("无证书头不是错误").is_none());
    // ⑤ base64 非法 ⇒ 401
    let mut broken = HeaderMap::new();
    broken.insert("x-agf-client-cert-der", "!!!".parse().expect("header value"));
    broken.insert("x-ssl-client-verify", "SUCCESS".parse().expect("header value"));
    assert!(cert_from_headers(&broken).is_err());
}

#[test]
fn mtls_pem_header_is_supported_too() {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("cert params");
    params.distinguished_name.push(rcgen::DnType::CommonName, "pem-collector");
    let key = rcgen::KeyPair::generate().expect("key pair");
    let pem = params.self_signed(&key).expect("self signed").pem();

    let cert = parse_client_cert_pem(&pem).expect("PEM 必须可解析");
    assert_eq!(cert.common_name.as_deref(), Some("pem-collector"));
    // nginx 的 `$ssl_client_escaped_cert` 形态：percent-encoded
    let escaped = pem.replace('\n', "%0A");
    let cert = parse_client_cert_pem(&escaped).expect("percent-encoded PEM 必须可解析");
    assert_eq!(cert.common_name.as_deref(), Some("pem-collector"));
    assert!(parse_client_cert_pem("not a certificate").is_err());
}
