//! KoP 端点与凭据解析（纯函数）：`kop://` 端点、Pulsar topic → Kafka topic 映射、`token:` 形式的 PLAIN 用户名/口令。

use super::*;

/// KoP 端点解析结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KopEndpoint {
    /// Kafka 协议 broker 列表（`host:port`）。
    pub brokers: Vec<String>,
    /// 非致命提示（例如写了 `pulsar://` 前缀但端口不是原生端口）。
    pub note: String,
}

/// 解析 KoP 的 **Kafka 协议**监听地址（纯函数）。
///
/// * 接受 `kafka://host:9092`、`plaintext://host:9092`、`host:9092`（逗号分隔多 broker）；
/// * **拒绝** `pulsar://host:6650` / `pulsar+ssl://…`：那是 Pulsar 原生 binary protocol，
///   本接收器未实现（拒绝而不是静默降级——配置错误必须让人看见）；
/// * `pulsar://host:19092` 这类"写了原生 scheme 但端口不是原生端口"的写法按 KoP 地址处理并给出提示。
///
/// # Errors
/// 地址为空、含空项、缺端口、指向原生协议端口、或 scheme 不认识。
pub fn parse_kop_endpoint(endpoint: &str) -> DomainResult<KopEndpoint> {
    let mut brokers: Vec<String> = Vec::new();
    let mut note = String::new();
    for raw in endpoint.split(',') {
        let item = raw.trim();
        if item.is_empty() {
            continue;
        }
        let (scheme, rest) = match item.split_once("://") {
            Some((scheme, rest)) => (Some(scheme.to_ascii_lowercase()), rest),
            None => (None, item),
        };
        let host_port = rest.trim_end_matches('/').trim_end_matches('.');
        let port = host_port.rsplit_once(':').map(|(_, port)| port.to_string()).unwrap_or_default();
        match scheme.as_deref() {
            Some("pulsar" | "pulsar+ssl") => {
                if port == "6650" || port == "6651" || scheme.as_deref() == Some("pulsar+ssl") {
                    return Err(DomainError::Config(format!(
                        "Pulsar 原生协议（binary protocol）未实现：{item} 指向 Pulsar 原生端口；\
                         本接收器经 **KoP（Kafka on Pulsar）** 复用 Kafka 接收器，\
                         请把 AGF_INGEST_PULSAR_SERVICE_URL 指向 KoP 的 Kafka 协议监听（如 kafka://host:9092）"
                    )));
                }
                note =
                    format!("{item} 使用了 pulsar:// 前缀，已按 KoP 的 Kafka 协议地址解析（端口 {port} ≠ 6650/6651）");
            }
            Some("kafka" | "plaintext" | "kafka-plaintext" | "sasl_plaintext" | "ssl" | "kafka-ssl" | "sasl_ssl")
            | None => {}
            Some(other) => {
                return Err(DomainError::Config(format!(
                    "不认识的 KoP 端点 scheme `{other}`：支持 kafka:// / plaintext:// / ssl:// 或直接 host:port"
                )));
            }
        }
        if !host_port.contains(':') {
            return Err(DomainError::Config(format!("KoP 端点 {item:?} 缺少端口（形如 host:9092）")));
        }
        brokers.push(host_port.to_string());
    }
    if brokers.is_empty() {
        return Err(DomainError::Config(
            "Pulsar 需要 KoP 的 Kafka 协议地址（AGF_INGEST_PULSAR_SERVICE_URL，如 kafka://host:9092）".to_string(),
        ));
    }
    Ok(KopEndpoint { brokers, note })
}

/// Pulsar topic → Kafka（KoP）topic 名 + tenant/namespace（纯函数）。
///
/// KoP 把 Kafka topic `T` 映射为 `persistent://{tenant}/{namespace}/T`，
/// 因此 `persistent://public/default/sec-logs` 在 Kafka 协议侧的 topic 名是 `sec-logs`。
#[must_use]
pub fn kop_topic_name(raw: &str) -> (String, Option<String>) {
    let trimmed = raw.trim().trim_start_matches("persistent://");
    let parts: Vec<&str> = trimmed.split('/').filter(|part| !part.is_empty()).collect();
    match parts.as_slice() {
        [] => (raw.trim().to_string(), None),
        [topic] => ((*topic).to_string(), None),
        [tenant, topic] => ((*topic).to_string(), Some((*tenant).to_string())),
        [tenant, namespace, topic, ..] => ((*topic).to_string(), Some(format!("{tenant}/{namespace}"))),
    }
}

/// KoP 的 SASL/PLAIN **username**：必须是 token 的 subject（即授权角色）。
///
/// **实测结论**（KoP 3.1.1.1 + Pulsar 3.3.1，authorizationEnabled=true）：
/// 按"官方文档写法"把 username 写成固定的 `token` 时，token 本身能通过认证
/// （KoP 日志 `PlainSaslServer - Authenticated User agf-ingest`），但紧接着
/// `KafkaCommandDecoder - Failed authentication ... (User is not allowed to access this tenant)`
/// ——即 KoP 用 **SASL username** 去做租户授权，username 必须是**被授权的角色**。
/// 这里直接从 JWT 的 `sub` 声明取角色（不验签，仅用于填充 SASL 字段）；
/// 解析不出来时回退为 `token`（保持与文档一致的保守默认）。
#[must_use]
pub fn kop_plain_username(token: &str) -> String {
    use base64::Engine as _;
    let raw = token.trim();
    // 允许 `token:<jwt>` / `<jwt>` 两种写法
    let jwt = raw.split_once(':').map_or(raw, |(_, value)| value);
    let payload = jwt.split('.').nth(1);
    let Some(payload) = payload else {
        return "token".to_string();
    };
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload).ok();
    let Some(decoded) = decoded else {
        return "token".to_string();
    };
    serde_json::from_slice::<Value>(&decoded)
        .ok()
        .and_then(|value| value.get("sub").and_then(Value::as_str).map(ToString::to_string))
        .filter(|sub| !sub.trim().is_empty())
        .unwrap_or_else(|| "token".to_string())
}

/// KoP 的 SASL/PLAIN 口令格式（**实测结论，与"裸 token"的想当然不同**）。
///
/// KoP 的 `SaslUtils.parseSaslAuthBytes` 对 PLAIN 的 password 字段做 `split(":")`
/// 并要求**恰好两段**：`<authMethod>:<authData>`；否则报
/// `Authentication failed: password not specified`（与"口令为空"共用同一句错误文本，
/// 极易误导——用真实 KoP 抓包/反编译才定位到）。随后 KoP 用 `<authMethod>` 去
/// `AuthenticationService.getAuthenticationProvider(<authMethod>)` 取认证器
/// （token 鉴权即 `token`），`<authData>` 作为该认证器的凭据（JWT 原文）。
///
/// 因此：
/// * `AGF_INGEST_PULSAR_TOKEN=eyJ...`（裸 JWT）→ 自动补成 `token:eyJ...`；
/// * `AGF_INGEST_PULSAR_TOKEN=token:eyJ...`（已带 authMethod 前缀，与 Pulsar 自身
///   `brokerClientAuthenticationParameters=token:...` 同构）→ 原样使用。
#[must_use]
pub fn kop_plain_password(token: &str) -> String {
    if token.contains(':') { token.trim().to_string() } else { format!("token:{}", token.trim()) }
}

/// Pulsar 能力描述（能力矩阵与 `/readyz` 共用）。
///
/// `kop_service_url` = `AGF_INGEST_PULSAR_SERVICE_URL`：
/// **未配置 ⇒ `not-implemented`**（不假装 ready）；配置了 ⇒ `ready`，
/// note 一字不差写明"经 KoP（Kafka on Pulsar）复用 Kafka 接收器；Pulsar 原生协议未实现"。
#[must_use]
pub fn pulsar_descriptor(kop_service_url: Option<&str>) -> ReceiverDescriptor {
    let configured = kop_service_url.map(str::trim).filter(|url| !url.is_empty());
    match configured {
        Some(url) => ReceiverDescriptor {
            name: "pulsar".to_string(),
            protocol: IngestProtocol::Pulsar,
            status: ReceiverStatus::Ready,
            note: format!(
                "经 KoP（Kafka on Pulsar）复用 Kafka 接收器；Pulsar 原生协议未实现。\
                 KoP 的 Kafka 协议监听：{url}（AGF_INGEST_PULSAR_SERVICE_URL）"
            ),
            todo: Some(PULSAR_NATIVE_TODO.to_string()),
            mock_replay: false,
        },
        None => ReceiverDescriptor {
            name: "pulsar".to_string(),
            protocol: IngestProtocol::Pulsar,
            status: ReceiverStatus::NotImplemented,
            note: "未启用：未配置 AGF_INGEST_PULSAR_SERVICE_URL（KoP 的 Kafka 协议监听，如 kafka://host:9092）；\
                   Pulsar 原生协议同样未实现（经 KoP 复用 Kafka 接收器是唯一已实现路径）"
                .to_string(),
            todo: Some(PULSAR_NATIVE_TODO.to_string()),
            mock_replay: true,
        },
    }
}
