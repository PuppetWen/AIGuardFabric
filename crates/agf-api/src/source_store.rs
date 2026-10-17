//! Durable tenant log sources. Credentials are sealed separately from public connection metadata.
use crate::state::AppState;
use agf_core::{
    enums::{HealthState, IngestProtocol},
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    source::{CollectionMode, LogSource, SourceConnection},
    time::Timestamp,
};
use secrecy::ExposeSecret;
use serde::Deserialize;
use std::collections::BTreeMap;

pub const KIND: &str = "log-source";
pub const MAX_BATCH: usize = 1_000;
pub const MAX_BYTES: usize = 2 * 1024 * 1024;

pub use agf_core::source::SourceRecord as Record;

/// Deliberately excludes server-owned counters, tenant, credentials and health fields.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub name: String,
    pub protocol: String,
    #[serde(default, alias = "nativeReceiver")]
    pub native_receiver: Option<String>,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default, alias = "parserId")]
    pub parser_id: Option<String>,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default = "interval", alias = "pollIntervalSecs")]
    pub poll_interval_secs: i64,
    #[serde(default)]
    pub headers: Option<BTreeMap<String, String>>,
    #[serde(default, alias = "allowedCidrs")]
    pub allowed_cidrs: Option<Vec<String>>,
    #[serde(default, alias = "requireMtls")]
    pub require_mtls: Option<bool>,
}

impl std::fmt::Debug for Input {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Input").field("name", &self.name).field("protocol", &self.protocol).finish_non_exhaustive()
    }
}
fn yes() -> bool {
    true
}
fn interval() -> i64 {
    60
}

pub async fn load(state: &AppState, tenant: TenantId, id: Id) -> DomainResult<Record> {
    state
        .configurations
        .get::<Record>(tenant, KIND, id)
        .await?
        .filter(|row| row.source.is_some())
        .ok_or_else(|| DomainError::NotFound { entity: "log-source", id: id.to_string() })
}

pub async fn build(state: &AppState, tenant: TenantId, id: Id, input: Input) -> DomainResult<Record> {
    let allowed_cidrs = input.allowed_cidrs.unwrap_or_default();
    agf_ingest::pipeline::validate_cidrs(&allowed_cidrs)?;
    let require_mtls = input.require_mtls.unwrap_or(false);
    let (supports_cidrs, supports_mtls) =
        agf_ingest::pipeline::source_transport_controls(input.native_receiver.as_deref().unwrap_or_default());
    if (!allowed_cidrs.is_empty() && !supports_cidrs) || (require_mtls && !supports_mtls) {
        return Err(DomainError::Validation(
            "此接收器不能核验所选连接限制；CIDR 用于 Syslog/OTLP，双向 TLS 用于 Syslog TLS/OTLP gRPC。消息代理和拉取端请在上游配置访问策略。".into(),
        ));
    }
    let name = input.name.trim();
    if name.is_empty() || name.len() > 200 {
        return Err(DomainError::Validation("日志源名称须为 1–200 字节".into()));
    }
    let protocol = if let Some(receiver) = &input.native_receiver {
        let protocol = agf_core::source::native_receiver_protocol(receiver)
            .ok_or_else(|| DomainError::Validation("请选择受支持的原生接收器".into()))?;
        if input.protocol != "native" && input.protocol != protocol.as_str() {
            return Err(DomainError::Validation("接收器与接入协议不匹配".into()));
        }
        protocol
    } else {
        match input.protocol.as_str() {
            "http-webhook" | "webhook" | "http-push" => IngestProtocol::Webhook,
            "http-pull" => IngestProtocol::HttpPull,
            _ => {
                return Err(DomainError::Validation(
                    "此配置入口支持 HTTP Webhook 和 HTTP Pull；其他协议请使用协议接收器部署指南".into(),
                ));
            }
        }
    };
    let pull = protocol == IngestProtocol::HttpPull;
    let endpoint = if pull {
        let url = url::Url::parse(input.endpoint.trim())
            .map_err(|_| DomainError::Validation("请输入有效的 HTTP 拉取地址".into()))?;
        let loopback = url.host_str().is_some_and(|host| {
            host.trim_matches(['[', ']']).parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
        });
        if !(url.scheme() == "https" || (url.scheme() == "http" && loopback))
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(DomainError::Validation(
                "拉取地址须使用 HTTPS（本机测试 IP 可用 HTTP）；凭据放入请求头，不接受 URL 用户信息或片段".into(),
            ));
        }
        url.to_string()
    } else if let Some(receiver) = &input.native_receiver {
        format!("receiver://{receiver}")
    } else {
        format!("/api/v1/ingest/sources/{id}/events")
    };
    if !(5..=86_400).contains(&input.poll_interval_secs) {
        return Err(DomainError::Validation("拉取间隔必须为 5–86400 秒".into()));
    }
    let parsers = crate::parser_store::registry(state, tenant).await?;
    let parser_id = input
        .parser_id
        .filter(|id| !id.is_empty())
        .map(|raw| {
            parsers
                .find_key(&raw)
                .or_else(|| Id::parse(&raw).ok().and_then(|id| parsers.find_id(id)))
                .filter(|parser| parser.enabled)
                .map(|parser| parser.id)
                .ok_or_else(|| DomainError::Validation("所选解析器不存在或未启用".into()))
        })
        .transpose()?;
    let headers = input
        .headers
        .map(|headers| {
            if !pull && !headers.is_empty() {
                return Err(DomainError::Validation("推送源使用平台 API Key，无需保存上游凭据".into()));
            }
            if headers.len() > 20
                || headers.iter().any(|(key, value)| {
                    key.len() > 100
                        || value.len() > 4096
                        || key.eq_ignore_ascii_case("host")
                        || key.eq_ignore_ascii_case("x-agf-cursor")
                        || reqwest::header::HeaderName::from_bytes(key.as_bytes()).is_err()
                        || reqwest::header::HeaderValue::from_str(value).is_err()
                })
            {
                return Err(DomainError::Validation("请求头非法、超过长度限制或包含保留的 Host / X-AGF-Cursor".into()));
            }
            crate::model_gateway::encrypt(state, tenant, id, serde_json::to_string(&headers)?)
        })
        .transpose()?;
    let now = Timestamp::now();
    Ok(Record {
        source: Some(LogSource {
            id,
            tenant_id: tenant,
            name: name.into(),
            protocol,
            vendor: String::new(),
            product: input.native_receiver.clone().unwrap_or_default(),
            enabled: input.enabled,
            parser_id,
            connection: SourceConnection {
                tls: endpoint.starts_with("https:"),
                endpoint: Some(endpoint),
                ..Default::default()
            },
            mode: match protocol {
                IngestProtocol::Kafka | IngestProtocol::Pulsar | IngestProtocol::Nats | IngestProtocol::Mqtt => {
                    CollectionMode::Subscribe
                }
                IngestProtocol::Jdbc => CollectionMode::Poll,
                IngestProtocol::ObjectStorage | IngestProtocol::HttpPull => CollectionMode::Pull,
                _ => CollectionMode::Push,
            },
            poll_interval_secs: pull.then_some(input.poll_interval_secs),
            require_mtls,
            allowed_cidrs,
            max_message_bytes: MAX_BYTES,
            max_eps: 10_000,
            tags: Vec::new(),
            health: HealthState::Unconfigured,
            last_event_at: None,
            total_events: 0,
            last_error: None,
            created_at: now,
            updated_at: now,
        }),
        headers,
        native_receiver: input.native_receiver,
        ..Record::default()
    })
}

pub fn public(record: &Record) -> serde_json::Value {
    let mut value = serde_json::to_value(&record.source).unwrap_or_default();
    if let Some(object) = value.as_object_mut() {
        object.insert("native_receiver".into(), record.native_receiver.clone().into());
        object.insert("headers_configured".into(), record.headers.is_some().into());
        object.insert("received".into(), record.received.into());
        object.insert("matched".into(), record.matched.into());
        object.insert("failed".into(), record.failed.into());
        object.insert("next_poll_at".into(), record.next_poll_at.into());
    }
    value
}

pub fn headers(state: &AppState, source: &LogSource, record: &Record) -> DomainResult<BTreeMap<String, String>> {
    let Some(secret) = &record.headers else {
        return Ok(BTreeMap::new());
    };
    let expected = agf_storage::crypto::FieldCipher::make_aad(&source.tenant_id, &source.id);
    if secret.aad.as_deref() != Some(&expected) {
        return Err(DomainError::Crypto("日志源凭据绑定不匹配".into()));
    }
    let plain = crate::model_gateway::cipher(state)?.decrypt(secret)?;
    Ok(serde_json::from_str(plain.expose_secret())?)
}
