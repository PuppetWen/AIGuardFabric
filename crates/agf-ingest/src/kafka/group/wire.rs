//! Kafka wire 传输层：长度前缀分帧、ApiVersions 版本协商、请求/响应编解码、TLS 与 SASL/PLAIN 握手。
//!
//! 这一层**只做"把一条请求发出去、把对应响应解回来"**：协调器状态机在 `session` 里，
//! 分配算法在 `assign` 里。报文结构全部来自 `kafka-protocol`（不手写 wire 格式），
//! 但**连接池、版本协商、分帧、SASL 握手**是本仓库自己实现的（`kafka-protocol` 不含这些）。

use std::collections::BTreeMap;
use std::time::Duration;

use agf_core::error::{DomainError, DomainResult};
use bytes::{BufMut, Bytes, BytesMut};
use kafka_protocol::messages::{ApiVersionsRequest, ApiVersionsResponse, RequestHeader, ResponseHeader};
use kafka_protocol::protocol::{Decodable as _, Encodable as _, HeaderVersion, Request, StrBytes};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::kafka::{KafkaSaslMechanism, KafkaSecurity};
use tracing::debug;

/// 单帧上限（防止对端发一个天文数字的长度把内存吃光）。
const MAX_FRAME_BYTES: i32 = 64 * 1024 * 1024;

/// 我们使用的 ApiVersions 版本。
///
/// **固定用 v0**：v0 是 Kafka 0.10.0 起就有的版本，所有实现（真 Kafka、KoP、Redpanda…）
/// 都接受；而 v3/v4 是 flexible 版本，遇到不支持的服务端还要按"降级重发 v0"的特殊规则处理
/// （Kafka 对 ApiVersions 的 UNSUPPORTED_VERSION 响应是**按 v0 编码**的，解码会错位）。
/// 版本协商本来只需要 `ApiVersionsResponse.api_keys` 里的 min/max，v0 就够。
const API_VERSIONS_VERSION: i16 = 0;

/// 请求头版本兜底值（v1）。真实取值一律走 `<Req as HeaderVersion>::header_version`。
const _: i16 = 1;

/// 可当作 Kafka 连接使用的双向流（明文 TCP 或 TLS 之上）。
pub(super) trait IoStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> IoStream for T {}

/// 一条 Kafka 连接（按 broker 地址复用；内部串行化请求/响应）。
pub(super) struct Wire {
    io: Box<dyn IoStream>,
    buffer: BytesMut,
    client_id: String,
    correlation: i32,
    /// 本连接协商结果：`api_key → (min_version, max_version)`。
    versions: BTreeMap<i16, (i16, i16)>,
    /// 排障用标签（`host:port`，**不含凭据**）。
    label: String,
}

impl std::fmt::Debug for Wire {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wire")
            .field("label", &self.label)
            .field("correlation", &self.correlation)
            .field("api_keys", &self.versions.len())
            .finish_non_exhaustive()
    }
}

/// 建连/传输错误（**只带地址与驱动原文**，绝不含 SASL 凭据）。
fn wire_err(label: &str, action: &str, detail: impl std::fmt::Display) -> DomainError {
    DomainError::DependencyUnavailable {
        dependency: "kafka".to_string(),
        cause: format!("{label} {action} 失败: {detail}"),
    }
}

impl Wire {
    /// 建立连接：TCP（+ 可选 TLS）→ ApiVersions 协商 → 可选 SASL/PLAIN 认证。
    pub(super) async fn connect(addr: &str, client_id: &str, security: &KafkaSecurity) -> DomainResult<Self> {
        let tcp = tokio::time::timeout(Duration::from_secs(10), tokio::net::TcpStream::connect(addr))
            .await
            .map_err(|_| wire_err(addr, "连接超时（10s）", "TCP connect timed out"))?
            .map_err(|e| wire_err(addr, "TCP 连接", e))?;
        let _ = tcp.set_nodelay(true);
        let io: Box<dyn IoStream> = match &security.tls {
            Some(tls) => {
                let config = tls.build_client_config()?;
                let host = addr.rsplit_once(':').map_or(addr, |(host, _)| host).to_string();
                let name = rustls::pki_types::ServerName::try_from(host.clone())
                    .map_err(|e| DomainError::Config(format!("Kafka TLS 服务名 {host:?} 非法: {e}")))?;
                let connector = tokio_rustls::TlsConnector::from(config);
                Box::new(connector.connect(name, tcp).await.map_err(|e| wire_err(addr, "TLS 握手", e))?)
            }
            None => Box::new(tcp),
        };
        let mut wire = Self {
            io,
            buffer: BytesMut::with_capacity(64 * 1024),
            client_id: client_id.to_string(),
            correlation: 1,
            versions: BTreeMap::new(),
            label: addr.to_string(),
        };
        wire.negotiate_versions().await?;
        wire.authenticate(security).await?;
        Ok(wire)
    }

    /// 地址（`host:port`）。
    pub(super) fn label(&self) -> &str {
        &self.label
    }

    /// 该 API 的可用版本（`None` = broker 未声明该 API）。
    pub(super) fn api_version(&self, api_key: i16) -> Option<(i16, i16)> {
        self.versions.get(&api_key).copied()
    }

    /// 按协商结果挑选版本：`min(preferred, broker_max)`。
    ///
    /// # Errors
    /// broker 未声明该 API，或声明区间低于我们的最低要求。
    pub(super) fn version_for(&self, api_key: i16, preferred: i16, minimum: i16) -> DomainResult<i16> {
        let Some((min_version, max_version)) = self.api_version(api_key) else {
            return Err(DomainError::NotImplemented(format!(
                "Kafka broker {} 不支持 API key {api_key}（消费者组协议必需）",
                self.label
            )));
        };
        if max_version < minimum {
            return Err(DomainError::NotImplemented(format!(
                "Kafka broker {} 的 API key {api_key} 最高只到 v{max_version}，本客户端至少需要 v{minimum}",
                self.label
            )));
        }
        Ok(preferred.min(max_version).max(minimum.min(min_version)))
    }

    /// ApiVersions(v0) → 版本表。
    async fn negotiate_versions(&mut self) -> DomainResult<()> {
        // 报文类型是 `#[non_exhaustive]`：外部 crate 只能用 `default()` + 逐字段赋值
        let mut request = ApiVersionsRequest::default();
        request.client_software_name = StrBytes::from_static_str("agf-ingest");
        request.client_software_version = StrBytes::from_static_str(crate::VERSION);
        let response: ApiVersionsResponse = self.send(API_VERSIONS_VERSION, &request).await?;
        if response.error_code != 0 {
            return Err(wire_err(&self.label, "ApiVersions", format!("broker 返回错误码 {}", response.error_code)));
        }
        self.versions =
            response.api_keys.iter().map(|entry| (entry.api_key, (entry.min_version, entry.max_version))).collect();
        Ok(())
    }

    /// SASL 握手（未配置 ⇒ 直接返回）。
    ///
    /// **只实现 `SASL/PLAIN`**（KoP 的 token 鉴权就走它）。SCRAM 需要完整的
    /// SCRAM 客户端状态机（client-first/server-first/client-final + HMAC 派生），
    /// 这里显式拒绝并**指路降级**：去掉 `GROUP_ID` 即回到既有"本地游标"路径（`rskafka` 支持 SCRAM）。
    async fn authenticate(&mut self, security: &KafkaSecurity) -> DomainResult<()> {
        let Some(sasl) = &security.sasl else {
            return Ok(());
        };
        if sasl.mechanism != KafkaSaslMechanism::Plain {
            return Err(DomainError::NotImplemented(format!(
                "Kafka 消费者组路径只实现 SASL/PLAIN，未实现 {}（去掉 AGF_INGEST_KAFKA_GROUP_ID 即回到 \
                 rskafka 本地游标路径，支持 SCRAM；TODO ingest-kafka-group-scram）",
                sasl.mechanism.as_str()
            )));
        }
        use kafka_protocol::messages::{
            SaslAuthenticateRequest, SaslAuthenticateResponse, SaslHandshakeRequest, SaslHandshakeResponse,
        };
        let handshake_version = self.version_for(SaslHandshakeRequest::KEY, 1, 0)?;
        let mut handshake = SaslHandshakeRequest::default();
        handshake.mechanism = StrBytes::from_static_str("PLAIN");
        let response: SaslHandshakeResponse = self.send(handshake_version, &handshake).await?;
        if response.error_code != 0 {
            return Err(wire_err(
                &self.label,
                "SASL 握手",
                format!("broker 不接受 PLAIN（错误码 {}）", response.error_code),
            ));
        }
        // PLAIN 载荷 = `\0username\0password`；**口令只在这一次发送里出现，绝不进日志**
        let mut payload = Vec::with_capacity(sasl.username.len() + sasl.password().len() + 2);
        payload.push(0);
        payload.extend_from_slice(sasl.username.as_bytes());
        payload.push(0);
        payload.extend_from_slice(sasl.password().as_bytes());
        let auth_version = self.version_for(SaslAuthenticateRequest::KEY, 1, 0)?;
        let mut auth = SaslAuthenticateRequest::default();
        auth.auth_bytes = Bytes::from(payload);
        let response: SaslAuthenticateResponse = self.send(auth_version, &auth).await?;
        if response.error_code != 0 {
            let detail = response
                .error_message
                .as_ref()
                .map_or_else(|| "无错误详情".to_string(), std::string::ToString::to_string);
            return Err(wire_err(&self.label, "SASL 认证", format!("错误码 {}（{detail}）", response.error_code)));
        }
        Ok(())
    }

    /// 发送一条请求并按**同一版本**解码响应（Kafka 的请求/响应共用 api_version）。
    pub(super) async fn send<Req>(&mut self, version: i16, request: &Req) -> DomainResult<Req::Response>
    where
        Req: Request,
        Req::Response: Send,
    {
        let correlation = self.correlation;
        self.correlation = self.correlation.wrapping_add(1);
        let mut header = RequestHeader::default();
        header.request_api_key = Req::KEY;
        header.request_api_version = version;
        header.correlation_id = correlation;
        header.client_id = Some(StrBytes::from_string(self.client_id.clone()));
        let header_version = <Req as HeaderVersion>::header_version(version);
        let response_header_version = <Req::Response as HeaderVersion>::header_version(version);
        let size = header
            .compute_size(header_version)
            .and_then(|head| request.compute_size(version).map(|body| head + body))
            .map_err(|e| wire_err(&self.label, "请求编码", e))?;
        let mut frame = BytesMut::with_capacity(size + 4);
        frame.put_i32(i32::try_from(size).unwrap_or(i32::MAX));
        header.encode(&mut frame, header_version).map_err(|e| wire_err(&self.label, "请求头编码", e))?;
        request.encode(&mut frame, version).map_err(|e| wire_err(&self.label, "请求体编码", e))?;
        self.io.write_all(&frame).await.map_err(|e| wire_err(&self.label, "发送请求", e))?;
        self.io.flush().await.map_err(|e| wire_err(&self.label, "刷新连接", e))?;
        // 排障开关（`AGF_KAFKA_WIRE_DUMP=1`）：把**真正发上线的字节**打进 DEBUG 日志。
        self.dump("请求帧", Req::KEY, version, &frame);

        let mut head = [0_u8; 4];
        self.io.read_exact(&mut head).await.map_err(|e| wire_err(&self.label, "读取响应长度", e))?;
        let length = i32::from_be_bytes(head);
        if length <= 0 || length > MAX_FRAME_BYTES {
            return Err(wire_err(&self.label, "读取响应", format!("帧长度 {length} 非法（上限 {MAX_FRAME_BYTES}）")));
        }
        self.buffer.clear();
        self.buffer.resize(usize::try_from(length).unwrap_or(0), 0);
        self.io.read_exact(&mut self.buffer).await.map_err(|e| wire_err(&self.label, "读取响应体", e))?;
        self.dump("响应帧", Req::KEY, version, &self.buffer);
        let mut body: Bytes = self.buffer.clone().freeze();
        let response_header = ResponseHeader::decode(&mut body, response_header_version)
            .map_err(|e| wire_err(&self.label, "响应头解码", e))?;
        if response_header.correlation_id != correlation {
            return Err(wire_err(
                &self.label,
                "响应关联",
                format!(
                    "correlation_id {} 与请求 {correlation} 不匹配（连接上的响应错位）",
                    response_header.correlation_id
                ),
            ));
        }
        Req::Response::decode(&mut body, version).map_err(|e| wire_err(&self.label, "响应体解码", e))
    }

    /// 排障开关（`AGF_KAFKA_WIRE_DUMP=1`）：把**真正收发的字节**打进 DEBUG 日志。
    ///
    /// 组协议卡住时，"我们发出去的请求体长什么样"和"协调器到底回了什么"是唯一能定分止争的证据。
    /// 真机上靠它定位过一次"响应被协调器扣住"的 bug（消费者协议少 2 字节版本前缀，见 `codec` 模块文档）。
    fn dump(&self, label: &str, api_key: i16, version: i16, bytes: &[u8]) {
        if std::env::var_os("AGF_KAFKA_WIRE_DUMP").is_none() {
            return;
        }
        let mut hex = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            hex.push_str(&format!("{byte:02x}"));
        }
        debug!(broker = %self.label, api_key, version, bytes = bytes.len(), hex, "Kafka wire dump（{label}）");
    }
}
