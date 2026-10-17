//! 原生 Pulsar 连接：TCP/TLS 建连 → CONNECT 握手 → SUBSCRIBE → FLOW → 收 MESSAGE → ACK。
//!
//! 本文件只负责**一条连接**上的一问一答；重连策略（指数退避）由 [`super::receiver`] 驱动，
//! 两者之间的契约是 [`PulsarError::retryable`]——"这个错误换了/重连后是否可能变好"。
//!
//! ## 握手顺序（与官方客户端一致）
//!
//! 1. TCP 建连（`connect_timeout` 为界；`pulsar+ssl://` 再套 rustls，见 [`super::tls`]）；
//! 2. 发 `CommandConnect`（`client_version` / `protocol_version=12` /
//!    可选 `auth_method_name="token"` + `auth_data=<jwt>`）；
//! 3. 收 `CommandConnected`（含 `server_version` / `max_message_size`）；
//!    ——收到 `CommandError` 即分类失败（`AuthorizationError` 等**不重试**）；
//! 4. 发 `CommandSubscribe`（topic / subscription / subType / consumer_id / request_id /
//!    durable / read_compacted / initialPosition / schema=NONE）；
//! 5. 收 `CommandSuccess`（`request_id` 必须与订阅时一致，否则判为协议错乱）；
//! 6. 发 `CommandFlow{message_permits=receiver_queue_size}` 开口子；
//! 7. 之后每收到 `CommandMessage` 处理完就发 `CommandAck`，并**在信用将尽时补 FLOW**
//!    （Pulsar 的 flow 是"增量许可"，不补发会在收满 `receiver_queue_size` 条后停住）。

use std::sync::Arc;

use bytes::BytesMut;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::config::{CLIENT_VERSION, PROTOCOL_VERSION, PulsarEndpoint, PulsarNativeConfig};
use super::frame::{self, DecodedFrame};
use super::proto::{
    BaseCommand, CommandAck, CommandConnect, CommandFlow, CommandLookupTopic, CommandSubscribe, CommandSuccess,
    MessageIdData, ServerError, base_command_type_name, command_type, lookup_type,
};
use super::tls::{self, PulsarStream};

/// 一条原生 Pulsar 连接。
pub struct PulsarClient {
    stream: Box<dyn PulsarStream>,
    buffer: BytesMut,
    stats: Arc<PulsarNativeStats>,
    /// broker 在 `CommandConnected` 里报的版本串（日志/能力矩阵）。
    pub server_version: String,
    /// broker 声明的单条消息上限（0 = 未声明）。
    pub max_message_size: i32,
    /// broker 协商后的协议版本。
    pub protocol_version: i32,
    /// 本连接的消费者 id（每次重新订阅都会换新）。
    pub consumer_id: u64,
    /// 本连接连到的 broker 地址（LOOKUP 重定向后是重定向目标）。
    pub broker_url: String,
    /// 下一个 request_id。
    next_request_id: u64,
}

impl std::fmt::Debug for PulsarClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PulsarClient")
            .field("server_version", &self.server_version)
            .field("max_message_size", &self.max_message_size)
            .field("protocol_version", &self.protocol_version)
            .field("consumer_id", &self.consumer_id)
            .finish_non_exhaustive()
    }
}

impl PulsarClient {
    /// 建连 + 握手（**一次尝试**；退避由调用方负责）。连的是配置里的第一个端点。
    ///
    /// # Errors
    /// TCP/TLS 失败、超时、握手被拒（`CommandError`）或对端提前关闭。
    pub async fn connect(config: &PulsarNativeConfig, stats: Arc<PulsarNativeStats>) -> Result<Self, PulsarError> {
        let endpoint =
            config.primary().ok_or_else(|| PulsarError::Config("Pulsar 原生 URL 里没有可用端点".to_string()))?.clone();
        Self::connect_endpoint(config, stats, &endpoint, config.tls).await
    }

    /// 建连 + 握手到**指定端点**（LOOKUP 重定向后连新 broker 用）。
    ///
    /// # Errors
    /// 同 [`Self::connect`]。
    pub async fn connect_endpoint(
        config: &PulsarNativeConfig,
        stats: Arc<PulsarNativeStats>,
        endpoint: &PulsarEndpoint,
        tls_enabled: bool,
    ) -> Result<Self, PulsarError> {
        let authority = endpoint.authority();
        let connect = tokio::net::TcpStream::connect(&authority);
        let tcp = tokio::time::timeout(config.connect_timeout, connect)
            .await
            .map_err(|_| {
                PulsarError::Io(format!("TCP 连接 {authority} 超时（{}s）", config.connect_timeout.as_secs()))
            })?
            .map_err(|e| PulsarError::Io(format!("TCP 连接 {authority} 失败：{e}")))?;
        tcp.set_nodelay(true).map_err(|e| PulsarError::Io(format!("set_nodelay: {e}")))?;

        let stream: Box<dyn PulsarStream> = if tls_enabled {
            let plan = tls::PulsarTlsPlan {
                ca_pem: config.tls_ca.clone(),
                client_cert_pem: config.tls_cert.clone(),
                client_key_pem: config.tls_key.clone(),
                insecure_skip_verify: config.tls_insecure_skip_verify,
            };
            let upgraded = tokio::time::timeout(config.connect_timeout, tls::upgrade(tcp, &plan, &endpoint.host))
                .await
                .map_err(|_| PulsarError::Tls(format!("TLS 握手 {authority} 超时")))?
                .map_err(|e| PulsarError::Tls(e.to_string()))?;
            Box::new(upgraded)
        } else {
            Box::new(tcp)
        };

        let mut client = Self {
            stream,
            buffer: BytesMut::with_capacity(64 * 1024),
            stats,
            server_version: String::new(),
            max_message_size: 0,
            protocol_version: 0,
            consumer_id: 0,
            next_request_id: 1,
            broker_url: authority,
        };
        client.handshake(config).await?;
        PulsarNativeStats::bump(&client.stats.connects, 1);
        Ok(client)
    }

    /// 分配下一个 request_id（从 1 开始，与官方客户端一致）。
    pub fn next_request_id(&mut self) -> u64 {
        let id = self.next_request_id;
        self.next_request_id = self.next_request_id.saturating_add(1);
        id
    }

    /// 发送 `CommandConnect` 并等待 `CommandConnected`。
    async fn handshake(&mut self, config: &PulsarNativeConfig) -> Result<(), PulsarError> {
        let connect = CommandConnect {
            client_version: Some(CLIENT_VERSION.to_string()),
            auth_method: None,
            auth_data: config.token.as_ref().map(|token| token.as_bytes().to_vec()),
            protocol_version: Some(PROTOCOL_VERSION),
            auth_method_name: config.token.as_ref().map(|_| "token".to_string()),
        };
        self.write_command(&BaseCommand::connect(connect)).await?;
        match self.read_command().await? {
            BaseCommand { connected: Some(connected), .. } => {
                self.server_version = connected.server_version.clone().unwrap_or_default();
                self.protocol_version = connected.protocol_version.unwrap_or(0);
                self.max_message_size = connected.max_message_size.unwrap_or(0);
                tracing::debug!(
                    server_version = %self.server_version,
                    protocol_version = self.protocol_version,
                    max_message_size = self.max_message_size,
                    "Pulsar 原生握手完成"
                );
                Ok(())
            }
            BaseCommand { error: Some(error), .. } => Err(PulsarError::Server {
                error: error.server_error(),
                message: error.message.clone().unwrap_or_default(),
                request_id: error.request_id.unwrap_or(0),
            }),
            other => Err(PulsarError::Unsupported(format!("握手期望 CONNECTED，收到 {}", other.type_name()))),
        }
    }

    /// 发 `CommandLookupTopic` 并等待 `CommandLookupTopicResponse` 的**一跳**结果。
    ///
    /// # Errors
    /// 写失败、超时/EOF、broker 返回 `Failed`、或应答 `request_id` 不匹配。
    pub async fn lookup(&mut self, topic: &str, authoritative: bool) -> Result<LookupOutcome, PulsarError> {
        let request_id = self.next_request_id();
        let lookup = CommandLookupTopic {
            topic: Some(topic.to_string()),
            request_id: Some(request_id),
            authoritative: Some(authoritative),
        };
        self.write_command(&BaseCommand::lookup(lookup)).await?;
        let response = loop {
            let command = self.read_command().await?;
            match command.command_type() {
                command_type::LOOKUP_RESPONSE => break command.lookup_topic_response.clone().unwrap_or_default(),
                command_type::ERROR => {
                    let error = command.error.clone().unwrap_or_default();
                    PulsarNativeStats::bump(&self.stats.server_errors, 1);
                    return Err(PulsarError::Server {
                        error: error.server_error(),
                        message: error.message.clone().unwrap_or_default(),
                        request_id: error.request_id.unwrap_or(0),
                    });
                }
                command_type::PING => {
                    self.write_command(&BaseCommand::with_type(command_type::PONG)).await?;
                }
                other => {
                    return Err(PulsarError::Unsupported(format!(
                        "LOOKUP 等待期收到 {}",
                        base_command_type_name(other)
                    )));
                }
            }
        };
        if response.request_id.is_some_and(|got| got != request_id) {
            return Err(PulsarError::Unsupported(format!(
                "LOOKUP 应答 request_id 不匹配：期望 {request_id}，收到 {:?}",
                response.request_id
            )));
        }
        match response.lookup_type() {
            lookup_type::CONNECT => Ok(LookupOutcome::ConnectHere),
            lookup_type::REDIRECT => {
                let url = response.best_broker_url().map(ToString::to_string);
                match url {
                    Some(url) => {
                        Ok(LookupOutcome::Redirect { url, authoritative: response.authoritative.unwrap_or(false) })
                    }
                    None => Err(PulsarError::Unsupported("LOOKUP 要求重定向但没给 broker URL".to_string())),
                }
            }
            other => Err(PulsarError::Server {
                error: ServerError::from_code(response.error.unwrap_or(6)),
                message: response.message.clone().unwrap_or_else(|| format!("LOOKUP Failed（response={other}）")),
                request_id: response.request_id.unwrap_or(0),
            }),
        }
    }

    /// 发 `CommandSubscribe` 并等待 `CommandSuccess`。
    ///
    /// # Errors
    /// 写失败、超时/EOF、broker 返回 `CommandError`、或收到的应答 `request_id` 不匹配。
    pub async fn subscribe(&mut self, config: &PulsarNativeConfig) -> Result<u64, PulsarError> {
        let consumer_id = self.next_request_id();
        let request_id = self.next_request_id();
        let subscribe = CommandSubscribe {
            topic: Some(config.topic.clone()),
            subscription: Some(config.subscription.clone()),
            // `Exclusive = 0` 是合法且必须显式写出的 proto2 required 字段
            sub_type: Some(config.subscription_type.as_i32()),
            consumer_id: Some(consumer_id),
            request_id: Some(request_id),
            consumer_name: None,
            durable: Some(true),
            metadata: Vec::new(),
            read_compacted: Some(false),
            // **不声明 schema**（`None`）：真机上给一个已有 schema 的 topic（例如 CLI 默认的
            // `bytes`）发 `Schema{type=NONE}` 会被 broker 拒绝：
            //   `Failed to add schema to an active topic with empty(BYTES) schema: new schema type NONE`
            // 官方 Java 客户端的 `Schema.BYTES` 本来就不携带 schema（`getSchemaInfo() == null`），
            // 因此"不发 schema 字段"才与官方行为一致（测试 `subscribe_frame_carries_no_schema` 钉死）。
            schema: None,
            initial_position: Some(config.initial_position.as_i32()),
            force_topic_creation: Some(true),
        };
        self.write_command(&BaseCommand::subscribe(subscribe)).await?;
        // 订阅应答只可能有一条：`Subscribed` / `Error` / `CloseConsumer`，三条都直接返回
        match self.read_event().await? {
            ClientEvent::Subscribed { request_id: got } => {
                if got != request_id {
                    return Err(PulsarError::Unsupported(format!(
                        "订阅应答 request_id 不匹配：期望 {request_id}，收到 {got}"
                    )));
                }
                self.consumer_id = consumer_id;
                Ok(consumer_id)
            }
            ClientEvent::Error { error, message, request_id: got } => {
                Err(PulsarError::Server { error, message, request_id: got })
            }
            ClientEvent::CloseConsumer { assigned_broker } => Err(PulsarError::ConsumerClosed { assigned_broker }),
            other => {
                // 订阅等待期收到消息/其它命令：如实报错（正常 broker 不会这样）
                Err(PulsarError::Unsupported(format!("订阅等待期收到意外事件：{other:?}")))
            }
        }
    }

    /// 发 `CommandFlow`（增量许可）。
    ///
    /// # Errors
    /// 写失败。
    pub async fn send_flow(&mut self, permits: u32) -> Result<(), PulsarError> {
        if permits == 0 {
            return Ok(());
        }
        let flow = CommandFlow { consumer_id: Some(self.consumer_id), message_permits: Some(permits) };
        self.write_command(&BaseCommand::flow(flow)).await?;
        PulsarNativeStats::bump(&self.stats.permits, u64::from(permits));
        Ok(())
    }

    /// 发 `CommandAck`（**真的写到线路上**；不是空实现）。
    ///
    /// `message_ids` 为空 ⇒ 直接返回（不发空 ack，broker 会当成协议错）。
    ///
    /// # Errors
    /// 写失败。
    pub async fn send_ack(
        &mut self,
        ack_type: i32,
        message_ids: &[MessageIdData],
        validation_error: Option<i32>,
    ) -> Result<(), PulsarError> {
        if message_ids.is_empty() && validation_error.is_none() {
            return Ok(());
        }
        let ack = CommandAck {
            consumer_id: Some(self.consumer_id),
            ack_type: Some(ack_type),
            message_id: message_ids.to_vec(),
            validation_error,
        };
        self.write_command(&BaseCommand::ack(ack)).await?;
        PulsarNativeStats::bump(&self.stats.acks, message_ids.len() as u64);
        Ok(())
    }

    /// 发一个空命令（PING）。
    ///
    /// # Errors
    /// 写失败。
    pub async fn send_ping(&mut self) -> Result<(), PulsarError> {
        self.write_command(&BaseCommand::with_type(command_type::PING)).await
    }

    /// 写一帧命令（长度前缀 + `BaseCommand`）。
    async fn write_command(&mut self, command: &BaseCommand) -> Result<(), PulsarError> {
        let bytes = frame::encode_command_frame(command);
        self.stream.write_all(&bytes).await.map_err(|e| PulsarError::Io(format!("写命令失败：{e}")))?;
        self.stream.flush().await.map_err(|e| PulsarError::Io(format!("flush 失败：{e}")))?;
        PulsarNativeStats::bump(&self.stats.bytes_out, bytes.len() as u64);
        Ok(())
    }

    /// 读一个事件（自动回 PONG 应答 broker 的 PING）。
    ///
    /// # Errors
    /// IO/EOF、帧解码失败（含 CRC32C 不匹配）、未处理命令。
    pub async fn read_event(&mut self) -> Result<ClientEvent, PulsarError> {
        loop {
            let command = self.read_command().await?;
            match command.command_type() {
                command_type::PING => {
                    self.write_command(&BaseCommand::with_type(command_type::PONG)).await?;
                }
                command_type::PONG => {}
                command_type::MESSAGE => {
                    // `read_command` 已把整帧解出来；消息分支由 `read_frame` 直接给出
                    return Err(PulsarError::Unsupported("MESSAGE 应经 read_message 取得".to_string()));
                }
                command_type::SUCCESS => {
                    let success: CommandSuccess = command.success.clone().unwrap_or_default();
                    return Ok(ClientEvent::Subscribed { request_id: success.request_id.unwrap_or(0) });
                }
                command_type::ERROR => {
                    let error = command.error.clone().unwrap_or_default();
                    PulsarNativeStats::bump(&self.stats.server_errors, 1);
                    return Ok(ClientEvent::Error {
                        error: error.server_error(),
                        message: error.message.clone().unwrap_or_default(),
                        request_id: error.request_id.unwrap_or(0),
                    });
                }
                command_type::CLOSE_CONSUMER => {
                    let close = command.close_consumer.clone().unwrap_or_default();
                    let assigned = close
                        .assigned_broker_service_url
                        .clone()
                        .or_else(|| close.assigned_broker_service_url_tls.clone())
                        .filter(|url| !url.is_empty());
                    return Ok(ClientEvent::CloseConsumer { assigned_broker: assigned });
                }
                command_type::REACHED_END_OF_TOPIC => return Ok(ClientEvent::ReachedEndOfTopic),
                command_type::ACTIVE_CONSUMER_CHANGE => {
                    let change = command.active_consumer_change.clone().unwrap_or_default();
                    return Ok(ClientEvent::ActiveConsumerChange { is_active: change.is_active.unwrap_or(false) });
                }
                other => {
                    return Err(PulsarError::Unsupported(format!("未处理的命令 {}（{other}）", command.type_name())));
                }
            }
        }
    }

    /// 读一个**消息**事件（供 receiver 主循环使用）。
    ///
    /// # Errors
    /// 同 [`Self::read_event`]。
    pub async fn read_message(&mut self) -> Result<ClientEvent, PulsarError> {
        loop {
            let frame_bytes = self.read_frame_bytes().await?;
            match frame::decode_frame(&frame_bytes).map_err(PulsarError::Frame)? {
                DecodedFrame::Command(command) => {
                    if command.command_type() == command_type::PING {
                        self.write_command(&BaseCommand::with_type(command_type::PONG)).await?;
                        continue;
                    }
                    if command.command_type() == command_type::PONG {
                        continue;
                    }
                    // 复用 interpret_command 的分支逻辑
                    return self.interpret_command(*command);
                }
                DecodedFrame::Message { command, metadata, payload, checksummed } => {
                    PulsarNativeStats::bump(&self.stats.frames, 1);
                    if checksummed {
                        PulsarNativeStats::bump(&self.stats.checksum_ok, 1);
                    }
                    return Ok(ClientEvent::Message { command, metadata, payload: payload.to_vec(), checksummed });
                }
            }
        }
    }

    /// 读一条命令（消息帧在这里被如实报错——它只在 [`Self::read_message`] 里处理）。
    async fn read_command(&mut self) -> Result<BaseCommand, PulsarError> {
        let bytes = self.read_frame_bytes().await?;
        match frame::decode_frame(&bytes).map_err(PulsarError::Frame)? {
            DecodedFrame::Command(command) => Ok(*command),
            DecodedFrame::Message { .. } => {
                // 握手/订阅等待期不应出现消息；如实报错而不是丢弃
                Err(PulsarError::Unsupported("命令等待期收到 MESSAGE 帧".to_string()))
            }
        }
    }

    /// 把一条非消息命令翻译成 [`ClientEvent`]（[`Self::read_message`] 内联用）。
    fn interpret_command(&self, command: BaseCommand) -> Result<ClientEvent, PulsarError> {
        match command.command_type() {
            command_type::SUCCESS => {
                let success = command.success.clone().unwrap_or_default();
                Ok(ClientEvent::Subscribed { request_id: success.request_id.unwrap_or(0) })
            }
            command_type::ERROR => {
                let error = command.error.clone().unwrap_or_default();
                PulsarNativeStats::bump(&self.stats.server_errors, 1);
                Ok(ClientEvent::Error {
                    error: error.server_error(),
                    message: error.message.clone().unwrap_or_default(),
                    request_id: error.request_id.unwrap_or(0),
                })
            }
            command_type::CLOSE_CONSUMER => {
                let close = command.close_consumer.clone().unwrap_or_default();
                let assigned = close
                    .assigned_broker_service_url
                    .clone()
                    .or_else(|| close.assigned_broker_service_url_tls.clone())
                    .filter(|url| !url.is_empty());
                Ok(ClientEvent::CloseConsumer { assigned_broker: assigned })
            }
            command_type::REACHED_END_OF_TOPIC => Ok(ClientEvent::ReachedEndOfTopic),
            command_type::ACTIVE_CONSUMER_CHANGE => {
                let change = command.active_consumer_change.clone().unwrap_or_default();
                Ok(ClientEvent::ActiveConsumerChange { is_active: change.is_active.unwrap_or(false) })
            }
            other => Err(PulsarError::Unsupported(format!("未处理的命令 {}（{other}）", command.type_name()))),
        }
    }

    /// 从流里读满一整帧（含 4 字节 `TOTAL_SIZE`）。
    async fn read_frame_bytes(&mut self) -> Result<Vec<u8>, PulsarError> {
        loop {
            if let Some(len) = frame::peek_frame_len(&self.buffer).map_err(PulsarError::Frame)? {
                let total = 4 + len;
                if self.buffer.len() >= total {
                    let frame = self.buffer.split_to(total);
                    PulsarNativeStats::bump(&self.stats.bytes_in, frame.len() as u64);
                    return Ok(frame.to_vec());
                }
            }
            let mut chunk = vec![0_u8; 32 * 1024];
            let read = self.stream.read(&mut chunk).await.map_err(|e| PulsarError::Io(format!("读失败：{e}")))?;
            if read == 0 {
                return Err(PulsarError::Disconnected);
            }
            self.buffer.extend_from_slice(&chunk[..read]);
        }
    }

    /// 消费信用是否将尽（应补发 FLOW）：剩余许可 < 一半。
    #[must_use]
    pub const fn should_replenish(remaining: u32, queue_size: u32) -> bool {
        remaining < queue_size / 2
    }
}

mod types;

pub use types::{ClientEvent, LookupOutcome, PulsarError, PulsarNativeStats, attempts_exhausted, backoff_delay};
