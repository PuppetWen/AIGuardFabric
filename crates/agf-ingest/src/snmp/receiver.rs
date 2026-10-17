//! SNMP Trap 接收器（UDP）：socket 绑定、datagram 接入、流水线投递与 `Receiver` 实现。

// ---------------------------------------------------------------------------
// 接收器
// ---------------------------------------------------------------------------

use super::*;

/// SNMP Trap 接收器（UDP）。
#[derive(Debug)]
pub struct SnmpTrapReceiver {
    pub(super) pipeline: Arc<IngestPipeline>,
    pub(super) source: LogSource,
    pub(super) listen: String,
    pub(super) community: Option<String>,
    pub(super) version: String,
    pub(super) usm: Option<UsmConfig>,
    pub(super) usm_stats: Arc<UsmStats>,
    pub(super) engine_clock: EngineClock,
    pub(super) max_datagram_bytes: usize,
    pub(super) counters: Arc<ReceiverCounters>,
}

impl SnmpTrapReceiver {
    /// 由日志源配置构造（`connection.listen` / `connection.headers`）。
    ///
    /// v3 的 USM 参数同样从 headers 读：`user` / `security-level` / `auth-protocol` / `auth-password`
    /// / `priv-protocol` / `priv-password`（后两项只在 `authPriv` 生效；缺省 `priv-protocol=aes`）。
    ///
    /// # Errors
    /// 版本不受支持，或 v3 配置非法（`authPriv` 缺隐私口令 / 口令过短 / 隐私协议非法）。
    pub fn from_source(pipeline: Arc<IngestPipeline>, source: &LogSource) -> DomainResult<Self> {
        let listen = source.connection.listen.clone().unwrap_or_else(|| "0.0.0.0:1162".to_string());
        let community = source.connection.headers.get("community").cloned().unwrap_or_else(|| "public".to_string());
        let version = source.connection.headers.get("version").cloned().unwrap_or_else(|| "v2c".to_string());
        let receiver = Self::new(pipeline, source.clone(), &listen, community, version)?;
        if receiver.version != "v3" {
            return Ok(receiver);
        }
        let header = |key: &str| source.connection.headers.get(key).cloned().filter(|v| !v.trim().is_empty());
        let level = header("security-level").as_deref().and_then(V3SecurityLevel::parse).unwrap_or_default();
        let protocol = header("auth-protocol").as_deref().and_then(AuthProtocol::parse).unwrap_or_default();
        // 隐私协议：未配置 ⇒ 默认 AES（与 `PrivProtocol::default()` 一致）；配了非法值 ⇒ 显式报错
        // （不静默退回 AES：安全参数写错必须让人看见，否则会一路解密失败）
        let priv_protocol = match header("priv-protocol") {
            Some(text) => PrivProtocol::parse(&text).ok_or_else(|| {
                DomainError::Config(format!(
                    "SNMP v3 隐私协议 {text:?} 不受支持（AGF_INGEST_SNMP_V3_PRIV_PROTOCOL：aes / des）"
                ))
            })?,
            None => PrivProtocol::default(),
        };
        let usm = UsmConfig::from_parts(
            header("user"),
            level,
            protocol,
            header("auth-password"),
            priv_protocol,
            header("priv-password"),
        )?;
        Ok(receiver.with_usm(usm))
    }

    /// 显式构造。
    ///
    /// # Errors
    /// 版本不受支持（支持 `v1` / `v2c` / `v3`；v3 默认 `noAuthNoPriv`，
    /// 需要认证时用 [`Self::with_usm`]）。
    pub fn new(
        pipeline: Arc<IngestPipeline>,
        source: LogSource,
        listen: &str,
        community: impl Into<String>,
        version: impl Into<String>,
    ) -> DomainResult<Self> {
        let version = version.into();
        let normalized = version.trim().to_ascii_lowercase();
        let version = match normalized.as_str() {
            "v1" | "1" => "v1",
            "v2c" | "2c" => "v2c",
            "v3" | "3" => "v3",
            _ => return Err(DomainError::Config(format!("SNMP 版本 {version} 不受支持（支持 v1 / v2c / v3）"))),
        };
        // v3 不带 community：community 字段只对 v1/v2c 有意义
        let community = if version == "v3" { None } else { Some(community.into()) };
        // USM 计数器在构造时就登记进进程级槽位（[`usm_prometheus`] 只读它）：
        // `/metrics` 与接收器**共用同一个计数器实例**，未配置 SNMP 时该族以全零序列呈现。
        let usm_stats = Arc::new(UsmStats::new());
        register_process_usm_stats(&usm_stats);
        Ok(Self {
            pipeline,
            source,
            listen: listen.to_string(),
            community,
            version: version.to_string(),
            usm: if version == "v3" { Some(UsmConfig::no_auth()) } else { None },
            usm_stats,
            engine_clock: EngineClock::new(),
            max_datagram_bytes: 65_535,
            counters: Arc::new(ReceiverCounters::new()),
        })
    }

    /// 注入 v3 USM 配置（仅 `v3` 生效）。
    #[must_use]
    pub fn with_usm(mut self, usm: UsmConfig) -> Self {
        self.usm = Some(usm);
        self
    }

    /// 当前 v3 USM 配置。
    #[must_use]
    pub fn usm_config(&self) -> Option<&UsmConfig> {
        self.usm.as_ref()
    }

    /// v3 `usmStats` 计数器（认证失败分类计数）。
    #[must_use]
    pub fn usm_stats(&self) -> &Arc<UsmStats> {
        &self.usm_stats
    }

    /// 注入共享计数器。
    #[must_use]
    pub fn with_counters(mut self, counters: Arc<ReceiverCounters>) -> Self {
        self.counters = counters;
        self
    }

    /// 关闭 community 校验（仅限受信内网；默认开启）。
    #[must_use]
    pub fn without_community_check(mut self) -> Self {
        self.community = None;
        self
    }

    /// 监听地址。
    #[must_use]
    pub fn listen(&self) -> &str {
        &self.listen
    }

    /// 生效的 SNMP 版本。
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// 计数器。
    #[must_use]
    pub fn counters(&self) -> &Arc<ReceiverCounters> {
        &self.counters
    }

    /// 期望的 community。
    #[must_use]
    pub fn community(&self) -> Option<&str> {
        self.community.as_deref()
    }

    /// 绑定 UDP 套接字（由调用方决定失败时的降级策略）。
    ///
    /// # Errors
    /// 端口占用/权限不足/地址非法。
    pub async fn bind(&self) -> DomainResult<UdpSocket> {
        UdpSocket::bind(&self.listen).await.map_err(|e| DomainError::DependencyUnavailable {
            dependency: "snmp-trap".to_string(),
            cause: format!("绑定 {} 失败: {e}", self.listen),
        })
    }

    /// 接入一个 Trap 报文。
    ///
    /// # Errors
    /// 报文非法 / community 或 v3 摘要不匹配 / 落库失败。
    pub async fn ingest_datagram(&self, bytes: &[u8], origin: &str) -> DomainResult<usize> {
        self.counters.add_received(1);
        let usm = self.usm.as_ref().map(|config| (config, &self.engine_clock, self.usm_stats.as_ref()));
        let parsed = match parse_message(bytes, self.community.as_deref(), usm) {
            Ok(trap) => trap,
            Err(e) => {
                self.counters.add_dropped(1);
                return Err(e);
            }
        };
        let trap = SnmpTrap { source: origin.to_string(), ..parsed };
        let outcomes = self
            .pipeline
            .ingest_batch(&self.source, IngestProtocol::SnmpTrap, &[(trap.to_payload(), origin.to_string())])
            .await?;
        self.counters.record_outcomes(&outcomes);
        let persisted = outcomes.iter().filter(|o| o.persisted).count();
        debug!(
            origin,
            version = %trap.version,
            security_level = ?trap.security_level,
            oid = ?trap.trap_oid(),
            persisted,
            "SNMP Trap 已接入"
        );
        Ok(persisted)
    }

    /// 在已绑定的套接字上长跑（UDP 无连接；解码失败只 warn + 计数）。
    ///
    /// # Errors
    /// 接收系统调用发生**非超时**错误时返回。
    pub async fn serve(&self, socket: UdpSocket) -> DomainResult<()> {
        let mut buf = vec![0_u8; self.max_datagram_bytes];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, peer)) => {
                    let origin = peer.to_string();
                    if let Err(e) = self.ingest_datagram(buf.get(..len).unwrap_or_default(), &origin).await {
                        warn!(%origin, error = %e, "SNMP Trap 被拒绝/丢弃（已计数）");
                    }
                }
                Err(e) => {
                    warn!(error = %e, "SNMP Trap 接收异常（监听继续）");
                }
            }
        }
    }
}

#[async_trait]
impl Receiver for SnmpTrapReceiver {
    fn protocol(&self) -> IngestProtocol {
        IngestProtocol::SnmpTrap
    }

    fn describe(&self) -> ReceiverDescriptor {
        let v3_detail = self.usm.as_ref().map(|usm| format!("；USM {}", usm.describe())).unwrap_or_default();
        ReceiverDescriptor {
            name: "snmp-trap".to_string(),
            protocol: IngestProtocol::SnmpTrap,
            status: ReceiverStatus::Ready,
            note: format!(
                "UDP {} 收 SNMP {} Trap：v2c(0xa7)/Inform(0xa6)/v1(0xa4)/v3(USM) BER 解析；community 校验={}{v3_detail}；\
                 v3 authPriv 支持 CBC-DES(RFC3414 §8) 与 CFB128-AES-128(RFC3826 §3)；\
                 指标 agf_ingest_snmp_usm_*（认证/解密失败按 usmStats 分类计数）",
                self.listen,
                self.version,
                if self.community.is_some() { "开启" } else { "关闭" },
            ),
            todo: Some(
                "TODO ingest-snmp-inform-ack：Inform 只解析不回应答（Trap 语义不需要）；\
                 GET/WALK 轮询不在本接收器（请用 HTTP Pull/JDBC）；\
                 SNMP v3 authPriv（DES/AES）**已实现**（见 agf_ingest::snmp::priv）"
                    .to_string(),
            ),
            mock_replay: false,
        }
    }

    async fn start(&self, _pipeline: Arc<IngestPipeline>, _source: LogSource) -> DomainResult<()> {
        let socket = self.bind().await?;
        self.serve(socket).await
    }

    async fn poll_once(&self, _pipeline: Arc<IngestPipeline>, _source: LogSource, _max: usize) -> DomainResult<usize> {
        Err(DomainError::NotImplemented(
            "SNMP Trap 为推送型（UDP）接收器，无轮询语义；请调用 serve/ingest_datagram".to_string(),
        ))
    }
}
