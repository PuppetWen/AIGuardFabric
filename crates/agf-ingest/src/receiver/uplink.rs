//! 采集器上行接收器：mTLS 指纹纯函数校验（`CollectorUplinkAuth`）与 AgentReport/原始日志信封解码。

use super::*;

/// 采集器上行鉴权（**纯函数**，便于单测与审计）。
#[derive(Debug, Clone, Copy)]
pub struct CollectorUplinkAuth;

impl CollectorUplinkAuth {
    /// 归一化证书指纹：去掉 `:` / 空格 / 连字符并转小写（SHA-256 hex 大小写不敏感）。
    #[must_use]
    pub fn normalize(fingerprint: &str) -> String {
        fingerprint.chars().filter(char::is_ascii_alphanumeric).map(|c| c.to_ascii_lowercase()).collect()
    }

    /// 指纹是否匹配（常量时间比较）。
    #[must_use]
    pub fn matches(presented: &str, registered: &str) -> bool {
        let a = Self::normalize(registered);
        let b = Self::normalize(presented);
        !a.is_empty() && constant_time_eq(a.as_bytes(), b.as_bytes())
    }

    /// 校验采集器上行是否可信：启用 + 指纹登记且一致 + 证书未过期。
    ///
    /// # Errors
    /// 未启用、未登记指纹、指纹不一致、证书过期。
    pub fn authorize(
        registration: &CollectorRegistration,
        presented_fingerprint: &str,
        now: Timestamp,
    ) -> DomainResult<()> {
        if !registration.enabled {
            return Err(DomainError::Forbidden(format!("采集器 {} 已停用", registration.collector_id)));
        }
        let Some(registered) = &registration.cert_fingerprint else {
            return Err(DomainError::Unauthenticated(format!(
                "采集器 {} 未登记证书指纹，拒绝上行（需先完成注册）",
                registration.collector_id
            )));
        };
        if !Self::matches(presented_fingerprint, registered) {
            return Err(DomainError::Unauthenticated(format!(
                "采集器 {} 证书指纹不匹配（presented={}…）",
                registration.collector_id,
                presented_fingerprint.chars().take(8).collect::<String>()
            )));
        }
        if let Some(expires) = registration.cert_expires_at {
            if expires.unix_secs() <= now.unix_secs() {
                return Err(DomainError::Unauthenticated(format!(
                    "采集器 {} 证书已于 {} 过期",
                    registration.collector_id,
                    expires.to_rfc3339()
                )));
            }
        }
        Ok(())
    }
}

/// 上行信封里的原始日志项。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UplinkRawLog {
    /// 原始载荷（base64；二进制安全）。
    pub payload_b64: String,
    /// 来源（文件路径/接口名）。
    #[serde(default)]
    pub origin: String,
    /// 协议文本（缺省按 `file` 处理）。
    #[serde(default)]
    pub protocol: Option<String>,
}

impl UplinkRawLog {
    /// 解码载荷。
    ///
    /// # Errors
    /// base64 非法。
    pub fn decode(&self) -> DomainResult<Vec<u8>> {
        B64.decode(&self.payload_b64).map_err(|e| DomainError::Parse(format!("上行原始日志 base64 非法: {e}")))
    }

    /// 协议（未知文本回退 `File`）。
    #[must_use]
    pub fn protocol(&self) -> IngestProtocol {
        self.protocol
            .as_deref()
            .and_then(|p| IngestProtocol::all().into_iter().find(|candidate| candidate.as_str() == p))
            .unwrap_or(IngestProtocol::File)
    }
}

/// 采集器上行信封（`agf-agent` → `agf-ingest`）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UplinkEnvelope {
    /// 采集器 id。
    pub collector_id: String,
    /// 客户端证书指纹（mTLS；由前置网关透传）。
    #[serde(default)]
    pub cert_fingerprint: Option<String>,
    /// Agent 资产上报。
    pub report: agf_core::agent::AgentReport,
    /// 原始日志批量（同一信封内混协议时按条判定）。
    #[serde(default)]
    pub raw_logs: Vec<UplinkRawLog>,
}

/// 上行接入结果。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UplinkIngestReport {
    /// 采集器 id。
    pub collector_id: String,
    /// Agent 上报条数（信封只带一份）。
    pub agent_reports: usize,
    /// 原始日志总条数。
    pub raw_logs: usize,
    /// 成功落库的事件数。
    pub events: usize,
    /// 去重丢弃数。
    pub deduped: usize,
    /// 被拒绝的条目数（base64 非法/超限等）。
    pub rejected: usize,
}

/// 解码 Agent 上报体。
///
/// # Errors
/// JSON 非法或字段缺失。
pub fn decode_agent_report(payload: &[u8]) -> DomainResult<agf_core::agent::AgentReport> {
    serde_json::from_slice(payload).map_err(|e| DomainError::Parse(format!("AgentReport JSON 非法: {e}")))
}

/// 解码采集器上行信封。
///
/// # Errors
/// JSON 非法或字段缺失。
pub fn decode_uplink(payload: &[u8]) -> DomainResult<UplinkEnvelope> {
    serde_json::from_slice(payload).map_err(|e| DomainError::Parse(format!("上行信封 JSON 非法: {e}")))
}

/// 南向采集器上行接收器（服务端接入路径）。
#[derive(Debug)]
pub struct UplinkReceiver {
    registration: CollectorRegistration,
    /// 是否强制校验指纹（默认 `true`；仅离线演示可关闭）。
    pub require_fingerprint: bool,
}

impl UplinkReceiver {
    /// 构造。
    #[must_use]
    pub const fn new(registration: CollectorRegistration) -> Self {
        Self { registration, require_fingerprint: true }
    }

    /// 注册信息。
    #[must_use]
    pub const fn registration(&self) -> &CollectorRegistration {
        &self.registration
    }

    /// 接入一份上行信封。
    ///
    /// # Errors
    /// 鉴权失败、原始日志解码失败或落库失败。
    pub async fn ingest_envelope(
        &self,
        envelope: &UplinkEnvelope,
        pipeline: &IngestPipeline,
        source: &LogSource,
    ) -> DomainResult<UplinkIngestReport> {
        if envelope.collector_id != self.registration.collector_id {
            return Err(DomainError::Forbidden(format!(
                "信封采集器 id {} 与注册的 {} 不一致",
                envelope.collector_id, self.registration.collector_id
            )));
        }
        if self.require_fingerprint {
            let presented = envelope.cert_fingerprint.clone().unwrap_or_default();
            CollectorUplinkAuth::authorize(&self.registration, &presented, Timestamp::now())?;
        }
        let mut by_protocol: BTreeMap<&'static str, (IngestProtocol, Vec<(Vec<u8>, String)>)> = BTreeMap::new();
        let mut rejected = 0_usize;
        for raw in &envelope.raw_logs {
            match raw.decode() {
                Ok(bytes) => {
                    let protocol = raw.protocol();
                    let origin =
                        if raw.origin.is_empty() { self.registration.collector_id.clone() } else { raw.origin.clone() };
                    by_protocol
                        .entry(protocol.as_str())
                        .or_insert_with(|| (protocol, Vec::new()))
                        .1
                        .push((bytes, origin));
                }
                Err(e) => {
                    warn!(error = %e, collector = %envelope.collector_id, "上行原始日志解码失败，已拒绝该条");
                    rejected += 1;
                }
            }
        }
        let mut events = 0_usize;
        let mut deduped = 0_usize;
        for (_, (protocol, items)) in by_protocol {
            let outcomes = pipeline.ingest_batch(source, protocol, &items).await?;
            events += outcomes.iter().filter(|o| o.persisted).count();
            deduped += outcomes.iter().filter(|o| o.deduped).count();
        }
        debug!(collector = %envelope.collector_id, events, rejected, "采集器上行已接入");
        Ok(UplinkIngestReport {
            collector_id: envelope.collector_id.clone(),
            agent_reports: 1,
            raw_logs: envelope.raw_logs.len(),
            events,
            deduped,
            rejected,
        })
    }

    /// 接入上行字节流（解码 + 鉴权 + 接入）。
    ///
    /// # Errors
    /// 解码失败或接入失败。
    pub async fn ingest_bytes(
        &self,
        payload: &[u8],
        served_fingerprint: Option<&str>,
        pipeline: &IngestPipeline,
        source: &LogSource,
    ) -> DomainResult<UplinkIngestReport> {
        let mut envelope = decode_uplink(payload)?;
        if envelope.cert_fingerprint.is_none() {
            // 由前置网关（mTLS 终结）透传的真实指纹优先于信封自述
            envelope.cert_fingerprint = served_fingerprint.map(ToString::to_string);
        }
        self.ingest_envelope(&envelope, pipeline, source).await
    }
}

#[async_trait]
impl Receiver for UplinkReceiver {
    fn protocol(&self) -> IngestProtocol {
        IngestProtocol::Mcp
    }

    fn describe(&self) -> ReceiverDescriptor {
        ReceiverDescriptor {
            name: "collector-uplink".to_string(),
            protocol: IngestProtocol::Mcp,
            status: ReceiverStatus::Ready,
            note: format!(
                "南向采集器上行：collector_id={}，mTLS 指纹校验={}",
                self.registration.collector_id,
                if self.require_fingerprint { "启用" } else { "关闭" }
            ),
            todo: None,
            mock_replay: false,
        }
    }

    async fn start(&self, _pipeline: Arc<IngestPipeline>, _source: LogSource) -> DomainResult<()> {
        // 上行走 HTTPS/mTLS（由 agf-api/agf-runtime 的网关托管），这里只提供解码与鉴权。
        Ok(())
    }

    async fn poll_once(&self, _pipeline: Arc<IngestPipeline>, _source: LogSource, _max: usize) -> DomainResult<usize> {
        Err(DomainError::NotImplemented("采集器上行为推送型，无轮询语义；请调用 ingest_bytes".to_string()))
    }
}
