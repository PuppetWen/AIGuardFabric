//! 采集器上行的**请求体契约**（自 `agent.rs` 拆出，逻辑不变）。
//!
//! 兼容两种既有写法：`agf-ingest` 的 `UplinkEnvelope`（`collector_id` + `report` + `raw_logs`）
//! 与脚本/控制台常用的简写（`logs: [...]`）。**载荷本身不在这里解析**——这里只做"信封 →
//! 字节"的搬运，真正的解析与归一化交给 `agf-ingest` 流水线（见 `super::agent`）。

use agf_core::enums::IngestProtocol;
use agf_core::error::DomainError;

use crate::error::ApiError;

/// 上行信封（兼容既有 `agf-ingest` 的 `UplinkEnvelope` 与裸 `{logs:[...]}` 两种写法）。
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize, utoipa::ToSchema)]
pub struct AgentUplinkBody {
    /// 采集器 id（既有 `UplinkEnvelope` 契约）。
    #[serde(default)]
    pub collector_id: Option<String>,
    /// agent id（`agf-agent` 的 `AgentIdentity::agent_id`）。
    #[serde(default)]
    pub agent_id: Option<String>,
    /// 主机名（未提供时作为日志源名的一部分）。
    #[serde(default)]
    pub hostname: Option<String>,
    /// 单条原始文本（与 `logs` 二选一）。
    #[serde(default)]
    pub source: Option<String>,
    /// Agent 资产上报（`agf_core::agent::AgentReport`）。
    #[serde(default)]
    pub report: Option<serde_json::Value>,
    /// 终端扩展资产（模型端点与 Skill）；不包含凭据明文。
    #[serde(default)]
    pub extras: serde_json::Value,
    /// 原始日志批量。
    #[serde(default)]
    pub raw_logs: Vec<AgentUplinkItem>,
    /// 原始文本批量（控制台/脚本的简写形式）。
    #[serde(default)]
    pub logs: Vec<AgentUplinkItem>,
}

impl AgentUplinkBody {
    /// 采集器标识（响应/审计用）。
    #[must_use]
    pub fn collector_key(&self) -> Option<String> {
        self.collector_id.clone().or_else(|| self.agent_id.clone())
    }

    /// 日志源名（确定性：同一采集器恒定同一 source）。
    #[must_use]
    pub fn origin_label(&self) -> String {
        self.collector_key().unwrap_or_else(|| "agent-collector".to_string())
    }
}

/// 单条上行载荷。
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize, utoipa::ToSchema)]
pub struct AgentUplinkItem {
    /// 原始载荷（base64；二进制安全）。
    #[serde(default)]
    pub payload_b64: Option<String>,
    /// 明文载荷（与 `payload_b64` 二选一）。
    #[serde(default)]
    pub text: Option<String>,
    /// 来源（文件路径/接口名）。
    #[serde(default)]
    pub origin: Option<String>,
    /// 协议文本（缺省按 `mcp` 处理，与 `UplinkReceiver` 口径一致）。
    #[serde(default)]
    pub protocol: Option<String>,
}

impl AgentUplinkItem {
    /// 解码为字节。
    ///
    /// # Errors
    /// 两个载荷字段都缺失，或 base64 非法。
    pub fn decode(&self) -> Result<Vec<u8>, ApiError> {
        use base64::Engine as _;
        if let Some(text) = &self.text {
            return Ok(text.as_bytes().to_vec());
        }
        let Some(encoded) = &self.payload_b64 else {
            return Err(ApiError::new(DomainError::Validation("载荷项必须提供 payload_b64 或 text 之一".to_string())));
        };
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| ApiError::new(DomainError::Parse(format!("上行原始日志 base64 非法: {e}"))))
    }

    /// 协议（未知文本回退 `Mcp`，与既有 `UplinkReceiver` 一致）。
    #[must_use]
    pub fn protocol(&self) -> IngestProtocol {
        self.protocol
            .as_deref()
            .and_then(|p| IngestProtocol::all().into_iter().find(|candidate| candidate.as_str() == p))
            .unwrap_or(IngestProtocol::Mcp)
    }
}
