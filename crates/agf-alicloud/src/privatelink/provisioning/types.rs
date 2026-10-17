use agf_core::ids::Id;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// 创建目标：只使用已存在且明确选择的 VPC、服务、交换机和安全组。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateEndpoint {
    pub region_id: String,
    pub service_region_id: String,
    pub service_id: String,
    pub vpc_id: String,
    pub name: String,
    pub zones: Vec<Zone>,
    pub security_group_ids: Vec<String>,
    /// 跨地域必须明确带宽；同地域不得混用跨地域参数。
    pub cross_region_bandwidth: Option<u32>,
}

/// 每个选定可用区只使用一个已有交换机；不自动选择默认网络。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Zone {
    pub zone_id: String,
    pub vswitch_id: String,
}

/// 服务提供方单独确认连接。不得沿用消费方凭据自动接受。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptConnection {
    pub region_id: String,
    pub service_id: String,
    pub endpoint_id: String,
}

/// 不可变请求计划。敏感来源凭据不进入参数或 Debug。
#[derive(Clone, PartialEq, Eq)]
pub struct PreparedChange {
    pub(crate) action: &'static str,
    pub(crate) input: Value,
    pub(crate) endpoint_id: Option<String>,
}

impl std::fmt::Debug for PreparedChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateLinkPreparedChange").field("action", &self.action).finish_non_exhaustive()
    }
}

impl PreparedChange {
    /// 官方动作名，供调用层封存意图与原 UUID。
    #[must_use]
    pub const fn action(&self) -> &'static str {
        self.action
    }

    /// 精确非凭据参数；仅封存于调用层租户 AEAD 状态。
    #[must_use]
    pub fn input(&self) -> &Value {
        &self.input
    }
}

/// 仅表示厂商 ACK；不表示创建完成、连接完成、DNS/TCP/TLS 或业务认证成功。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WriteStatus {
    Acknowledged,
    Rejected,
    Unknown,
}

/// 已进入一次传输后的安全事实，即使撤权或超时仍交回调用层封存。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteEvidence {
    pub attempted: bool,
    pub status: WriteStatus,
    pub provider_request_id: Option<Id>,
    pub endpoint_id: Option<String>,
    pub authority_current: bool,
    pub original_deadline_current: bool,
}
