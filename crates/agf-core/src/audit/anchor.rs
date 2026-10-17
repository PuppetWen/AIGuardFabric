//! 平台签名的检查点绑定租户、审计链及可选的已认证 Agent。
use super::{AuditChainAnchor, AuditLog, GENESIS_HASH};
use crate::{
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// 由检查点保护、独立排序的审计链。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditChainKind {
    /// 平台管理审计，以已提交的 audit_logs 表为权威数据源。
    Management,
    /// Agent MCP 决策审计，以已认证的追加协议为权威数据源。
    AgentRuntime,
}
impl AuditChainKind {
    /// 纳入签名的稳定用途域名。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Management => "management",
            Self::AgentRuntime => "agent-runtime",
        }
    }
}

/// 带签名的身份封装；签名密钥仅由平台持有，绝不下发给 Agent。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAuditAnchor {
    /// 审计链用途，防止管理链与运行时链相互替用。
    pub kind: AuditChainKind,
    /// 持久化的审计链身份，进程重启后保持不变。
    pub chain_id: Id,
    /// 已认证的 Agent 资产，仅 AgentRuntime 必须提供。
    pub agent_id: Option<Id>,
    /// 前一个签名检查点的身份，仅首个检查点可以为空。
    pub previous_anchor_id: Option<Id>,
    /// 前一个签名封装的哈希，用于发现检查点被删除或重排。
    pub previous_anchor_hash: Option<String>,
    /// 既有审计检查点字段；签名认证整个封装。
    pub anchor: AuditChainAnchor,
}
impl SignedAuditAnchor {
    /// 带版本的规范消息，包含旧模型未纳入签名的身份字段。
    #[must_use]
    pub fn signing_payload(&self) -> String {
        format!(
            "agf.audit-anchor.v1|{}|{}|{}|{}|{}|{}|{}|{}",
            self.kind.as_str(),
            self.chain_id,
            self.agent_id.map_or_else(|| "-".into(), |id| id.to_string()),
            self.anchor.id,
            self.previous_anchor_id.map_or_else(|| "-".into(), |id| id.to_string()),
            self.previous_anchor_hash.as_deref().unwrap_or("-"),
            self.anchor.signing_payload(),
            self.anchor.created_at.as_datetime().to_rfc3339()
        )
    }

    /// 签名见证的哈希；Agent 在数据库之外保留该见证。
    #[must_use]
    pub fn witness_hash(&self) -> String {
        crate::secret::content_hash(&format!("{}|{}", self.signing_payload(), self.anchor.signature))
    }

    /// 使用签名前，校验结构与预期的已认证身份。
    ///
    /// # Errors
    /// 身份、计数器、哈希或前序字段无效。
    pub fn validate_identity(&self, tenant: TenantId, kind: AuditChainKind, agent: Option<Id>) -> DomainResult<()> {
        if self.anchor.tenant_id != tenant
            || self.kind != kind
            || self.agent_id != agent
            || self.chain_id.is_nil()
            || self.anchor.id.is_nil()
            || tenant.as_uuid().is_nil()
            || agent.is_some_and(|id| id.is_nil())
            || (kind == AuditChainKind::AgentRuntime) != agent.is_some()
            || self.anchor.up_to_sequence < 0
            || self.anchor.entry_count != self.anchor.up_to_sequence
            || !valid_hash(&self.anchor.tail_hash)
            || (self.anchor.entry_count == 0 && self.anchor.tail_hash != GENESIS_HASH)
            || self.previous_anchor_id.is_some() != self.previous_anchor_hash.is_some()
            || self.previous_anchor_id.is_some_and(|id| id.is_nil())
            || self.previous_anchor_hash.as_deref().is_some_and(|hash| !valid_hash(hash))
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// 检查与可信前序检查点之间的连续性。
    ///
    /// # Errors
    /// 前序检查点不匹配，或序号未递增。
    pub fn follows(&self, previous: Option<&Self>) -> DomainResult<()> {
        match previous {
            None if self.previous_anchor_id.is_none() && self.previous_anchor_hash.is_none() => Ok(()),
            Some(old)
                if self.chain_id == old.chain_id
                    && self.kind == old.kind
                    && self.agent_id == old.agent_id
                    && self.anchor.tenant_id == old.anchor.tenant_id
                    && self.previous_anchor_id == Some(old.anchor.id)
                    && self.previous_anchor_hash.as_deref() == Some(old.witness_hash().as_str())
                    && self.anchor.up_to_sequence > old.anchor.up_to_sequence =>
            {
                Ok(())
            }
            _ => Err(invalid()),
        }
    }
}

/// 有大小上限的 Agent 追加请求；身份仅来自认证结果。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentAuditBatch {
    /// 本地持久化的稳定审计链身份。
    pub chain_id: Id,
    /// 最近的平台签名见证，在重启及重试之间保留。
    pub previous: Option<SignedAuditAnchor>,
    /// 按连续递增序号排列的真实新决策；首次空请求用于初始化身份。
    pub entries: Vec<AuditLog>,
}

/// 签名确认及实际认证所得的身份。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentAuditAcknowledgement {
    /// 持久化签名检查点；离线 Mock 明确返回非持久化确认。
    pub checkpoint: SignedAuditAnchor,
    /// 仅在 PostgreSQL 事务已提交后为真。
    pub durable: bool,
    /// 仅当这些完全相同的记录已经提交过时为真。
    pub replayed: bool,
}

/// 依据已可信的前缀校验有界追加段，不重新封装输入来掩盖篡改。
///
/// # Errors
/// 记录的身份、哈希或序号无效，存在重复，或超过大小限制。
pub fn verify_agent_segment(
    entries: &[AuditLog],
    tenant: TenantId,
    agent: Id,
    after: i64,
    previous_hash: &str,
) -> DomainResult<(i64, String)> {
    if entries.len() > 256 || after < 0 || !valid_hash(previous_hash) {
        return Err(invalid());
    }
    let mut sequence = after;
    let mut tail = previous_hash.to_owned();
    let mut ids = BTreeSet::new();
    for entry in entries {
        sequence = sequence.checked_add(1).ok_or_else(invalid)?;
        if entry.tenant_id != tenant
            || entry.actor.id != Some(agent)
            || entry.actor.kind != "agent"
            || entry.id.is_nil()
            || !ids.insert(entry.id)
            || entry.sequence != sequence
            || entry.prev_hash != tail
            || !valid_hash(&entry.entry_hash)
            || !entry.verify()
            || serde_json::to_vec(entry)?.len() > 16 * 1024
        {
            return Err(invalid());
        }
        tail.clone_from(&entry.entry_hash);
    }
    Ok((sequence, tail))
}

/// 规范审计链记录使用严格的小写 SHA256 格式。
#[must_use]
pub fn valid_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn invalid() -> DomainError {
    DomainError::Crypto("Audit anchor identity, continuity or content is invalid".into())
}

#[cfg(test)]
mod tests;
