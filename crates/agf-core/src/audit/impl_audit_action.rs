//! 由 `audit.rs` 拆分：`impl_AuditAction`/`impl_AuditOutcome` 等 10 项（纯搬移，逻辑不变）。
use super::*;

use crate::ids::{TenantId, TenantScoped};
use crate::time::Timestamp;

impl AuditAction {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Logout => "logout",
            Self::Create => "create",
            Self::Read => "read",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::Export => "export",
            Self::Execute => "execute",
            Self::Configure => "configure",
            Self::Grant => "grant",
            Self::Approve => "approve",
            Self::Contain => "contain",
            Self::System => "system",
        }
    }

    /// 是否属于高敏感动作（必须实时告警）。
    #[must_use]
    pub const fn is_sensitive(&self) -> bool {
        matches!(self, Self::Grant | Self::Export | Self::Contain | Self::Configure)
    }
}

impl AuditOutcome {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Denied => "denied",
        }
    }
}

impl AuditTarget {
    /// 构造目标。
    #[must_use]
    pub fn new(kind: impl Into<String>, id: Option<String>, name: Option<String>) -> Self {
        Self { kind: kind.into(), id, name }
    }
}

impl AuditActor {
    /// 系统自身（定时任务、迁移）。
    #[must_use]
    pub fn system(component: &str) -> Self {
        Self {
            id: None,
            kind: "service".to_string(),
            name: component.to_string(),
            source_ip: None,
            user_agent: None,
            session_id: None,
        }
    }
}

impl TenantScoped for AuditLog {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

impl AuditLog {
    /// 计算本条哈希。
    ///
    /// 规范化载荷包含：租户、序号、动作、结果、操作者、目标、前后快照、时间（RFC3339）。
    /// **注意**：计算只依赖不可变字段，重算必须与写入时完全一致，否则链校验失败。
    #[must_use]
    pub fn compute_hash(&self) -> String {
        let canonical = serde_json::json!({
            "tenant_id": self.tenant_id.to_string(),
            "sequence": self.sequence,
            "action": self.action.as_str(),
            "outcome": self.outcome.as_str(),
            "actor_kind": self.actor.kind,
            "actor_name": self.actor.name,
            "actor_source_ip": self.actor.source_ip,
            "target_kind": self.target.kind,
            "target_id": self.target.id,
            "before": self.before,
            "after": self.after,
            "changed_fields": self.changed_fields,
            "error": self.error,
            "note": self.note,
            "request_id": self.request_id,
            "at": self.at.to_rfc3339(),
            "prev_hash": self.prev_hash,
        });
        crate::secret::content_hash(&serde_json::to_string(&canonical).unwrap_or_default())
    }

    /// 依据当前字段重算并写入 `entry_hash`。
    pub fn seal(&mut self) {
        self.entry_hash = self.compute_hash();
    }

    /// 校验本条记录的哈希是否与内容一致。
    #[must_use]
    pub fn verify(&self) -> bool {
        self.compute_hash() == self.entry_hash
    }
}

/// 校验一条审计链（按 `sequence` 升序传入）。
///
/// 返回的问题类型：
/// - `hash_mismatch`：记录内容被改动；
/// - `prev_gap`：`prev_hash` 与上一条 `entry_hash` 不一致（删除/插入记录）；
/// - `sequence_gap`：序号不连续。
#[must_use]
pub fn verify_chain(entries: &[AuditLog]) -> ChainVerification {
    let mut verifier = ChainVerifier::new();
    for entry in entries {
        verifier.push(entry);
    }
    verifier.finish()
}

/// Incremental verification keeps only the prior hash while a database chain is paged.
#[derive(Debug)]
pub struct ChainVerifier {
    previous: Option<(i64, String)>,
    report: ChainVerification,
}

impl Default for ChainVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl ChainVerifier {
    /// Start a verifier at the genesis link.
    #[must_use]
    pub fn new() -> Self {
        Self { previous: None, report: ChainVerification { passed: true, ..ChainVerification::default() } }
    }

    fn flag(&mut self, entry: &AuditLog, kind: &str, detail: String) {
        self.report.passed = false;
        if self.report.violations.len() < 1_000 {
            self.report.violations.push(ChainViolation {
                entry_id: entry.id,
                sequence: entry.sequence,
                kind: kind.into(),
                detail,
            });
        }
    }

    /// Check the next entry without retaining its full payload.
    pub fn push(&mut self, entry: &AuditLog) {
        if self.previous.is_none() {
            self.report.first_sequence = Some(entry.sequence);
            if entry.sequence != 1 {
                self.flag(entry, "sequence_gap", format!("审计链从序号 {} 开始，而非 1", entry.sequence));
            }
            if entry.prev_hash != GENESIS_HASH {
                self.flag(entry, "prev_gap", "审计链首条记录未连接创世哈希".into());
            }
        }
        if !entry.verify() {
            self.flag(entry, "hash_mismatch", format!("序号 {} 的内容哈希与记录不一致，疑似被篡改", entry.sequence));
        }
        if let Some((sequence, hash)) = self.previous.as_ref() {
            let sequence = *sequence;
            if entry.prev_hash != *hash {
                self.flag(
                    entry,
                    "prev_gap",
                    format!("序号 {} 的 prev_hash 与序号 {} 不衔接", entry.sequence, sequence),
                );
            }
            if entry.sequence != sequence.saturating_add(1) {
                self.flag(entry, "sequence_gap", format!("序号从 {} 跳到 {}，存在缺失记录", sequence, entry.sequence));
            }
        }
        self.report.checked = self.report.checked.saturating_add(1);
        self.report.last_sequence = Some(entry.sequence);
        self.previous = Some((entry.sequence, entry.entry_hash.clone()));
    }

    /// Return the accumulated verdict and verification timestamp.
    #[must_use]
    pub fn finish(mut self) -> ChainVerification {
        self.report.verified_at = Some(Timestamp::now());
        self.report
    }
}

impl TenantScoped for AuditChainAnchor {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

impl AuditChainAnchor {
    /// 签名的规范化载荷（签名方与校验方必须使用同一函数）。
    #[must_use]
    pub fn signing_payload(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}",
            self.tenant_id,
            self.up_to_sequence,
            self.tail_hash,
            self.entry_count,
            self.created_at.to_rfc3339()
        )
    }
}

impl AuditQuery {
    /// 判断一条记录是否匹配。
    #[must_use]
    pub fn matches(&self, e: &AuditLog) -> bool {
        if !self.actions.is_empty() && !self.actions.contains(&e.action) {
            return false;
        }
        if !self.outcomes.is_empty() && !self.outcomes.contains(&e.outcome) {
            return false;
        }
        if let Some(a) = &self.actor {
            if !e.actor.name.to_lowercase().contains(&a.to_lowercase()) {
                return false;
            }
        }
        if let Some(k) = &self.target_kind {
            if &e.target.kind != k {
                return false;
            }
        }
        if let Some(from) = self.from {
            if e.at.as_datetime() < from.as_datetime() {
                return false;
            }
        }
        if let Some(to) = self.to {
            if e.at.as_datetime() > to.as_datetime() {
                return false;
            }
        }
        if self.sensitive_only && !e.action.is_sensitive() {
            return false;
        }
        true
    }
}
