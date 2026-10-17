//! 风险发现（finding）与证据模型（§4.2）。
//!
//! 设计要点：
//! - 每条 finding 必须能回答"**基于什么证据**"，因此 `evidence_refs` 不可为空（除纯配置类问题）。
//! - `evidence_level` 四档（unknown/partial/confirmed/impact）决定 finding 能否进最终报告。
//! - 渗透/攻防语义的"对照三件套"（baseline/diff_evidence/marker_echo）作为可空字段保留，
//!   由 `agf-scan` 在验证阶段填充。

use serde::{Deserialize, Serialize};

use crate::enums::{EvidenceLevel, RiskDomain, Severity, Verdict};
use crate::ids::{Id, TenantId, TenantScoped};
use crate::time::Timestamp;

/// finding 状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingState {
    /// 待复核。
    Pending,
    /// 已代码/规则复核。
    CodeReviewed,
    /// 已验证且可复现。
    Verified,
    /// 误报。
    FalsePositive,
    /// 已修复（复测不成立）。
    Fixed,
}

impl FindingState {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::CodeReviewed => "code-reviewed",
            Self::Verified => "verified",
            Self::FalsePositive => "false-positive",
            Self::Fixed => "fixed",
        }
    }

    /// 是否可进入最终报告。
    #[must_use]
    pub const fn reportable(&self) -> bool {
        matches!(self, Self::Verified | Self::Fixed)
    }
}

/// 审计形态（代审语义；渗透场景为 `None`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditMode {
    /// 静态（无本地复现环境/未复现生效）。
    Static,
    /// 动态（本地环境真实复现生效）。
    Dynamic,
}

impl AuditMode {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::Dynamic => "dynamic",
        }
    }
}

/// 证据条目。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// 证据编号（形如 `EV-0001`，报告引用用）。
    pub code: String,
    /// 证据类型（`log` / `http` / `file` / `tool-output` / `model-output` / `screenshot` / `diff`）。
    pub kind: String,
    /// 摘要。
    pub summary: String,
    /// 内容哈希（SHA-256 hex；用于防篡改与去重）。
    pub content_hash: String,
    /// 对象存储 key 或本地路径（原始载荷保真存储）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_ref: Option<String>,
    /// 采集时间。
    pub collected_at: Timestamp,
}

impl Evidence {
    /// 构造证据条目。
    #[must_use]
    pub fn new(
        code: impl Into<String>,
        kind: impl Into<String>,
        summary: impl Into<String>,
        hash: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            kind: kind.into(),
            summary: summary.into(),
            content_hash: hash.into(),
            artifact_ref: None,
            collected_at: Timestamp::now(),
        }
    }
}

/// 风险发现。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 标题（简短）。
    pub title: String,
    /// 严重等级。
    pub severity: Severity,
    /// 所属安全域。
    pub domain: RiskDomain,
    /// 分类标签（CWE / 战果类型 / 产物类型，按模式词表）。
    pub category: String,
    /// CWE 编号（可选）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwe: Option<String>,
    /// CVSS 向量。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss: Option<String>,
    /// 目标（地址/资产/文件位置）。
    pub target: String,
    /// 关联资产 id。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset_id: Option<Id>,
    /// 一句话简介。
    pub summary: String,
    /// 详细描述（影响与成因）。
    #[serde(default)]
    pub description: String,
    /// 复现步骤 / PoC（复杂时指向 `exp/<id>.py`）。
    #[serde(default)]
    pub poc: String,
    /// 修复建议（每条 finding 必填）。
    pub fix: String,
    /// 修复 diff 建议。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patch: Option<String>,
    /// 状态。
    pub state: FindingState,
    /// 证据等级。
    pub evidence_level: EvidenceLevel,
    /// 证据引用编号。
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    /// 证据明细。
    #[serde(default)]
    pub evidence: Vec<Evidence>,
    /// 命中的规则 id 列表。
    #[serde(default)]
    pub rule_ids: Vec<Id>,
    /// 命中规则的稳定键（便于跨版本聚合）。
    #[serde(default)]
    pub rule_keys: Vec<String>,
    /// LLM 二次研判结论。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm_verdict: Option<LlmJudgement>,
    /// 置信度（0.0-1.0，规则与模型融合后的最终值）。
    pub confidence: f32,
    /// 来源：`manual` / `scan-confirmed` / `scan-false-positive`。
    pub source_origin: String,
    /// 审计形态。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_mode: Option<AuditMode>,
    /// 调用链（审计双链之一：entry → sink，每行一链）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain: Option<String>,
    /// 追踪员独立重追的链。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_tracer: Option<String>,
    /// 双链结论（`consistent` / `inconsistent:...`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_verdict: Option<String>,
    /// 三件套：基线。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline: Option<String>,
    /// 三件套：差分。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff_evidence: Option<String>,
    /// 三件套：marker 回显。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub marker_echo: Option<String>,
    /// 完整请求包。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_pkt: Option<String>,
    /// 关键响应。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_pkt: Option<String>,
    /// 影响证明。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impact: Option<String>,
    /// 复核注记。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify_note: Option<String>,
    /// 复测注记。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retest_note: Option<String>,
    /// 首次发现时间。
    pub first_seen_at: Timestamp,
    /// 最近发现时间。
    pub last_seen_at: Timestamp,
    /// 创建时间。
    pub created_at: Timestamp,
    /// 更新时间。
    pub updated_at: Timestamp,
    /// 软删除。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<Timestamp>,
}

impl TenantScoped for Finding {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

impl Finding {
    /// 构造一条待复核 finding（必填字段最小集）。
    #[must_use]
    pub fn new(
        tenant_id: TenantId,
        domain: RiskDomain,
        severity: Severity,
        target: impl Into<String>,
        title: impl Into<String>,
        summary: impl Into<String>,
        fix: impl Into<String>,
    ) -> Self {
        let now = Timestamp::now();
        Self {
            id: Id::new(),
            tenant_id,
            title: title.into(),
            severity,
            domain,
            category: String::new(),
            cwe: None,
            cvss: None,
            target: target.into(),
            asset_id: None,
            summary: summary.into(),
            description: String::new(),
            poc: String::new(),
            fix: fix.into(),
            patch: None,
            state: FindingState::Pending,
            evidence_level: EvidenceLevel::Unknown,
            evidence_refs: Vec::new(),
            evidence: Vec::new(),
            rule_ids: Vec::new(),
            rule_keys: Vec::new(),
            llm_verdict: None,
            confidence: 0.0,
            source_origin: "manual".to_string(),
            audit_mode: None,
            chain: None,
            chain_tracer: None,
            chain_verdict: None,
            baseline: None,
            diff_evidence: None,
            marker_echo: None,
            request_pkt: None,
            response_pkt: None,
            impact: None,
            verify_note: None,
            retest_note: None,
            first_seen_at: now,
            last_seen_at: now,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        }
    }

    /// 是否具备"可进报告"的证据强度。
    ///
    /// 规则：`Verified`/`Fixed` 状态 + 至少一条证据 + 证据等级不低于 `Partial`。
    #[must_use]
    pub fn is_report_ready(&self) -> bool {
        self.state.reportable() && !self.evidence.is_empty() && self.evidence_level >= EvidenceLevel::Partial
    }

    /// 风险分（等级权重 × 置信度，用于排序）。
    #[must_use]
    pub fn risk_points(&self) -> f32 {
        f32::from(self.severity.weight()) * self.confidence.clamp(0.0, 1.0)
    }

    /// 三件套是否齐全（渗透/攻防"可复现"判定）。
    #[must_use]
    pub fn has_three_piece_evidence(&self) -> bool {
        self.baseline.is_some() && self.diff_evidence.is_some() && self.marker_echo.is_some()
    }

    /// 双链是否一致。
    #[must_use]
    pub fn chains_consistent(&self) -> bool {
        self.chain_verdict.as_deref().is_some_and(|v| v.starts_with("consistent"))
    }
}

/// LLM 二次研判结论（置信度 + 证据链）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmJudgement {
    /// 判定。
    pub verdict: Verdict,
    /// 置信度（0.0-1.0）。
    pub confidence: f32,
    /// 理由。
    pub rationale: String,
    /// 证据链（引用 finding 内的 evidence code）。
    #[serde(default)]
    pub cited_evidence: Vec<String>,
    /// 使用的模型端点。
    pub model: String,
    /// 是否走 Mock 模型。
    pub mocked: bool,
    /// 研判时间。
    pub judged_at: Timestamp,
    /// 原始响应摘要（保真排障）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_excerpt: Option<String>,
}

impl LlmJudgement {
    /// 是否达到"确认为恶意"的阈值（默认 0.7）。
    #[must_use]
    pub fn is_malicious(&self, threshold: f32) -> bool {
        matches!(self.verdict, Verdict::Malicious) && self.confidence >= threshold
    }
}

/// finding 与规则的融合（规则分 + 模型分）。
///
/// 融合策略公开可解释：`final = max(rule_score, llm_score) * (1 + 0.1 * (证据条数.min(3)))`，
/// 上限 1.0。规则明确命中时不因模型判"良性"而丢失（避免模型被绕过），
/// 但模型判良性会降低置信度（`-0.15`）以抑制噪声。
#[must_use]
pub fn fuse_confidence(rule_confidence: f32, judgement: Option<&LlmJudgement>) -> f32 {
    let mut score = rule_confidence.clamp(0.0, 1.0);
    if let Some(j) = judgement {
        let llm = j.confidence.clamp(0.0, 1.0);
        score = match j.verdict {
            Verdict::Malicious => score.max(llm),
            Verdict::Suspicious => score.max(llm * 0.8),
            Verdict::Benign => (score - 0.15).max(0.0),
            Verdict::Unknown => score,
        };
    }
    score.clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Finding {
        Finding::new(
            TenantId::default_tenant(),
            RiskDomain::PromptAttack,
            Severity::High,
            "claude-code@10.0.0.5",
            "系统提示词泄露",
            "通过角色扮演诱导模型输出系统提示词",
            "在系统提示中加入防护指令并启用输出侧检测",
        )
    }

    #[test]
    fn new_finding_defaults() {
        let f = sample();
        assert_eq!(f.state, FindingState::Pending);
        assert_eq!(f.evidence_level, EvidenceLevel::Unknown);
        assert!(!f.is_report_ready());
        assert_eq!(f.risk_points(), 0.0, "置信度为 0 时风险分为 0");
    }

    #[test]
    fn report_ready_requires_state_and_evidence() {
        let mut f = sample();
        f.evidence.push(Evidence::new("EV-0001", "log", "命中日志", "hash"));
        f.evidence_level = EvidenceLevel::Confirmed;
        assert!(!f.is_report_ready(), "状态仍为 pending");
        f.state = FindingState::Verified;
        assert!(f.is_report_ready());
        f.evidence.clear();
        assert!(!f.is_report_ready());
    }

    #[test]
    fn risk_points_scale_with_confidence() {
        let mut f = sample();
        f.confidence = 0.5;
        assert!((f.risk_points() - 4.0).abs() < f32::EPSILON);
        f.confidence = 5.0;
        assert!((f.risk_points() - 8.0).abs() < f32::EPSILON, "置信度会被 clamp");
    }

    #[test]
    fn three_piece_evidence_detection() {
        let mut f = sample();
        assert!(!f.has_three_piece_evidence());
        f.baseline = Some("base".into());
        f.diff_evidence = Some("diff".into());
        assert!(!f.has_three_piece_evidence());
        f.marker_echo = Some("AGF-MARKER-9f2a".into());
        assert!(f.has_three_piece_evidence());
    }

    #[test]
    fn chain_consistency() {
        let mut f = sample();
        assert!(!f.chains_consistent());
        f.chain_verdict = Some("consistent".into());
        assert!(f.chains_consistent());
        f.chain_verdict = Some("inconsistent: 缺少 entry 校验".into());
        assert!(!f.chains_consistent());
    }

    #[test]
    fn fusion_prefers_malicious_and_penalizes_benign() {
        let j_mal = LlmJudgement {
            verdict: Verdict::Malicious,
            confidence: 0.9,
            rationale: "明确越狱".into(),
            cited_evidence: vec![],
            model: "mock".into(),
            mocked: true,
            judged_at: Timestamp::now(),
            raw_excerpt: None,
        };
        assert!((fuse_confidence(0.6, Some(&j_mal)) - 0.9).abs() < 1e-6);

        let j_benign = LlmJudgement { verdict: Verdict::Benign, ..j_mal.clone() };
        assert!((fuse_confidence(0.6, Some(&j_benign)) - 0.45).abs() < 1e-6);

        let j_susp = LlmJudgement { verdict: Verdict::Suspicious, confidence: 0.5, ..j_mal };
        assert!((fuse_confidence(0.2, Some(&j_susp)) - 0.4).abs() < 1e-6);

        assert!((fuse_confidence(0.3, None) - 0.3).abs() < 1e-6);
    }

    #[test]
    fn fusion_never_exceeds_one() {
        let j = LlmJudgement {
            verdict: Verdict::Malicious,
            confidence: 1.5,
            rationale: String::new(),
            cited_evidence: vec![],
            model: "m".into(),
            mocked: true,
            judged_at: Timestamp::now(),
            raw_excerpt: None,
        };
        assert!(fuse_confidence(1.0, Some(&j)) <= 1.0);
    }

    #[test]
    fn malicious_threshold() {
        let j = LlmJudgement {
            verdict: Verdict::Malicious,
            confidence: 0.65,
            rationale: String::new(),
            cited_evidence: vec![],
            model: "m".into(),
            mocked: true,
            judged_at: Timestamp::now(),
            raw_excerpt: None,
        };
        assert!(!j.is_malicious(0.7));
        assert!(j.is_malicious(0.6));
    }

    #[test]
    fn state_reportable_matrix() {
        assert!(FindingState::Verified.reportable());
        assert!(FindingState::Fixed.reportable());
        assert!(!FindingState::Pending.reportable());
        assert!(!FindingState::FalsePositive.reportable());
        assert_eq!(FindingState::CodeReviewed.as_str(), "code-reviewed");
    }
}
