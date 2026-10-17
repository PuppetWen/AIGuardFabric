//! 由 `domains.rs` 拆分：`DomainHit`/`DomainReport`/`DomainVerdict` 的实现（纯搬移，逻辑不变）。
use super::*;

impl DomainVerdict {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Malicious => "malicious",
            Self::Suspicious => "suspicious",
            Self::Benign => "benign",
        }
    }

    /// 是否值得登记 finding。
    #[must_use]
    pub const fn is_reportable(&self) -> bool {
        !matches!(self, Self::Benign)
    }

    /// 转为 `agf-core` 的判定枚举。
    #[must_use]
    pub const fn to_verdict(&self) -> agf_core::enums::Verdict {
        use agf_core::enums::Verdict;
        match self {
            Self::Malicious => Verdict::Malicious,
            Self::Suspicious => Verdict::Suspicious,
            Self::Benign => Verdict::Benign,
        }
    }
}

impl DomainHit {
    /// 构造。
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        key: impl Into<String>,
        title: impl Into<String>,
        domain: RiskDomain,
        severity: Severity,
        verdict: DomainVerdict,
        confidence: f32,
        detail: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self {
            key: key.into(),
            title: title.into(),
            domain,
            severity,
            verdict,
            confidence: confidence.clamp(0.0, 1.0),
            detail: detail.into(),
            evidence: Vec::new(),
            remediation: remediation.into(),
            asset_id: None,
        }
    }

    /// 追加证据。
    #[must_use]
    pub fn with_evidence(mut self, evidence: Vec<String>) -> Self {
        self.evidence = evidence;
        self
    }

    /// 转为 finding。
    #[must_use]
    pub fn to_finding(&self, tenant: TenantId, target: impl Into<String>) -> Finding {
        let mut f = Finding::new(
            tenant,
            self.domain,
            self.severity,
            target,
            self.title.clone(),
            self.detail.clone(),
            self.remediation.clone(),
        );
        f.category = self.key.clone();
        f.confidence = self.confidence;
        f.asset_id = self.asset_id;
        f.source_origin = "scan-confirmed".to_string();
        for (i, e) in self.evidence.iter().enumerate() {
            f.evidence.push(agf_core::risk::Evidence::new(
                format!("EV-{:04}", i + 1),
                "text",
                e.clone(),
                agf_core::secret::content_hash(e),
            ));
        }
        f.evidence_refs = f.evidence.iter().map(|e| e.code.clone()).collect();
        f
    }
}

impl DomainReport {
    /// 无命中的空报告。
    #[must_use]
    pub fn clean(domain: RiskDomain, checks: Vec<String>) -> Self {
        Self {
            domain,
            hits: Vec::new(),
            verdict: DomainVerdict::Benign,
            severity: Severity::Info,
            checks_run: checks,
            elapsed_micros: 0,
        }
    }

    /// 由检出列表构造。
    #[must_use]
    pub fn from_hits(domain: RiskDomain, hits: Vec<DomainHit>, checks: Vec<String>) -> Self {
        let verdict = if hits.iter().any(|h| h.verdict == DomainVerdict::Malicious) {
            DomainVerdict::Malicious
        } else if hits.iter().any(|h| h.verdict == DomainVerdict::Suspicious) {
            DomainVerdict::Suspicious
        } else {
            DomainVerdict::Benign
        };
        let severity = hits.iter().map(|h| h.severity).max().unwrap_or(Severity::Info);
        Self { domain, hits, verdict, severity, checks_run: checks, elapsed_micros: 0 }
    }

    /// 是否发现风险。
    #[must_use]
    pub fn has_hits(&self) -> bool {
        !self.hits.is_empty()
    }

    /// 转为 finding 列表。
    #[must_use]
    pub fn to_findings(&self, tenant: TenantId, target: &str) -> Vec<Finding> {
        self.hits.iter().map(|h| h.to_finding(tenant, target)).collect()
    }
}
