//! 将规则命中接到同一研判、发现、评分流程，保留逐目标证据。
use super::*;

pub(super) fn append(reports: &mut [DomainReport], rules: &[RuleHit]) {
    for report in reports {
        for rule in rules.iter().filter(|rule| rule.domain == report.domain) {
            let verdict = if rule.degraded { DomainVerdict::Suspicious } else { DomainVerdict::Malicious };
            report.hits.push(DomainHit::new(
                format!("rule:{}", rule.rule_key),
                rule.rule_name.clone(),
                rule.domain,
                rule.severity,
                verdict,
                rule.confidence,
                rule.note.clone(),
                rule.remediation.clone(),
            ));
            report.checks_run.push(format!("rule:{}", rule.rule_key));
        }
        let elapsed = report.elapsed_micros;
        *report = DomainReport::from_hits(
            report.domain,
            std::mem::take(&mut report.hits),
            std::mem::take(&mut report.checks_run),
        );
        report.elapsed_micros = elapsed;
    }
}

pub(super) fn reportable(reports: &[DomainReport], include_suspicious: bool) -> Vec<DomainReport> {
    reports
        .iter()
        .map(|report| {
            let mut report = report.clone();
            report.hits.retain(|hit| {
                hit.verdict == DomainVerdict::Malicious
                    || (include_suspicious && hit.verdict == DomainVerdict::Suspicious)
            });
            report
        })
        .collect()
}
