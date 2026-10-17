//! A response alone does not prove that the declared checks ran.
use super::*;
use agf_core::redteam::EvaluationStatus;

/// Evidence and assessment supplied by a target adapter for one case.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TargetObservation {
    /// Whether the adapter ran every declared check against a target response.
    pub evaluation: EvaluationStatus,
    /// Declared success checks that matched the recorded response.
    pub matched_signals: Vec<String>,
    /// Bounded, redacted interaction evidence for review.
    pub transcript: Vec<serde_json::Value>,
    /// Non-secret reason when assessment is incomplete.
    pub note: Option<String>,
}
impl TargetObservation {
    /// Record an assessment after the adapter ran all declared checks.
    pub fn evaluated(signals: Vec<String>, transcript: Vec<serde_json::Value>) -> Self {
        Self { evaluation: EvaluationStatus::Evaluated, matched_signals: signals, transcript, note: None }
    }
    /// Record an interaction that cannot support a success or failure conclusion.
    pub fn inconclusive(note: impl Into<String>) -> Self {
        Self { evaluation: EvaluationStatus::Inconclusive, note: Some(note.into()), ..Self::default() }
    }
    pub(crate) fn failed() -> Self {
        Self {
            evaluation: EvaluationStatus::ExecutionError,
            note: Some("Target execution failed; inspect target availability and retry explicitly.".into()),
            ..Self::default()
        }
    }
    pub(crate) fn validate(mut self, case: &RedteamCase, simulated: bool) -> Self {
        if self.matched_signals.iter().any(|signal| !case.success_signals.contains(signal)) {
            self.evaluation = EvaluationStatus::Inconclusive;
            self.note = Some("Target returned a signal outside this case's declared checks.".into());
        }
        if !simulated && self.evaluation == EvaluationStatus::Evaluated && self.transcript.is_empty() {
            self.evaluation = EvaluationStatus::Inconclusive;
            self.note = Some("No interaction evidence was recorded for this evaluation.".into());
        }
        // A bounded record must not silently claim completeness after dropping evidence.
        if serde_json::to_vec(&self.transcript).map_or(true, |bytes| bytes.len() > 64 * 1024) {
            self.transcript.clear();
            self.evaluation = EvaluationStatus::Inconclusive;
            self.note = Some("Interaction evidence exceeded 64 KiB; reduce the case and rerun.".into());
        }
        if self.evaluation != EvaluationStatus::Evaluated {
            self.matched_signals.clear();
        }
        self.matched_signals.sort();
        self.matched_signals.dedup();
        self
    }
}
