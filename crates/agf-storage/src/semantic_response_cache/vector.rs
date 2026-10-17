use agf_core::error::{DomainError, DomainResult};

/// Validated query and explicitly selected threshold/ambiguity policy; vector Debug is redacted.
#[derive(Clone)]
pub struct SearchVector {
    values: Vec<f32>,
    threshold: f64,
    margin: f64,
}

impl std::fmt::Debug for SearchVector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SearchVector").field("dimensions", &self.values.len()).finish_non_exhaustive()
    }
}

impl SearchVector {
    /// Require finite nonzero 1..4096 dimensions, threshold (0,1], explicit nonnegative margin.
    pub fn new(values: Vec<f32>, threshold: f64, ambiguity_margin: f64) -> DomainResult<Self> {
        validate(&values)?;
        if !threshold.is_finite()
            || threshold <= 0.0
            || threshold > 1.0
            || !ambiguity_margin.is_finite()
            || !(0.0..=1.0).contains(&ambiguity_margin)
        {
            return Err(invalid());
        }
        Ok(Self { values, threshold, margin: ambiguity_margin.max(1e-12) })
    }
    /// Query dimensions.
    pub fn dimensions(&self) -> usize {
        self.values.len()
    }
    pub(super) fn score(&self, values: &[f32]) -> DomainResult<f64> {
        validate(values)?;
        if self.values.len() != values.len() {
            return Err(invalid());
        }
        let left = normalized(&self.values);
        let right = normalized(values);
        let score = left.iter().zip(right).map(|(a, b)| a * b).sum::<f64>();
        if !score.is_finite() || !(-1.0 - 1e-12..=1.0 + 1e-12).contains(&score) {
            return Err(invalid());
        }
        Ok(score.clamp(-1.0, 1.0))
    }
    pub(super) fn accepted(&self, score: f64) -> bool {
        score >= self.threshold
    }
    pub(super) fn ambiguous(&self, best: f64, next: f64) -> bool {
        best - next <= self.margin
    }
}

pub(super) fn validate(values: &[f32]) -> DomainResult<()> {
    if values.is_empty()
        || values.len() > 4096
        || values.iter().any(|v| !v.is_finite())
        || !values.iter().any(|v| *v != 0.0)
    {
        return Err(invalid());
    }
    Ok(())
}

fn normalized(values: &[f32]) -> Vec<f64> {
    let maximum = values.iter().map(|v| f64::from(*v).abs()).fold(0.0, f64::max);
    let scaled = values.iter().map(|v| f64::from(*v) / maximum).collect::<Vec<_>>();
    let norm = scaled.iter().map(|v| v * v).sum::<f64>().sqrt();
    scaled.into_iter().map(|v| v / norm).collect()
}

fn invalid() -> DomainError {
    DomainError::Validation("Semantic vector or similarity bounds are invalid".into())
}
