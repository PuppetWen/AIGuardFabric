use std::fmt;

use serde::Serialize;
use serde_json::Value;

use super::{EmbeddingFailure, EmbeddingProfile, MAX_REPORTED_TOKENS};

#[derive(Serialize)]
pub(super) struct Request<'a> {
    pub(super) input: &'a str,
    pub(super) model: &'a str,
    pub(super) encoding_format: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) dimensions: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmbeddingUsage {
    pub prompt_tokens: u64,
    pub total_tokens: u64,
}

/// Float vector Debug exposes dimensions only, never values or input text.
#[derive(Clone)]
pub struct ValidatedEmbedding {
    values: Vec<f32>,
}

impl fmt::Debug for ValidatedEmbedding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("ValidatedEmbedding").field("dimensions", &self.values.len()).finish_non_exhaustive()
    }
}

impl ValidatedEmbedding {
    pub fn values(&self) -> &[f32] {
        &self.values
    }

    pub(super) fn new(values: Vec<f32>, dimensions: u16) -> Result<Self, EmbeddingFailure> {
        if !(1..=4096).contains(&dimensions)
            || values.len() != usize::from(dimensions)
            || values.iter().any(|value| !value.is_finite())
            || !values.iter().any(|value| *value != 0.0)
        {
            return Err(EmbeddingFailure::InvalidVector);
        }
        Ok(Self { values })
    }
}

/// Usage and vector parsing are separate; an invalid vector never erases known paid usage.
pub(super) fn usage(value: &Value) -> Option<EmbeddingUsage> {
    let usage = value.get("usage")?;
    let prompt_tokens = usage.get("prompt_tokens")?.as_u64()?;
    let total_tokens = usage.get("total_tokens")?.as_u64()?;
    if prompt_tokens == 0 || prompt_tokens != total_tokens || total_tokens > MAX_REPORTED_TOKENS {
        return None;
    }
    Some(EmbeddingUsage { prompt_tokens, total_tokens })
}

pub(super) fn vector(value: &Value, profile: &EmbeddingProfile) -> Result<ValidatedEmbedding, EmbeddingFailure> {
    if value.get("object").and_then(Value::as_str) != Some("list") {
        return Err(EmbeddingFailure::MalformedResponse);
    }
    if value.get("model").and_then(Value::as_str) != Some(profile.configuration.model.as_str()) {
        return Err(EmbeddingFailure::InvalidModel);
    }
    let data = value.get("data").and_then(Value::as_array).ok_or(EmbeddingFailure::InvalidVector)?;
    if data.len() != 1
        || data[0].get("index").and_then(Value::as_u64) != Some(0)
        || data[0].get("object").and_then(Value::as_str) != Some("embedding")
    {
        return Err(EmbeddingFailure::InvalidVector);
    }
    let raw = data[0].get("embedding").and_then(Value::as_array).ok_or(EmbeddingFailure::InvalidVector)?;
    if raw.len() != usize::from(profile.configuration.dimensions) {
        return Err(EmbeddingFailure::InvalidVector);
    }
    let values = raw
        .iter()
        .map(|value| {
            let number = value.as_f64().ok_or(EmbeddingFailure::InvalidVector)?;
            if !number.is_finite() || number.abs() > f64::from(f32::MAX) {
                return Err(EmbeddingFailure::InvalidVector);
            }
            Ok(number as f32)
        })
        .collect::<Result<Vec<_>, _>>()?;
    ValidatedEmbedding::new(values, profile.configuration.dimensions)
}
