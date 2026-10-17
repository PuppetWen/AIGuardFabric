use super::util;
use agf_core::error::DomainResult;
use sha2::{Digest, Sha256};

/// Actual local feature hashing, explicitly separated from every vendor embedding domain.
/// This sends nothing, has no provider usage and costs zero; it is not a multilingual model.
pub(super) fn vector(text: &str, dimensions: u16) -> DomainResult<Vec<f32>> {
    if text.is_empty() || text.len() > 8192 || !(1..=4096).contains(&dimensions) {
        return Err(util::invalid());
    }
    let mut values = vec![0.0f32; usize::from(dimensions)];
    let mut words = 0u32;
    for word in text.split_whitespace() {
        let hash = Sha256::digest(word.to_lowercase().as_bytes());
        let index = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]) % u32::from(dimensions);
        values[usize::try_from(index).map_err(|_| util::invalid())?] += 1.0;
        words = words.checked_add(1).ok_or_else(util::invalid)?;
    }
    let norm = values.iter().map(|value| f64::from(*value).powi(2)).sum::<f64>().sqrt();
    if words == 0 || !norm.is_finite() || norm <= 0.0 {
        return Err(util::invalid());
    }
    for value in &mut values {
        *value = (f64::from(*value) / norm) as f32;
    }
    Ok(values)
}
