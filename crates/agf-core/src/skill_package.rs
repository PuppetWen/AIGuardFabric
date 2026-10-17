//! Versioned, bounded directory observations shared by collectors and ingest.
use serde::{Deserialize, Serialize};

/// Hash framing version; a change requires a new baseline, not a tampering alert.
pub const ALGORITHM: &str = "sha256-tree-v1";
/// Maximum bytes in a single package file.
pub const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
/// Maximum sum of regular file lengths in one package.
pub const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum regular files in one package.
pub const MAX_FILES: u32 = 4096;
/// Maximum files and directories combined, excluding the root.
pub const MAX_ENTRIES: usize = 8192;
/// Maximum relative path component count.
pub const MAX_DEPTH: usize = 16;

/// A complete observation or the reason a complete observation was unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PackageStatus {
    /// All supported entries were read and passed the final metadata check.
    Verified,
    /// A directory, file or required metadata could not be read.
    Unreadable,
    /// A file or the package exceeded the byte budget.
    TooLarge,
    /// The file or entry count exceeded the budget.
    TooManyEntries,
    /// A relative path exceeded the depth budget.
    TooDeep,
    /// A filename could not be represented unambiguously in the wire format.
    UnsupportedPath,
    /// An entry was neither a regular file nor a directory.
    NotRegularFile,
    /// Inventory or file metadata changed while reading.
    ChangedDuringRead,
    /// A symbolic link or Windows reparse point was encountered.
    LinkNotAllowed,
}

/// No source content or child filenames leave the collector in this record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageObservation {
    /// Deterministic hash framing version.
    pub algorithm: String,
    /// Completeness of the latest observation, not a security verdict.
    pub status: PackageStatus,
    /// Lowercase hex SHA-256, present only for complete observations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Number of regular files included, including the manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub files: Option<u32>,
    /// Sum of regular file lengths; directories contribute no bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
}

impl PackageObservation {
    /// Validate the wire contract without treating a partial digest as complete.
    ///
    /// # Errors
    /// An unknown version, inconsistent status or out-of-range count is rejected.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.algorithm != ALGORITHM {
            return Err("unsupported Skill package hash algorithm");
        }
        if self.status == PackageStatus::Verified {
            if !self.sha256.as_ref().is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
                || !self.files.is_some_and(|n| (1..=MAX_FILES).contains(&n))
                || self.bytes.is_none_or(|n| n > MAX_TOTAL_BYTES)
            {
                return Err("verified Skill package requires a valid digest and bounded counts");
            }
        } else if self.sha256.is_some() || self.files.is_some() || self.bytes.is_some() {
            return Err("incomplete Skill package must not carry a digest or counts");
        }
        Ok(())
    }

    /// Describe an incomplete observation without retaining an old or partial hash.
    #[must_use]
    pub fn unavailable(status: PackageStatus) -> Self {
        Self { algorithm: ALGORITHM.into(), status, sha256: None, files: None, bytes: None }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn incomplete_and_oversized_observations_cannot_claim_verification() {
        let mut row = PackageObservation::unavailable(PackageStatus::Unreadable);
        assert!(row.validate().is_ok());
        row.sha256 = Some("a".repeat(64));
        assert!(row.validate().is_err());
        row.status = PackageStatus::Verified;
        row.files = Some(1);
        row.bytes = Some(MAX_TOTAL_BYTES);
        assert!(row.validate().is_ok());
        row.bytes = Some(MAX_TOTAL_BYTES + 1);
        assert!(row.validate().is_err());
        row.bytes = Some(0);
        row.files = Some(0);
        assert!(row.validate().is_err());
        row.files = Some(MAX_FILES + 1);
        assert!(row.validate().is_err());
        row.files = Some(1);
        row.algorithm = "unknown".into();
        assert!(row.validate().is_err());
    }
}
