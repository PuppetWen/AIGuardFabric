//! Older files mixed observed values and fabricated startup zeros. Preserve bytes before restarting sampling.
use super::*;
use sha2::{Digest, Sha256};
use std::io::Write;

pub(super) fn archive_legacy(path: &Path, raw: &str) -> DomainResult<bool> {
    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|error| agf_core::error::DomainError::Internal(error.to_string()))?;
    if value.get("version").and_then(serde_json::Value::as_u64).unwrap_or(0) >= 2 {
        return Ok(false);
    }
    let digest = hex::encode(Sha256::digest(raw.as_bytes()));
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".pre-v2-{digest}.json"));
    let archive = path.with_file_name(name);
    match std::fs::OpenOptions::new().write(true).create_new(true).open(&archive) {
        Ok(mut file) => file.write_all(raw.as_bytes()).and_then(|()| file.sync_all()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if std::fs::read(&archive).is_ok_and(|bytes| bytes == raw.as_bytes()) {
                Ok(())
            } else {
                Err(std::io::Error::other("Existing history archive does not match source bytes"))
            }
        }
        Err(error) => Err(error),
    }
    .map_err(|error| agf_core::error::DomainError::Internal(format!("Cannot preserve legacy risk history: {error}")))?;
    warn!(path = %archive.display(), "Legacy risk history archived; actual observations restart without fabricated zero values");
    Ok(true)
}
