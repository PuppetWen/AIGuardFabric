//! Read only a bounded regular file and send its digest, never its contents.
use std::{fs::File, io::Read, path::Path};
const MAX_BYTES: u64 = 4 * 1024 * 1024;

pub(super) fn content_hash(path: &Path) -> Result<String, &'static str> {
    let link = std::fs::symlink_metadata(path).map_err(|_| "unreadable")?;
    if !link.file_type().is_file() {
        return Err("not-regular-file");
    }
    let file = File::open(path).map_err(|_| "unreadable")?;
    let before = file.metadata().map_err(|_| "unreadable")?;
    if before.len() > MAX_BYTES {
        return Err("too-large");
    }
    let mut bytes = Vec::new();
    (&file).take(MAX_BYTES + 1).read_to_end(&mut bytes).map_err(|_| "unreadable")?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err("too-large");
    }
    let after = file.metadata().map_err(|_| "unreadable")?;
    if before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
        || bytes.len() as u64 != after.len()
    {
        return Err("changed-during-read");
    }
    Ok(crate::selfupdate::sha256_hex(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn changed_content_changes_digest_without_uploading_content() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let path = dir.path().join("SKILL.md");
        std::fs::write(&path, b"approved").expect("fixture");
        let first = content_hash(&path).expect("first hash");
        std::fs::write(&path, b"modified").expect("fixture");
        assert_ne!(first, content_hash(&path).expect("changed hash"));
        File::create(&path).expect("file").set_len(MAX_BYTES + 1).expect("sparse size");
        assert_eq!(content_hash(&path), Err("too-large"));
        assert_eq!(content_hash(dir.path()), Err("not-regular-file"));
        assert_eq!(content_hash(&dir.path().join("missing")), Err("unreadable"));
    }
}
