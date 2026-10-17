//! Bounded whole-directory observations. This is not an atomic filesystem snapshot.
use agf_core::skill_package::{self as contract, PackageObservation, PackageStatus as Status};
use sha2::{Digest, Sha256};
use std::{fs, io::Read, path::Path, time::SystemTime};

#[derive(Clone, Copy)]
struct Limits {
    file_bytes: u64,
    total_bytes: u64,
    files: u32,
    entries: usize,
    depth: usize,
}
const LIMITS: Limits = Limits {
    file_bytes: contract::MAX_FILE_BYTES,
    total_bytes: contract::MAX_TOTAL_BYTES,
    files: contract::MAX_FILES,
    entries: contract::MAX_ENTRIES,
    depth: contract::MAX_DEPTH,
};

#[derive(Debug, PartialEq, Eq)]
struct Entry {
    relative: String,
    directory: bool,
    bytes: u64,
    modified: SystemTime,
}

#[derive(Debug, PartialEq, Eq)]
struct Inventory {
    entries: Vec<Entry>,
    files: u32,
    bytes: u64,
    root_modified: SystemTime,
}

pub(super) fn observe(root: &Path) -> PackageObservation {
    match hash(root, LIMITS) {
        Ok((sha256, inventory)) => PackageObservation {
            algorithm: contract::ALGORITHM.into(),
            status: Status::Verified,
            sha256: Some(sha256),
            files: Some(inventory.files),
            bytes: Some(inventory.bytes),
        },
        Err(status) => PackageObservation::unavailable(status),
    }
}

fn checked_metadata(path: &Path) -> Result<fs::Metadata, Status> {
    let metadata = fs::symlink_metadata(path).map_err(|_| Status::Unreadable)?;
    reject_link(&metadata)?;
    if !metadata.is_file() && !metadata.is_dir() {
        return Err(Status::NotRegularFile);
    }
    Ok(metadata)
}

fn reject_link(metadata: &fs::Metadata) -> Result<(), Status> {
    if metadata.file_type().is_symlink() {
        return Err(Status::LinkNotAllowed);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        // FILE_ATTRIBUTE_REPARSE_POINT includes junctions and cloud placeholders.
        if metadata.file_attributes() & 0x0400 != 0 {
            return Err(Status::LinkNotAllowed);
        }
    }
    Ok(())
}

fn inventory(root: &Path, limits: Limits) -> Result<Inventory, Status> {
    let metadata = checked_metadata(root)?;
    if !metadata.is_dir() {
        return Err(Status::NotRegularFile);
    }
    let mut result = Inventory {
        entries: Vec::new(),
        files: 0,
        bytes: 0,
        root_modified: metadata.modified().map_err(|_| Status::Unreadable)?,
    };
    visit(root, "", &mut result, limits)?;
    result.entries.sort_unstable_by(|a, b| a.relative.cmp(&b.relative));
    if !result.entries.iter().any(|entry| entry.relative == "SKILL.md" && !entry.directory) {
        return Err(Status::NotRegularFile);
    }
    Ok(result)
}

fn visit(root: &Path, relative: &str, result: &mut Inventory, limits: Limits) -> Result<(), Status> {
    for item in fs::read_dir(root.join(relative)).map_err(|_| Status::Unreadable)? {
        let item = item.map_err(|_| Status::Unreadable)?;
        let name = item.file_name().into_string().map_err(|_| Status::UnsupportedPath)?;
        // Do not conflate a Unix backslash filename with a Windows path separator.
        if name.contains(['/', '\\']) {
            return Err(Status::UnsupportedPath);
        }
        let child = if relative.is_empty() { name } else { format!("{relative}/{name}") };
        if child.split('/').count() > limits.depth {
            return Err(Status::TooDeep);
        }
        if result.entries.len() >= limits.entries {
            return Err(Status::TooManyEntries);
        }
        let metadata = checked_metadata(&root.join(&child))?;
        let directory = metadata.is_dir();
        let bytes = if directory { 0 } else { metadata.len() };
        if !directory {
            result.files += 1;
            if result.files > limits.files {
                return Err(Status::TooManyEntries);
            }
            if bytes > limits.file_bytes || bytes > limits.total_bytes.saturating_sub(result.bytes) {
                return Err(Status::TooLarge);
            }
            result.bytes += bytes;
        }
        result.entries.push(Entry {
            relative: child.clone(),
            directory,
            bytes,
            modified: metadata.modified().map_err(|_| Status::Unreadable)?,
        });
        if directory {
            visit(root, &child, result, limits)?;
        }
    }
    Ok(())
}

fn hash(root: &Path, limits: Limits) -> Result<(String, Inventory), Status> {
    let before = inventory(root, limits)?;
    let canonical = fs::canonicalize(root).map_err(|_| Status::Unreadable)?;
    let digest = hash_inventory(&canonical, &before, limits)?;
    if before != inventory(root, limits).map_err(|_| Status::ChangedDuringRead)?
        || fs::canonicalize(root).map_err(|_| Status::ChangedDuringRead)? != canonical
    {
        return Err(Status::ChangedDuringRead);
    }
    Ok((digest, before))
}

fn hash_inventory(root: &Path, before: &Inventory, limits: Limits) -> Result<String, Status> {
    let mut digest = Sha256::new();
    digest.update(b"agf:sha256-tree-v1\0");
    for entry in &before.entries {
        digest.update(if entry.directory { b"D" } else { b"F" });
        digest.update((entry.relative.len() as u64).to_be_bytes());
        digest.update(entry.relative.as_bytes());
        if !entry.directory {
            digest.update(entry.bytes.to_be_bytes());
            digest.update(read_file(root, entry, limits)?);
        }
    }
    Ok(hex::encode(digest.finalize()))
}

fn read_file(root: &Path, entry: &Entry, limits: Limits) -> Result<[u8; 32], Status> {
    let path = root.join(&entry.relative);
    let mut parent = root.to_path_buf();
    for component in Path::new(&entry.relative).components() {
        parent.push(component);
        checked_metadata(&parent)?;
    }
    if !fs::canonicalize(&path).map_err(|_| Status::Unreadable)?.starts_with(root) {
        return Err(Status::LinkNotAllowed);
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // OPEN_REPARSE_POINT: inspect the final entry, never follow a newly replaced link.
        // SHARE_READ: refuse a concurrently writable/deletable handle while reading.
        // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
        options.custom_flags(0x0020_0000).share_mode(1).security_qos_flags(0);
    }
    let file = options.open(&path).map_err(|_| Status::Unreadable)?;
    let metadata = file.metadata().map_err(|_| Status::Unreadable)?;
    matches_entry(&metadata, entry)?;
    let mut bytes = Vec::new();
    (&file).take(limits.file_bytes + 1).read_to_end(&mut bytes).map_err(|_| Status::Unreadable)?;
    matches_entry(&file.metadata().map_err(|_| Status::Unreadable)?, entry)?;
    matches_entry(&checked_metadata(&path)?, entry)?;
    if bytes.len() as u64 != entry.bytes {
        return Err(Status::ChangedDuringRead);
    }
    Ok(Sha256::digest(&bytes).into())
}

fn matches_entry(metadata: &fs::Metadata, entry: &Entry) -> Result<(), Status> {
    reject_link(metadata)?;
    if !metadata.is_file()
        || metadata.len() != entry.bytes
        || metadata.modified().map_err(|_| Status::Unreadable)? != entry.modified
    {
        return Err(Status::ChangedDuringRead);
    }
    Ok(())
}

#[cfg(test)]
#[path = "skill_package_tests.rs"]
mod tests;
