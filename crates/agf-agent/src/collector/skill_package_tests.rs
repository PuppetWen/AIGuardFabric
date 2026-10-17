use super::*;

fn fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temporary package");
    fs::write(dir.path().join("SKILL.md"), "# Package\nRun scripts/main.py").expect("manifest");
    fs::create_dir(dir.path().join("scripts")).expect("scripts");
    fs::write(dir.path().join("scripts/main.py"), "print('original')").expect("script");
    dir
}

fn digest(root: &Path) -> String {
    let result = observe(root);
    assert_eq!(result.status, Status::Verified);
    result.validate().expect("wire contract");
    result.sha256.expect("complete hash")
}

#[test]
fn nested_edits_additions_removals_and_renames_change_only_package_digest() {
    let dir = fixture();
    let root = dir.path();
    let manifest = super::super::skill_hash::content_hash(&root.join("SKILL.md")).expect("manifest hash");
    let first = digest(root);
    fs::write(root.join("scripts/main.py"), "print('modified')").expect("edit");
    let edited = digest(root);
    assert_ne!(first, edited);
    fs::write(root.join(".hidden"), "hidden input").expect("hidden");
    let added = digest(root);
    assert_ne!(edited, added);
    fs::rename(root.join(".hidden"), root.join("renamed")).expect("rename");
    assert_ne!(added, digest(root));
    fs::remove_file(root.join("renamed")).expect("remove test file");
    assert_eq!(edited, digest(root));
    fs::create_dir(root.join("empty")).expect("empty directory");
    assert_ne!(edited, digest(root));
    assert_eq!(manifest, super::super::skill_hash::content_hash(&root.join("SKILL.md")).expect("same manifest"));
}

#[test]
fn identical_trees_ignore_creation_order_and_absolute_location() {
    let first = fixture();
    let other = tempfile::tempdir().expect("other package");
    fs::create_dir(other.path().join("scripts")).expect("scripts");
    fs::write(other.path().join("scripts/main.py"), "print('original')").expect("script");
    fs::write(other.path().join("SKILL.md"), "# Package\nRun scripts/main.py").expect("manifest");
    assert_eq!(digest(first.path()), digest(other.path()));
    let observed = observe(first.path());
    assert_eq!(observed.files, Some(2));
    assert_eq!(observed.bytes, Some(46));
}

#[test]
fn every_budget_rejects_the_whole_observation_without_partial_hash() {
    let dir = fixture();
    for (limits, reason) in [
        (Limits { file_bytes: 1, ..LIMITS }, Status::TooLarge),
        (Limits { total_bytes: 1, ..LIMITS }, Status::TooLarge),
        (Limits { files: 1, ..LIMITS }, Status::TooManyEntries),
        (Limits { entries: 1, ..LIMITS }, Status::TooManyEntries),
        (Limits { depth: 1, ..LIMITS }, Status::TooDeep),
    ] {
        assert_eq!(hash(dir.path(), limits), Err(reason));
    }
    fs::File::create(dir.path().join("huge.bin"))
        .expect("sparse file")
        .set_len(contract::MAX_FILE_BYTES + 1)
        .expect("size");
    let result = observe(dir.path());
    assert_eq!(result.status, Status::TooLarge);
    assert!(result.sha256.is_none() && result.files.is_none() && result.bytes.is_none());
}

#[test]
fn changed_or_disappeared_files_cannot_use_the_old_inventory() {
    let dir = fixture();
    let before = inventory(dir.path(), LIMITS).expect("inventory");
    let canonical = fs::canonicalize(dir.path()).expect("canonical fixture");
    fs::write(dir.path().join("scripts/main.py"), "changed length").expect("edit");
    assert_eq!(hash_inventory(&canonical, &before, LIMITS), Err(Status::ChangedDuringRead));
    fs::remove_file(dir.path().join("scripts/main.py")).expect("remove test script");
    assert_eq!(hash_inventory(&canonical, &before, LIMITS), Err(Status::Unreadable));
    assert_eq!(observe(&dir.path().join("missing")).status, Status::Unreadable);
    assert_eq!(observe(&dir.path().join("SKILL.md")).status, Status::NotRegularFile);
}

#[cfg(windows)]
#[test]
fn writable_file_and_directory_junction_are_explicitly_unavailable() {
    use std::process::Command;
    let dir = fixture();
    let held = fs::OpenOptions::new().write(true).open(dir.path().join("scripts/main.py")).expect("writer");
    assert_eq!(observe(dir.path()).status, Status::Unreadable);
    drop(held);
    let outside = tempfile::tempdir().expect("external fixture");
    fs::write(outside.path().join("never-read.txt"), "outside").expect("outside fixture");
    let junction = dir.path().join("linked");
    // Native PowerShell creates/removes only this test-owned junction; no shell deletion chain.
    let quote = |path: &Path| format!("'{}'", path.display().to_string().replace('\'', "''"));
    let script = format!(
        "$ErrorActionPreference='Stop'; New-Item -ItemType Junction -Path {} -Target {} | Out-Null",
        quote(&junction),
        quote(outside.path())
    );
    assert!(
        Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .status()
            .expect("create fixture junction")
            .success()
    );
    assert_eq!(observe(dir.path()).status, Status::LinkNotAllowed);
    // remove_dir removes the junction itself; it does not traverse the target.
    fs::remove_dir(&junction).expect("remove fixture junction");
    assert!(outside.path().join("never-read.txt").is_file());
}

#[cfg(unix)]
#[test]
fn symlink_and_non_utf8_name_are_explicitly_unavailable() {
    use std::os::unix::{ffi::OsStringExt, fs::symlink};
    let dir = fixture();
    symlink("scripts", dir.path().join("linked")).expect("fixture symlink");
    assert_eq!(observe(dir.path()).status, Status::LinkNotAllowed);
    fs::remove_file(dir.path().join("linked")).expect("remove test link");
    fs::write(dir.path().join(std::ffi::OsString::from_vec(vec![0xff])), "bad name").expect("filename");
    assert_eq!(observe(dir.path()).status, Status::UnsupportedPath);
}
