//! 由 `backup.rs` 拆分：`temp_dir` 等 15 个函数（纯搬移，逻辑不变）。
use super::*;

pub(crate) fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("agf-backup-{tag}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("建目录");
    dir
}

#[test]
pub(crate) fn layout_resolves_directory_and_dump_path() {
    // 目录分支：`--in` 指向真实存在的备份目录（用临时目录，避免硬编码绝对路径）
    let dir = temp_dir("layout-dir");
    let from_dir = BackupLayout::resolve(&dir);
    assert_eq!(from_dir.dir, dir);
    assert_eq!(from_dir.dump, dir.join(DUMP_NAME));
    assert_eq!(from_dir.manifest_json, dir.join(MANIFEST_JSON));
    assert_eq!(from_dir.manifest_txt, dir.join(MANIFEST_TXT));
    assert_eq!(from_dir.data_zip, dir.join(DATA_ZIP));
    let _ = std::fs::remove_dir_all(&dir);

    // 文件分支：`--in` 直接指向 agf.dump（不存在的路径不会被当作目录）
    let dump = temp_dir("layout-file").join(DUMP_NAME);
    let from_file = BackupLayout::resolve(&dump);
    assert_eq!(from_file.dump, dump);
    assert_eq!(from_file.dir, dump.parent().map(Path::to_path_buf).unwrap_or_default());
    assert!(from_file.manifest_json.ends_with(MANIFEST_JSON));
    assert!(from_file.manifest_txt.ends_with(MANIFEST_TXT));
}

#[test]
pub(crate) fn layout_validate_requires_dump_file() {
    let dir = temp_dir("validate");
    let layout = BackupLayout::resolve(&dir);
    let err = layout.validate().expect_err("缺 dump 必须失败");
    assert_eq!(err.exit_code(), 1);
    assert!(err.to_string().contains(DUMP_NAME));
    std::fs::write(&layout.dump, b"dump").expect("写 dump");
    assert!(layout.validate().is_ok());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
pub(crate) fn process_results_are_classified_correctly() {
    assert_eq!(classify_process_result(Some(0), ""), None);
    assert_eq!(classify_process_result(Some(1), "pg_dump: error: fake"), Some(ProcessFailure::NonZero(1)));
    assert_eq!(classify_process_result(None, ""), Some(ProcessFailure::Spawn("进程被终止且无退出码".to_string())));
    let conn = classify_process_result(Some(1), "pg_dump: error: connection to server at \"127.0.0.1\" failed")
        .expect("应归类为连接错误");
    assert!(matches!(conn, ProcessFailure::Connection(_)));
    assert!(conn.is_dependency_unavailable());
    assert!(!ProcessFailure::NonZero(1).is_dependency_unavailable());
}

#[test]
pub(crate) fn connection_error_detection_covers_libpq_phrasings() {
    for text in [
        "could not connect to server: Connection refused",
        "could not translate host name \"nope\" to address",
        "password authentication failed for user \"agf\"",
        "connection to server at \"db\" port 5432 failed",
    ] {
        assert!(is_connection_error(text), "应识别为连接错误: {text}");
    }
    assert!(!is_connection_error("pg_dump: error: permission denied for table users"));
}

#[test]
pub(crate) fn process_error_maps_dependency_failures_to_exit_two() {
    let missing = process_error(PG_DUMP, &ProcessFailure::NotFound, "postgres://agf:***@h:5432/db");
    assert_eq!(missing.exit_code(), 2);
    let msg = missing.to_string();
    assert!(msg.contains("TODO(agfctl-pg-tools)"), "必须带 TODO 锚点: {msg}");
    assert!(msg.contains("PATH"), "应提示把工具加入 PATH: {msg}");

    let failed = process_error(PG_DUMP, &ProcessFailure::NonZero(1), "t");
    assert_eq!(failed.exit_code(), 1, "非连接类失败是内容问题（退出码 1）");
}

#[test]
pub(crate) fn manifest_txt_renders_powershell_compatible_lines() {
    let entries = vec![
        ManifestEntry { path: DUMP_NAME.to_string(), bytes: 4096, sha256: "a".repeat(64) },
        ManifestEntry { path: DATA_ZIP.to_string(), bytes: 12, sha256: "b".repeat(64) },
    ];
    let header = vec!["备份时间：2026-01-01 00:00:00".to_string(), String::new()];
    let text = render_manifest_txt(&header, &entries);
    assert!(text.starts_with("备份时间："));
    assert!(text.ends_with('\n'));
    let parsed = parse_manifest_txt(&text);
    assert_eq!(parsed, entries, "渲染出的清单必须能被同一解析器读回");
}

#[test]
pub(crate) fn manifest_txt_parser_ignores_headers_and_bad_lines() {
    let text = "备份时间：2026-01-01\n\n文件 字节 sha256\nagf.dump 10 nothex\nmanifest.json 5 zzzz\ndata-files.zip 7 "
        .to_string()
        + &"c".repeat(64);
    let parsed = parse_manifest_txt(&text);
    assert_eq!(parsed.len(), 1, "只有最后一行合法: {parsed:?}");
    assert_eq!(parsed[0].path, DATA_ZIP);
    assert_eq!(parsed[0].bytes, 7);
    assert!(parse_manifest_txt_line("").is_none());
    assert!(parse_manifest_txt_line("只有名字").is_none());
}

#[test]
pub(crate) fn backup_dir_defaults_under_data_dir_with_timestamp() {
    let dir = resolve_backup_dir(None, Path::new("data"));
    assert!(dir.starts_with(Path::new("data").join("backup")), "{dir:?}");
    let explicit = resolve_backup_dir(Some(Path::new("D:/bk")), Path::new("data"));
    assert_eq!(explicit, PathBuf::from("D:/bk"));
    assert!(!resolve_backup_dir(None, Path::new("data")).is_absolute(), "默认路径必须相对（铁律 4）");
}

#[test]
pub(crate) fn program_override_falls_back_to_default() {
    // 用一个几乎不可能存在的键名，验证回退分支
    assert_eq!(program_or("AGF_TEST_UNSET_PROGRAM_KEY_ZZZ", PG_DUMP), PG_DUMP);
    assert_eq!(program_or("AGF_PG_RESTORE_NOT_SET_ZZZ", PG_RESTORE), PG_RESTORE);
}

#[test]
pub(crate) fn verify_backup_package_detects_tampering() {
    let dir = temp_dir("verify-pkg");
    let dump = dir.join(DUMP_NAME);
    std::fs::write(&dump, b"original-dump").expect("写 dump");
    let entry = ManifestEntry::from_file(&dir, &dump).expect("条目");
    let manifest = BackupManifest {
        generated_at: now_rfc3339(),
        version: "0.1.0".to_string(),
        target: "postgres://agf:***@h:5432/db".to_string(),
        with_data: false,
        files: vec![entry],
    };
    std::fs::write(dir.join(MANIFEST_JSON), serde_json::to_string(&manifest).unwrap_or_default()).expect("写清单");
    let layout = BackupLayout::resolve(&dir);
    assert!(verify_backup_package(&layout, Output::silent()).is_ok());
    std::fs::write(&dump, b"tampered-dump").expect("篡改");
    let err = verify_backup_package(&layout, Output::silent()).expect_err("篡改必须被抓");
    assert_eq!(err.exit_code(), 1);
    assert!(err.to_string().contains("sha256 不一致"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
pub(crate) fn verify_backup_package_without_manifest_only_warns() {
    let dir = temp_dir("verify-nomanifest");
    std::fs::write(dir.join(DUMP_NAME), b"dump").expect("写 dump");
    let layout = BackupLayout::resolve(&dir);
    assert!(verify_backup_package(&layout, Output::silent()).is_ok(), "缺清单应降级为提示而非失败");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
pub(crate) fn verify_backup_package_detects_missing_file() {
    let dir = temp_dir("verify-missing");
    std::fs::write(dir.join(DUMP_NAME), b"dump").expect("写 dump");
    std::fs::write(dir.join(DATA_ZIP), b"zip").expect("写 zip");
    let files = vec![
        ManifestEntry::from_file(&dir, &dir.join(DUMP_NAME)).expect("条目1"),
        ManifestEntry::from_file(&dir, &dir.join(DATA_ZIP)).expect("条目2"),
    ];
    let manifest = BackupManifest {
        generated_at: now_rfc3339(),
        version: "0.1.0".to_string(),
        target: "t".to_string(),
        with_data: true,
        files,
    };
    std::fs::write(dir.join(MANIFEST_JSON), serde_json::to_string(&manifest).unwrap_or_default()).expect("写清单");
    std::fs::remove_file(dir.join(DATA_ZIP)).expect("删文件");
    let layout = BackupLayout::resolve(&dir);
    let err = verify_backup_package(&layout, Output::silent()).expect_err("缺文件必须失败");
    assert!(err.to_string().contains("缺失文件"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
pub(crate) async fn restore_without_force_is_refused_before_touching_database() {
    // force 校验发生在任何数据库交互之前，因此不需要 PG 也能验证
    let dir = temp_dir("restore-noforce");
    std::fs::write(dir.join(DUMP_NAME), b"dump").expect("写 dump");
    let err = restore(&dir, false, false, false, None, Output::silent()).await.expect_err("缺 --force 必须中止");
    assert_eq!(err.exit_code(), 1);
    assert!(err.to_string().contains("--force"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
pub(crate) async fn backup_reports_dependency_error_when_pg_unreachable() {
    // 指向必然拒绝连接的地址；backup 必须先给出退出码 2，而不是伪造成功
    let err = backup(None, true, Some("postgres://nobody:nothing@127.0.0.1:1/nodb"), Output::silent())
        .await
        .expect_err("PG 不可达必须失败");
    assert_eq!(err.exit_code(), 2, "PG 不可达 = 退出码 2: {err}");
    assert!(err.to_string().contains("TODO(agfctl-pg-live)"));
}
