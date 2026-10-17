//! 由 `tasks.rs` 拆分：`temp_dir` 等 29 个函数（纯搬移，逻辑不变）。
use super::*;
use std::time::Duration;
use std::time::UNIX_EPOCH;

pub(crate) fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("agf-scheduler-{tag}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("建临时目录");
    dir
}

pub(crate) fn candidate(name: &str, age_days: u64, bytes: u64) -> ArchiveCandidate {
    ArchiveCandidate {
        path: PathBuf::from(name),
        name: name.to_string(),
        bytes,
        modified: UNIX_EPOCH,
        age_days,
        sha256: content_hash(name.as_bytes()),
    }
}

pub(crate) fn snapshot(name: &str, runs: u64, failures: u64, last_millis: u64) -> TaskSnapshot {
    TaskSnapshot { name: name.to_string(), runs, failures, last_millis }
}

// ---- 任务目录 ----

#[test]
pub(crate) fn catalog_covers_exactly_the_eight_tasks() {
    let names: Vec<&str> = catalog().iter().map(|d| d.name).collect();
    assert_eq!(names, TASK_NAMES.to_vec(), "任务目录必须与 TASK_NAMES 一致且顺序稳定");
    let mut unique = names.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), 8, "任务名不得重复");
}

#[test]
pub(crate) fn catalog_notes_state_required_configuration() {
    for descriptor in catalog() {
        assert!(!descriptor.note.trim().is_empty(), "{} 的 note 不能为空", descriptor.name);
    }
    let log_pull = catalog().into_iter().find(|d| d.name == "log-pull").expect("log-pull 必须在册");
    assert!(log_pull.note.contains("sources:read/write"), "控制台源的服务权限必须写在 note 里");
    let archive = catalog().into_iter().find(|d| d.name == "cold-archive").expect("cold-archive 必须在册");
    assert!(archive.note.contains("AGF_S3_") && archive.note.contains("降级"));
}

#[test]
pub(crate) fn task_outcome_status_labels_are_distinct() {
    assert_eq!(TaskOutcome::ok("a").status_label(), "ok");
    assert_eq!(TaskOutcome::skipped("b").status_label(), "skipped");
    assert_eq!(TaskOutcome::degraded("c").status_label(), "degraded");
    assert_eq!(TaskOutcome::failed("d").status_label(), "failed");
    assert!(TaskOutcome::skipped("未配置").ok, "skip 不是失败");
    assert!(!TaskOutcome::failed("不可达").ok);
    let with_artifact = TaskOutcome::ok("done").with_artifact("/tmp/a.json");
    assert!(with_artifact.summary().contains("/tmp/a.json"));
}

// ---- log-pull 模板库（内置 18 条 vs 内置 + parsers/ 117 条） ----

/// `parsers/*/samples.json` 里声明 `http-pull` 协议的样本（`(key, 载荷行)`）。
pub(crate) fn http_pull_samples(root: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(root.join("parsers")) else { return out };
    let mut dirs: Vec<PathBuf> = entries.filter_map(|e| e.ok().map(|e| e.path())).filter(|p| p.is_dir()).collect();
    dirs.sort();
    for dir in dirs {
        let Ok(text) = std::fs::read_to_string(dir.join("samples.json")) else { continue };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else { continue };
        let Some(map) = value.get("samples").and_then(|v| v.as_object()) else { continue };
        for (key, entry) in map {
            let protocol = entry.get("protocol").and_then(|v| v.as_str()).unwrap_or_default();
            if !protocol.eq_ignore_ascii_case("http-pull") {
                continue;
            }
            let line = entry.get("line").and_then(|v| v.as_str()).unwrap_or_default().trim();
            if !line.is_empty() {
                out.push((key.clone(), line.to_string()));
            }
        }
    }
    out
}

/// 回归模拟器实测缺口：`log-pull` 只加载内置模板 ⇒ 仓库自己的 `http-pull` 样本 0/2 命中。
///
/// 修复后（[`build_log_pull_registry`]：内置 + `parsers/`）必须 2/2 命中。
#[test]
pub(crate) fn log_pull_registry_covers_http_pull_samples_that_builtins_miss() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    let parsers = root.join("parsers");
    let samples = http_pull_samples(&root);
    assert!(!samples.is_empty(), "parsers/*/samples.json 里必须有声明 http-pull 的样本（log-pull 验证前提）");

    // 修复前 log-pull 实际使用的注册表
    let mut builtins = ParserRegistry::with_builtins();
    let builtin_hits = samples
        .iter()
        .filter(|(_, line)| builtins.match_raw(line, IngestProtocol::HttpPull, None, None).matched)
        .count();
    assert!(
        builtin_hits < samples.len(),
        "内置模板本应漏掉部分 http-pull 样本（{} 条全命中则本用例失去意义）",
        samples.len()
    );

    let mut registry = build_log_pull_registry(&parsers);
    assert!(
        registry.all().len() > builtins.all().len(),
        "log-pull 必须加载 parsers/ 下的 YAML 模板（内置 {} 条，实际 {} 条）",
        builtins.all().len(),
        registry.all().len()
    );
    let mut missed = Vec::new();
    for (key, line) in &samples {
        let (lines, parsed, failed) = parse_log_text(&mut registry, IngestProtocol::HttpPull, line);
        if lines != 1 || parsed != 1 || failed != 0 {
            missed.push(key.clone());
        }
    }
    assert!(missed.is_empty(), "加载 parsers/ 后这些 http-pull 样本仍未命中：{missed:?}");
}

// ---- 配置解析 ----

#[test]
pub(crate) fn parse_pull_urls_empty_yields_empty() {
    assert!(parse_pull_urls("").is_empty());
    assert!(parse_pull_urls("   ").is_empty());
    assert!(parse_pull_urls(",,").is_empty());
}

#[test]
pub(crate) fn parse_pull_urls_trims_spaces_and_keeps_order() {
    let urls = parse_pull_urls(" http://a/log , http://b/log,http://c/log ");
    assert_eq!(urls, vec!["http://a/log".to_string(), "http://b/log".to_string(), "http://c/log".to_string()]);
}

#[test]
pub(crate) fn parse_pull_urls_dedupes_and_drops_blanks() {
    let urls = parse_pull_urls("http://a, ,http://a,http://b,");
    assert_eq!(urls, vec!["http://a".to_string(), "http://b".to_string()]);
}

#[test]
pub(crate) fn env_flag_defaults_and_truthy_values() {
    assert!(env_flag(None, true));
    assert!(!env_flag(None, false));
    assert!(env_flag(Some(""), true), "空值视为未设置");
    assert!(env_flag(Some("ON"), false));
    assert!(env_flag(Some("yes"), false));
    assert!(!env_flag(Some("0"), true));
    assert!(!env_flag(Some("off"), true));
}

#[test]
pub(crate) fn api_url_joins_without_double_slash() {
    assert_eq!(api_url("http://127.0.0.1:9100/", "/api/v1/assets/stats"), "http://127.0.0.1:9100/api/v1/assets/stats");
    assert_eq!(api_url("http://127.0.0.1:9100", "/api/v1/assets/stats"), "http://127.0.0.1:9100/api/v1/assets/stats");
}

#[test]
pub(crate) fn ts_slug_is_utc_sortable() {
    let at = chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("固定时间戳合法");
    assert_eq!(ts_slug(at), "20231114T221320Z");
    let earlier = chrono::DateTime::from_timestamp(1_600_000_000, 0).expect("固定时间戳合法");
    assert!(ts_slug(earlier) < ts_slug(at), "slug 字典序必须等于时间序");
}

// ---- asset-inventory ----

#[test]
pub(crate) fn asset_stats_summary_reads_inventory_fields() {
    let raw = r#"{"inventory":{"total":42,"by_kind":{"web":40,"ai":2}},"platform":{"agents":3}}"#;
    let (summary, value) = summarize_asset_stats(raw).expect("合法 JSON");
    assert!(summary.has_inventory);
    assert_eq!(summary.total, 42);
    assert_eq!(summary.inventory_fields, 2);
    assert_eq!(summary.raw_bytes, raw.len());
    assert_eq!(value["platform"]["agents"], 3);
    assert!(asset_summary_text(&summary).contains("总量 42"));
}

#[test]
pub(crate) fn asset_stats_summary_handles_missing_inventory() {
    let raw = r#"{"platform":{"agents":3}}"#;
    let (summary, _) = summarize_asset_stats(raw).expect("合法 JSON");
    assert!(!summary.has_inventory);
    assert_eq!(summary.total, 0);
    assert!(asset_summary_text(&summary).contains("无 inventory"));
    assert!(summarize_asset_stats("not-json").is_none());
}

// ---- log-pull ----

#[test]
pub(crate) fn log_parse_counts_matched_and_unmatched_lines() {
    let mut registry = ParserRegistry::with_builtins();
    let text = "<34>Feb 21 10:23:45 h sshd[1]: Failed password\n\n这是一条完全无法识别的自由文本\n";
    let (lines, parsed, failed) = parse_log_text(&mut registry, IngestProtocol::Syslog, text);
    assert_eq!(lines, 2, "空行不计入");
    assert!(parsed >= 1, "syslog 行必须命中内置模板");
    assert!(failed >= 1, "自由文本必须计入未命中");
    assert_eq!(parsed + failed, lines);
}

#[tokio::test]
pub(crate) async fn log_pull_without_sources_is_skipped_not_failed() {
    let dir = temp_dir("logpull-skip");
    let outcome = run_log_pull(&reqwest::Client::new(), "  ,  ", None, &dir).await;
    assert!(outcome.ok, "未配置拉取源不得计失败");
    assert!(outcome.skipped);
    assert!(outcome.note.contains("未配置拉取源"));
    assert!(outcome.artifacts.is_empty(), "skip 不落产物");
    assert_eq!(std::fs::read_dir(&dir).expect("读目录").count(), 0, "skip 不写文件");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
pub(crate) fn log_pull_text_summarizes_stats() {
    let stats = LogPullStats { sources: 3, fetched: 2, lines: 10, parsed: 8, failed: 2, per_source: Vec::new() };
    let text = log_pull_text(&stats);
    assert!(text.contains("2/3") && text.contains("10") && text.contains('8'));
}

// ---- cold-archive ----

#[test]
pub(crate) fn select_expired_uses_strict_day_window() {
    let candidates = vec![candidate("old.json", 9, 10), candidate("week.json", 7, 10), candidate("new.json", 1, 10)];
    let expired = select_expired(&candidates, 7);
    let names: Vec<&str> = expired.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, vec!["old.json"], "严格超过阈值才归档");
    assert_eq!(select_expired(&candidates, 0).len(), 3);
}

#[test]
pub(crate) fn scan_archive_candidates_reads_size_hash_and_age() {
    let dir = temp_dir("archive-scan");
    let path = dir.join("report-20200101T000000Z.md");
    std::fs::write(&path, b"hello").expect("写文件");
    let old = SystemTime::now() - Duration::from_hours(9 * 24);
    let handle = std::fs::File::options().write(true).open(&path).expect("打开文件");
    handle.set_modified(old).expect("设置 mtime");
    drop(handle);

    let candidates = scan_archive_candidates(&dir, SystemTime::now()).expect("扫描目录");
    assert_eq!(candidates.len(), 1);
    let first = candidates.first().expect("有候选");
    assert_eq!(first.name, "report-20200101T000000Z.md");
    assert_eq!(first.bytes, 5);
    assert_eq!(first.sha256, content_hash(b"hello"));
    assert!(first.age_days >= 8, "age_days 至少 8，实际 {}", first.age_days);
    assert_eq!(select_expired(&candidates, 7).len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
pub(crate) fn gzip_roundtrip_preserves_bytes() {
    let payload = b"aiguardfabric-cold-archive-".repeat(64);
    let gz = gzip_payload(&payload).expect("gzip 成功");
    assert!(gz.starts_with(&[0x1f, 0x8b]), "必须是 gzip 魔数");
    assert!(gz.len() < payload.len(), "重复内容应被压缩");
    assert_eq!(gunzip_payload(&gz).expect("gunzip 成功"), payload);
}

#[test]
pub(crate) fn archive_key_appends_gz_suffix() {
    assert_eq!(archive_key("report-1.md"), "report-1.md.gz");
    assert_eq!(archive_key("a"), "a.gz");
}

#[test]
pub(crate) fn manifest_totals_are_stable_and_content_bound() {
    let entries = vec![
        ArchiveEntry { name: "a.md".to_string(), bytes: 10, sha256: content_hash(b"a"), age_days: 8 },
        ArchiveEntry { name: "b.md".to_string(), bytes: 32, sha256: content_hash(b"b"), age_days: 9 },
    ];
    let (files, bytes, hash) = manifest_totals(&entries);
    assert_eq!((files, bytes), (2, 42));
    let (again_files, again_bytes, again_hash) = manifest_totals(&entries.clone());
    assert_eq!((again_files, again_bytes, again_hash.clone()), (files, bytes, hash.clone()));
    assert_eq!(hash.len(), 64, "SHA-256 hex 长度");
    let mut changed = entries;
    changed[1].sha256 = content_hash(b"b2");
    assert_ne!(manifest_totals(&changed).2, hash, "内容变了清单哈希必须变");
}

#[test]
pub(crate) fn archive_entry_from_candidate_keeps_identity() {
    let candidate = candidate("report-20200101T000000Z.md", 12, 99);
    let entry = ArchiveEntry::from_candidate(&candidate);
    assert_eq!(entry.name, candidate.name);
    assert_eq!(entry.bytes, 99);
    assert_eq!(entry.age_days, 12);
    assert_eq!(entry.sha256, candidate.sha256);
}

#[test]
pub(crate) fn archive_summary_marks_local_degradation() {
    let manifest = ArchiveManifest {
        files: 2,
        bytes: 128,
        backend: "local".to_string(),
        degraded_local: true,
        manifest_sha256: "abc".to_string(),
        ..ArchiveManifest::default()
    };
    let text = archive_summary_text(&manifest);
    assert!(text.contains("降级为本地") && text.contains("128"));
}

#[tokio::test]
pub(crate) async fn cold_archive_skips_when_nothing_is_expired() {
    let dir = temp_dir("archive-skip");
    std::fs::write(dir.join("fresh.md"), b"fresh").expect("写文件");
    let job = ArchiveJob {
        report_dir: dir.clone(),
        archive_dir: dir.join("archive"),
        store: std::sync::Arc::new(agf_storage::objectstore::MemoryObjectStore::new()),
        store_note: Some("测试替身：无 S3".to_string()),
        after_days: 7,
        delete_local: false,
    };
    let outcome = run_cold_archive(job, crate::Partition::default()).await;
    assert!(outcome.ok && outcome.skipped, "没有到期文件时如实跳过");
    assert!(outcome.note.contains("没有超过"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
pub(crate) async fn cold_archive_degrades_to_local_gzip_and_labels_it() {
    let dir = temp_dir("archive-degrade");
    let path = dir.join("report-20200101T000000Z.md");
    std::fs::write(&path, b"payload-for-archive").expect("写文件");
    let handle = std::fs::File::options().write(true).open(&path).expect("打开文件");
    handle.set_modified(SystemTime::now() - Duration::from_hours(30 * 24)).expect("设置 mtime");
    drop(handle);

    let archive_dir = dir.join("archive");
    let job = ArchiveJob {
        report_dir: dir.clone(),
        archive_dir: archive_dir.clone(),
        store: std::sync::Arc::new(agf_storage::objectstore::MemoryObjectStore::new()),
        store_note: Some("未配置 AGF_S3_*，降级为本地".to_string()),
        after_days: 7,
        delete_local: false,
    };
    let outcome = run_cold_archive(job, crate::Partition::default()).await;
    assert!(outcome.ok, "本地降级不算失败：{}", outcome.note);
    assert!(outcome.degraded, "必须标注降级");
    assert!(outcome.note.contains("降级为本地"), "note 必须写明降级：{}", outcome.note);
    let gz = archive_dir.join("report-20200101T000000Z.md.gz");
    assert!(gz.is_file(), "本地归档产物必须存在");
    let data = std::fs::read(&gz).expect("读 gz");
    assert_eq!(gunzip_payload(&data).expect("解压"), b"payload-for-archive");
    assert!(path.is_file(), "默认不删本地原文件");
    assert!(dir.join("archive-").is_dir() || latest_file(&dir, "archive-", ".json").is_some(), "清单必须落盘");
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- report-generate ----

#[test]
pub(crate) fn render_report_marks_missing_data_explicitly() {
    let input = ReportInput {
        generated_at: "2024-01-01T00:00:00Z".to_string(),
        rules_dir: "/nonexistent/rules".to_string(),
        ..ReportInput::default()
    };
    let markdown = render_report(&input);
    assert!(markdown.starts_with("# AIGuardFabric 周期报表"));
    assert!(markdown.contains(NO_DATA), "缺数据必须写本期无数据");
    assert!(markdown.contains("## 任务执行表"), "任务执行表小节必须存在");
    assert!(!markdown.contains("| 任务 | runs | failures | last_millis |"), "无任务时不得打印空表头");
}
