//! `history` 单元测试（自 `history.rs` 拆出，断言与原文件完全一致）。

use super::*;

/// 临时目录（每个用例一个，避免并行测试互相踩）。
fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "agf-risk-history-{tag}-{}-{}",
        std::process::id(),
        Timestamp::now().unix_millis()
    ));
    std::fs::create_dir_all(&dir).expect("创建临时目录失败");
    dir
}

fn at(secs: i64) -> Timestamp {
    Timestamp::from_unix_secs(secs).expect("时间戳构造失败")
}

fn sample(tenant: TenantId, secs: i64, value: f64) -> Sample {
    Sample::new(tenant, at(secs), value)
}

/// 精确比较（避免 `clippy::float_cmp`，也让失败信息可读）。
fn same(a: f64, b: f64) -> bool {
    (a - b).abs() < 1e-9
}

#[test]
fn roundtrip_through_disk_preserves_normalized_points() {
    let dir = temp_dir("roundtrip");
    let path = dir.join("state").join(FILE_NAME);
    let tenant = TenantId::default_tenant();
    let other = TenantId::new();
    // 3 个点：启动点 + 跨小时两点（同一小时内两个点会被合并，见下一个用例）
    let samples =
        vec![sample(tenant, 1_700_000_000, 0.0), sample(tenant, 1_700_007_200, 4.0), sample(other, 1_700_000_000, 0.0)];
    save_to(&path, &samples);
    assert!(path.exists(), "原子写必须落地到目标路径");

    let loaded = load_from(&path).expect("加载不应报错");
    let expected = normalize(samples);
    assert_eq!(loaded.len(), expected.len(), "往返点数必须一致: {loaded:?}");
    for (index, expected_sample) in expected.iter().enumerate() {
        let actual = loaded[index];
        assert_eq!(actual.tenant_id, expected_sample.tenant_id);
        assert_eq!(actual.ts, expected_sample.ts);
        assert!(same(actual.value, expected_sample.value), "值必须一致: {actual:?}");
    }
    // 目录里不留临时文件（临时文件必须被 rename 掉）
    let leftovers: Vec<String> = std::fs::read_dir(path.parent().expect("有父目录"))
        .expect("读取目录失败")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().to_string())
        .filter(|name| name.contains(".tmp-"))
        .collect();
    assert!(leftovers.is_empty(), "不得残留临时文件: {leftovers:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn missing_file_is_empty_and_not_an_error() {
    let dir = temp_dir("missing");
    let path = dir.join("state").join(FILE_NAME);
    assert!(!path.exists());
    let loaded = load_from(&path).expect("文件不存在不是错误");
    assert!(loaded.is_empty(), "首次启动必须是空历史而不是报错: {loaded:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn corrupt_file_warns_and_returns_empty_without_panicking() {
    let dir = temp_dir("corrupt");
    for (tag, content) in [
        ("not-json", "这不是 JSON"),
        ("truncated", "{\"version\":1,\"samples\":[{\"tenant_id\":\"x\""),
        ("empty", ""),
        ("wrong-shape", "{\"foo\":1}"),
    ] {
        let path = dir.join(format!("{tag}.json"));
        std::fs::write(&path, content).expect("写坏文件失败");
        assert!(load_from(&path).is_err(), "{tag} 拒绝读取并阻止自动覆盖");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), content);
        assert!(path.exists(), "{tag} 原文件不得被删除（交人工处置）");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn future_format_version_is_refused_instead_of_guessed() {
    let dir = temp_dir("future");
    let path = dir.join(FILE_NAME);
    let content = format!(
        "{{\"version\":{},\"samples\":[{{\"tenant_id\":\"00000000-0000-0000-0000-000000000001\",\"ts\":\"2026-05-01T00:00:00.000Z\",\"value\":1.0}}]}}",
        FORMAT_VERSION + 1
    );
    std::fs::write(&path, &content).expect("写文件失败");
    assert!(load_from(&path).is_err(), "不得猜读未来格式或覆盖原始数据");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), content);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn legacy_file_is_archived_without_presenting_uncertain_observations() {
    let dir = temp_dir("bare");
    let path = dir.join(FILE_NAME);
    let content =
        "[{\"tenant_id\":\"00000000-0000-0000-0000-000000000001\",\"ts\":\"2026-05-01T00:00:00.000Z\",\"value\":7.0}]";
    std::fs::write(&path, content).expect("写文件失败");
    let loaded = load_from(&path).expect("裸数组必须被接受");
    assert!(loaded.is_empty(), "历史零值无法区分是否真实，重新观测");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), content, "读取不能修改原文件");
    let archived = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(Result::ok)
        .find(|entry| entry.file_name().to_string_lossy().contains(".pre-v2-"))
        .unwrap();
    assert_eq!(std::fs::read_to_string(archived.path()).unwrap(), content);
    assert!(load_from(&path).unwrap().is_empty(), "归档可安全重试");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn hour_bucket_keeps_only_the_latest_point() {
    let tenant = TenantId::default_tenant();
    // 同一小时（3600s 桶）内三个点 + 下一小时一个点
    let samples = vec![
        sample(tenant, 1_700_000_000, 0.0),
        sample(tenant, 1_700_000_600, 3.0),
        sample(tenant, 1_700_001_200, 5.0),
        sample(tenant, 1_700_004_000, 9.0),
    ];
    let normalized = normalize(samples);
    assert_eq!(normalized.len(), 2);
    assert_eq!(normalized[0].ts, at(1_700_001_200));
    assert!(same(normalized[0].value, 5.0));
    assert_eq!(normalized[1].ts, at(1_700_004_000));
}

#[test]
fn first_observation_follows_the_same_hourly_rollup() {
    let tenant = TenantId::default_tenant();
    // 启动点与当前点落在**同一个**小时桶（进程启动后立刻被 /overview 采样）
    let samples = vec![sample(tenant, 1_700_000_000, 0.0), sample(tenant, 1_700_000_900, 6.0)];
    let normalized = normalize(samples);
    assert_eq!(normalized.len(), 1);
    assert!(same(normalized[0].value, 6.0));
}

#[test]
fn first_observation_is_preserved_on_load() {
    let dir = temp_dir("start-zero");
    let path = dir.join(FILE_NAME);
    // 首次观测必须原样往返
    let tenant = TenantId::default_tenant();
    save_to(&path, &[sample(tenant, 1_700_000_000, 42.0), sample(tenant, 1_700_007_200, 7.0)]);
    let loaded = load_from(&path).expect("加载失败");
    assert_eq!(loaded.len(), 2, "{loaded:?}");
    assert!(same(loaded[0].value, 42.0), "不得把首次观测覆盖成零: {loaded:?}");
    assert!(same(loaded[1].value, 7.0));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cap_is_enforced_per_tenant_from_the_oldest() {
    let tenant = TenantId::default_tenant();
    let other = TenantId::new();
    let mut samples: Vec<Sample> = (0..(MAX_SAMPLES_PER_TENANT as i64 + 20))
        .map(|index| sample(tenant, 1_700_000_000 + index * 3_600, index as f64))
        .collect();
    // 另一个租户只有 2 个点：裁剪必须**按租户**独立进行
    samples.push(sample(other, 1_700_000_000, 0.0));
    samples.push(sample(other, 1_700_007_200, 1.0));

    let normalized = normalize(samples);
    let grouped = group_by_tenant(&normalized);
    let capped = grouped.get(&tenant).expect("必须有该租户");
    assert_eq!(capped.len(), MAX_SAMPLES_PER_TENANT, "超出上限必须裁剪");
    // 裁掉的是最旧的点：首个保留点的 ts 后移了 20 小时
    assert_eq!(capped[0].ts, at(1_700_000_000 + 20 * 3_600), "必须从最旧开始裁");
    assert_eq!(grouped.get(&other).map(Vec::len), Some(2), "别的租户不受影响");
}

#[test]
fn merge_sets_is_a_rollup_union() {
    let tenant = TenantId::default_tenant();
    let existing = vec![sample(tenant, 1_700_000_000, 0.0), sample(tenant, 1_700_007_200, 2.0)];
    let incoming = vec![sample(tenant, 1_700_007_500, 5.0), sample(tenant, 1_700_014_400, 8.0)];
    let merged = merge_sets(&existing, &incoming);
    assert_eq!(merged.len(), 3, "同桶（1_700_007_200/1_700_007_500）必须合并: {merged:?}");
    assert_eq!(merged[0].ts, at(1_700_000_000), "最早的点仍是启动点");
    assert!(same(merged[1].value, 5.0), "同桶取更晚的值");
    assert!(same(merged[2].value, 8.0));
}

#[test]
fn path_precedence_prefers_env_override_then_data_dir_then_default() {
    let override_path = OsStr::new("D:/tmp/custom.json");
    assert_eq!(path_for(Some(OsStr::new("D:/agf/data")), Some(override_path)), PathBuf::from(override_path));
    // 空串视为未设置（部署脚本 `VAR=` 很常见）
    assert_eq!(
        path_for(Some(OsStr::new("D:/agf/data")), Some(OsStr::new(""))),
        PathBuf::from("D:/agf/data/state/risk-history.json")
    );
    assert_eq!(path_for(Some(OsStr::new("D:/agf/data")), None), PathBuf::from("D:/agf/data/state/risk-history.json"));
    assert_eq!(path_for(None, None), PathBuf::from("data/state/risk-history.json"));
    assert_eq!(path_for(Some(OsStr::new("")), None), PathBuf::from("data/state/risk-history.json"));
    // 无覆盖配置时的路径须与文件名一致；测试不得假定宿主进程没有环境覆盖。
    assert!(path_for(None, None).ends_with(Path::new(STATE_DIR).join(FILE_NAME)));
}

#[test]
fn save_creates_missing_directories_and_overwrites_previous_content() {
    let dir = temp_dir("mkdir");
    let path = dir.join("deep").join("nested").join(FILE_NAME);
    let tenant = TenantId::default_tenant();
    save_to(&path, &[sample(tenant, 1_700_000_000, 0.0)]);
    assert!(path.exists(), "父目录必须被自动创建");
    save_to(&path, &[sample(tenant, 1_700_000_000, 0.0), sample(tenant, 1_700_007_200, 3.0)]);
    let loaded = load_from(&path).expect("加载失败");
    assert_eq!(loaded.len(), 2, "后一次写入必须整体替换前一次: {loaded:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unwritable_path_only_warns_and_leaves_no_partial_file() {
    let dir = temp_dir("unwritable");
    // 父路径是一个**文件**：create_dir_all 必然失败
    let blocker = dir.join("blocker");
    std::fs::write(&blocker, "not a directory").expect("写占位文件失败");
    let target = blocker.join(STATE_DIR).join(FILE_NAME);
    save_to(&target, &[sample(TenantId::default_tenant(), 1_700_000_000, 0.0)]);
    assert!(!target.exists(), "写入失败不得产生半个文件");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn from_points_builds_samples_for_one_tenant() {
    let tenant = TenantId::default_tenant();
    let samples = from_points(tenant, [(at(1_700_000_000), 0.0), (at(1_700_007_200), 2.0)]);
    assert_eq!(samples.len(), 2);
    assert!(samples.iter().all(|sample| sample.tenant_id == tenant));
    let grouped = group_by_tenant(&samples);
    assert_eq!(grouped.get(&tenant).map(Vec::len), Some(2));
    // 分组结果必须按时间升序（回填 state::RiskHistory 的前提）
    let first = grouped.get(&tenant).expect("有该租户");
    assert!(first[0].ts <= first[1].ts);
    // 空输入 ⇒ 空输出（不 panic）
    assert!(from_points(tenant, std::iter::empty()).is_empty());
}
