#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! `agf-plugin` 的端到端与错误分类测试。
//!
//! 关键点：**这里用的全是真实动态库**——示例插件由 `cargo test -p agf-plugin` 通过
//! dev-dependency 真正编译出来（`target/debug/agf_plugin_example.dll`），
//! 不存在"用假函数指针假装加载"的测试。
//!
//! 覆盖：描述符校验、ABI 版本门禁、加载失败分类、缺符号、真实调用（返回值 + 副作用）、
//! 卸载（drop 真把库卸了）、路径解析、以及"缺插件时宿主仍正常启动"的降级。

use std::path::Path;
use std::path::PathBuf;

use agf_plugin::AGF_PLUGIN_ABI_VERSION;
use agf_plugin::PluginError;
use agf_plugin::PluginKind;
use agf_plugin::PluginLoader;
use agf_plugin::PluginMetadata;
use agf_plugin::PluginRegistry;
use agf_plugin::plugin_file_name;
use agf_plugin::plugin_file_suffix;

// ---------------------------------------------------------------------------
// 辅助
// ---------------------------------------------------------------------------

/// 仓库根（`crates/agf-plugin` 的上两级）。
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}

/// 在本进程里只解析一次（多个并行测试不会各跑一遍 cargo）。
fn example_plugin_path() -> PathBuf {
    static CACHE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    CACHE.get_or_init(resolve_example_plugin_path).clone()
}

/// 解析示例插件动态库；找不到就**自己构建一份**。
///
/// 为什么需要"自己构建"这条回退：**`cargo test` 不会构建 cdylib**（实测确认：
/// 即使 `crate-type = ["cdylib"]`，`cargo test -p agf-plugin-example` 也只产出
/// 测试用 rlib，`target/debug/agf_plugin_example.dll` 不会出现）。因此：
///
/// 1. 先找 `target/debug` 下由 `cargo build -p agf-plugin-example` 产出的产物（正常路径）；
/// 2. 没有就跑一次 `cargo build -p agf-plugin-example --target-dir target/plugin-e2e`——
///    **换一个 target 目录 ⇒ 换一把构建锁**，不会与正在运行的 `cargo test` 死锁。
///    产物由 cargo 缓存，后续运行几乎零成本。
///
/// 这条路径**绝不静默跳过**：构建失败就红（这正是要防的"假绿灯"）。
fn resolve_example_plugin_path() -> PathBuf {
    let root = workspace_root();
    let target = std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| root.join("target"), PathBuf::from);
    if let Some(path) = find_plugin_artifact(&target) {
        return path;
    }

    let fallback_target = root.join("target").join("plugin-e2e");
    let status = std::process::Command::new(env!("CARGO"))
        .current_dir(&root)
        .args(["build", "-p", "agf-plugin-example", "--target-dir"])
        .arg(&fallback_target)
        .status()
        .expect("执行 cargo build -p agf-plugin-example");
    assert!(status.success(), "`cargo build -p agf-plugin-example` 失败（{status}）：端到端测试需要真实 cdylib");
    find_plugin_artifact(&fallback_target).unwrap_or_else(|| {
        panic!(
            "已执行 cargo build，但在 {} 下仍未找到 `*agf_plugin_example*.{}`",
            fallback_target.display(),
            plugin_file_suffix()
        )
    })
}

/// 在 `<target>/{debug,debug/deps,debug/examples}` 里找示例插件动态库。
fn find_plugin_artifact(target: &Path) -> Option<PathBuf> {
    let suffix = plugin_file_suffix();
    for sub in ["debug", "debug/deps", "debug/examples"] {
        let dir = target.join(sub);
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut found: Vec<PathBuf> = entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.is_file())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.contains("agf_plugin_example") && name.ends_with(&format!(".{suffix}")))
            })
            .collect();
        found.sort();
        if let Some(path) = found.into_iter().next() {
            return Some(path);
        }
    }
    None
}

/// 把示例插件复制到独立临时目录，返回（临时目录, 复制后的路径）。
///
/// 复制是**必须的**：同一个路径被并发测试同时加载时，Windows 的模块引用计数不会归零，
/// "drop 是否真的卸载"就无法观察。
fn staged_example_plugin(name: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("创建临时目录");
    let destination = dir.path().join(name);
    std::fs::copy(example_plugin_path(), &destination).expect("复制示例插件动态库");
    (dir, destination)
}

fn metadata(
    name: &str,
    version: &str,
    kind: PluginKind,
    has_normalize: bool,
    has_notify: bool,
    has_free_string: bool,
) -> PluginMetadata {
    PluginMetadata {
        abi_version: AGF_PLUGIN_ABI_VERSION,
        kind,
        name: name.to_string(),
        version: version.to_string(),
        has_normalize,
        has_notify,
        has_free_string,
        reserved: 0,
    }
}

/// 一个"确实存在、但不可能导出我们符号"的系统动态库（用于验证缺符号分类）。
fn system_library_path() -> Option<PathBuf> {
    if cfg!(target_os = "windows") {
        let root = std::env::var_os("SystemRoot").map_or_else(|| PathBuf::from("C:\\Windows"), PathBuf::from);
        let path = root.join("System32").join("kernel32.dll");
        return path.is_file().then_some(path);
    }
    let candidates = [
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/lib64/libc.so.6",
        "/usr/lib/libc.so.6",
        "/usr/lib/x86_64-linux-gnu/libc.so.6",
        "/usr/lib/libSystem.B.dylib",
    ];
    candidates.iter().map(PathBuf::from).find(|path| path.is_file())
}

// ---------------------------------------------------------------------------
// 1. 描述符校验（纯逻辑）
// ---------------------------------------------------------------------------

#[test]
fn wellformed_normalizer_descriptor_is_accepted() {
    let meta = metadata("agf-plugin-example", "0.1.0", PluginKind::Normalizer, true, true, true);
    assert!(meta.validate().is_ok(), "{meta:?}");
}

#[test]
fn malformed_descriptors_are_rejected_field_by_field() {
    let base = || metadata("demo", "1.0.0", PluginKind::Normalizer, true, false, true);

    let mut zero_abi = base();
    zero_abi.abi_version = 0;
    assert!(matches!(zero_abi.validate(), Err(PluginError::BadDescriptor(_))));

    let mut reserved = base();
    reserved.reserved = 1;
    assert!(reserved.validate().unwrap_err().to_string().contains("保留位"));

    let mut empty_name = base();
    empty_name.name = String::new();
    assert!(empty_name.validate().is_err());

    let mut bad_name = base();
    bad_name.name = "demo plugin".to_string();
    assert!(bad_name.validate().unwrap_err().to_string().contains("非法字符"));

    let mut bad_version = base();
    bad_version.version = "1.0.0 beta".to_string();
    assert!(bad_version.validate().unwrap_err().to_string().contains("可见 ASCII"));

    let mut no_normalize = base();
    no_normalize.has_normalize = false;
    assert!(no_normalize.validate().unwrap_err().to_string().contains("normalize"));

    let mut no_free = base();
    no_free.has_free_string = false;
    assert!(no_free.validate().unwrap_err().to_string().contains("free_string"));

    let notifier = metadata("demo", "1.0.0", PluginKind::Notifier, false, false, false);
    assert!(notifier.validate().unwrap_err().to_string().contains("notify"));

    assert!(PluginKind::from_u32(0).is_none());
    assert!(PluginKind::from_u32(99).is_none());
    assert_eq!(PluginKind::from_u32(1), Some(PluginKind::Normalizer));
    assert_eq!(PluginKind::from_u32(2), Some(PluginKind::Notifier));
}

// ---------------------------------------------------------------------------
// 2. ABI 门禁与路径解析
// ---------------------------------------------------------------------------

#[test]
fn abi_gate_only_accepts_declared_versions() {
    let strict = PluginLoader::new();
    assert!(strict.accepts_abi(AGF_PLUGIN_ABI_VERSION));
    assert!(!strict.accepts_abi(AGF_PLUGIN_ABI_VERSION + 1));
    assert_eq!(strict.supported_abi(), &[AGF_PLUGIN_ABI_VERSION]);

    let permissive = PluginLoader::with_supported_abi([2, 3]);
    assert!(permissive.accepts_abi(2));
    assert!(permissive.accepts_abi(3));
    assert!(!permissive.accepts_abi(AGF_PLUGIN_ABI_VERSION));
}

#[test]
fn plugin_file_name_follows_platform_convention() {
    let name = plugin_file_name("demo");
    assert!(name.ends_with(plugin_file_suffix()), "{name}");
    if cfg!(target_os = "windows") {
        assert_eq!(name, "demo.dll");
    } else {
        assert!(name.starts_with("lib"), "{name}");
    }
}

#[test]
fn resolve_in_dir_finds_existing_plugin_and_reports_missing() {
    let dir = tempfile::tempdir().expect("临时目录");
    let expected = dir.path().join(plugin_file_name("demo"));
    std::fs::write(&expected, b"placeholder").expect("写占位文件");

    let resolved = PluginLoader::resolve_in_dir(dir.path(), "demo").expect("应能解析到动态库");
    assert_eq!(resolved, expected);
    assert!(PluginLoader::resolve_in_dir(dir.path(), "nope").is_none());

    let loader = PluginLoader::new();
    let err = loader.load_by_name(dir.path(), "nope").unwrap_err();
    assert!(err.is_not_found(), "{err}");
}

// ---------------------------------------------------------------------------
// 3. 加载失败分类（真实文件系统 / 真实 dlopen）
// ---------------------------------------------------------------------------

#[test]
fn missing_file_is_reported_as_not_found() {
    let dir = tempfile::tempdir().expect("临时目录");
    let missing = dir.path().join(plugin_file_name("does-not-exist"));
    let err = PluginLoader::new().load(&missing).unwrap_err();
    assert!(err.is_not_found(), "{err}");
    assert!(err.to_string().contains("不存在"), "{err}");
}

#[test]
fn directory_is_reported_as_not_a_file() {
    let dir = tempfile::tempdir().expect("临时目录");
    let err = PluginLoader::new().load(dir.path()).unwrap_err();
    assert!(matches!(err, PluginError::NotAFile(_)), "{err}");
}

#[test]
fn garbage_file_is_reported_as_load_failure() {
    let dir = tempfile::tempdir().expect("临时目录");
    let junk = dir.path().join(plugin_file_name("junk"));
    std::fs::write(&junk, b"this is definitely not a dynamic library").expect("写垃圾文件");
    let err = PluginLoader::new().load(&junk).unwrap_err();
    assert!(matches!(err, PluginError::Load { .. }), "{err}");
    assert!(err.to_string().contains("动态库加载失败"), "{err}");
}

#[test]
fn real_library_without_descriptor_symbol_is_missing_symbol() {
    let path = system_library_path().expect("未能定位一个系统动态库（用于验证「缺符号」分类）");
    let err = PluginLoader::new().load(&path).unwrap_err();
    assert!(err.is_missing_symbol(), "{} → {err}", path.display());
    assert!(err.to_string().contains("agf_plugin_descriptor_v1"), "{err}");
}

// ---------------------------------------------------------------------------
// 4. 真实端到端：加载真实 cdylib → 调用 → 断言返回值与副作用
// ---------------------------------------------------------------------------

#[test]
fn example_plugin_loads_and_metadata_is_truthful() {
    let path = example_plugin_path();
    let plugin = PluginLoader::new().load(&path).expect("加载示例插件");
    assert_eq!(plugin.name(), "agf-plugin-example");
    assert_eq!(
        plugin.version(),
        env!("CARGO_PKG_VERSION"),
        "两个 crate 共用工作区版本号（[workspace.package] version）"
    );
    assert_eq!(plugin.kind(), PluginKind::Normalizer);
    assert_eq!(plugin.abi_version(), AGF_PLUGIN_ABI_VERSION);
    assert_eq!(plugin.path(), path.as_path());
    assert!(plugin.metadata().has_normalize);
    assert!(plugin.metadata().has_notify);
}

#[test]
fn example_plugin_normalizes_real_log_line() {
    let plugin = PluginLoader::new().load(&example_plugin_path()).expect("加载示例插件");

    let json = plugin
        .normalize(
            r#"ts=2026-02-21T10:00:00Z src=10.1.2.3 dst=10.9.9.9 dpt=443 action=block rule=WAF-1001 msg="SQL injection attempt""#,
        )
        .expect("调用 normalize");
    let value: serde_json::Value = serde_json::from_str(&json).expect("返回的是合法 JSON");
    assert_eq!(value["@timestamp"], "2026-02-21T10:00:00Z");
    assert_eq!(value["source"]["ip"], "10.1.2.3");
    assert_eq!(value["destination"]["port"], 443);
    assert_eq!(value["event"]["action"], "block");
    assert_eq!(value["event"]["rule"], "WAF-1001");
    assert_eq!(value["message"], "SQL injection attempt");
    assert_eq!(value["agf"]["plugin"], "agf-plugin-example");

    // 插件的业务失败要变成 `PluginError::Call`，并且带上插件自己的 last_error。
    let err = plugin.normalize("foo=1 bar=2").unwrap_err();
    assert!(matches!(err, PluginError::Call(_)), "{err}");
    assert!(err.to_string().contains("没有识别出任何已知字段"), "{err}");
}

#[test]
fn example_plugin_notify_has_real_side_effect() {
    let plugin = PluginLoader::new().load(&example_plugin_path()).expect("加载示例插件");
    let dir = tempfile::tempdir().expect("临时目录");
    let sink = dir.path().join("notify.log");

    plugin.notify(sink.to_str().expect("临时路径是 UTF-8"), "第一条：WAF 拦截").expect("第一条投递成功");
    plugin.notify(sink.to_str().expect("临时路径是 UTF-8"), "第二条：EDR 隔离").expect("第二条投递成功");

    let content = std::fs::read_to_string(&sink).expect("读取通知落盘文件");
    assert_eq!(content, "第一条：WAF 拦截\n第二条：EDR 隔离\n");

    // 写不进去的路径 ⇒ 业务失败（不是 panic），原因来自插件的 last_error。
    let bad = dir.path().join("no-such-dir").join("x.log");
    let err = plugin.notify(bad.to_str().expect("临时路径是 UTF-8"), "会失败").unwrap_err();
    assert!(matches!(err, PluginError::Call(_)), "{err}");
    assert!(err.to_string().contains("last_error"), "{err}");
}

#[test]
fn real_plugin_with_mismatched_abi_is_refused_without_panic() {
    // 真实动态库声明 ABI v1；把宿主收窄到只接受 v2/v3 ⇒ 必须被拒。
    let path = example_plugin_path();
    let loader = PluginLoader::with_supported_abi([2, 3]);
    let err = loader.load(&path).unwrap_err();
    assert!(err.is_abi_mismatch(), "{err}");
    assert!(err.to_string().contains("ABI 版本不匹配"), "{err}");
    assert!(err.to_string().contains("agf-plugin-example"), "{err}");

    // 同一份库在默认装载器下能正常加载 ⇒ 上面拒绝的原因确实是 ABI 版本，不是文件坏了。
    assert!(PluginLoader::new().load(&path).is_ok());

    // 空接受集合 ⇒ 也必须是"明确拒绝"，不是 panic、不是静默通过。
    let nothing = PluginLoader::with_supported_abi([]);
    assert!(nothing.load(&path).unwrap_err().is_abi_mismatch());
}

#[test]
fn dropping_plugin_really_unloads_the_library() {
    let (_dir, staged) = staged_example_plugin(&plugin_file_name("agf_plugin_example"));

    {
        let plugin = PluginLoader::new().load(&staged).expect("加载临时副本");
        assert!(plugin.normalize("src=10.0.0.1").is_ok());
        // plugin 在这里 drop → Library drop → FreeLibrary/dlclose
    }

    // 卸载证明：Windows 上被加载的 DLL 文件是被锁住的，重命名会失败；
    // 能重命名成功，说明库真的被卸了。
    let renamed = staged.with_extension("unloaded");
    let result = std::fs::rename(&staged, &renamed);
    if cfg!(target_os = "windows") {
        assert!(result.is_ok(), "动态库似乎仍被加载（重命名失败）：{:?}", result.err());
        // 再用原路径重新加载一次，确认卸载没有把文件弄坏。
        std::fs::rename(&renamed, &staged).expect("还原文件名");
    } else {
        let _ = result;
    }
    assert!(PluginLoader::new().load(&staged).is_ok(), "卸载后可重新加载");
}

#[test]
fn loaded_plugin_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<agf_plugin::LoadedPlugin>();
    assert_send_sync::<PluginLoader>();
    assert_send_sync::<PluginMetadata>();
}

// ---------------------------------------------------------------------------
// 5. 缺插件时的降级（宿主照常启动）
// ---------------------------------------------------------------------------

#[test]
fn registry_degrades_when_plugin_directory_is_missing() {
    let dir = tempfile::tempdir().expect("临时目录");
    let missing = dir.path().join("plugins-not-deployed");

    let mut registry = PluginRegistry::new();
    assert_eq!(registry.load_dir(&missing).expect("目录缺失不算错误"), 0);
    assert!(registry.is_empty());
    assert!(registry.failures().is_empty());
    assert_eq!(registry.supported_abi(), &[AGF_PLUGIN_ABI_VERSION]);
}

#[test]
fn registry_keeps_going_after_a_broken_plugin() {
    let dir = tempfile::tempdir().expect("临时目录");
    // 好插件（真实 cdylib 的副本）
    let good = dir.path().join(plugin_file_name("agf_plugin_example_copy"));
    std::fs::copy(example_plugin_path(), &good).expect("复制示例插件");
    // 坏插件：后缀对、内容不是动态库
    let bad = dir.path().join(plugin_file_name("broken"));
    std::fs::write(&bad, b"not a library at all").expect("写坏插件");
    // 非插件文件：必须被直接跳过，不能算失败
    std::fs::write(dir.path().join("readme.txt"), b"ignore me").expect("写非插件文件");

    let mut registry = PluginRegistry::new();
    assert_eq!(registry.load_dir(dir.path()).expect("批量加载不返回 Err"), 1);
    assert_eq!(registry.len(), 1);
    assert_eq!(registry.failures().len(), 1, "{:?}", registry.failures());
    assert!(registry.failures()[0].path.ends_with(plugin_file_name("broken")), "{:?}", registry.failures());

    let plugin = registry.get("agf-plugin-example").expect("按名字取到好插件");
    assert!(plugin.normalize("src=10.0.0.9").is_ok());

    // 显式装载坏插件时，错误既被返回、也被登记。
    let before = registry.failures().len();
    assert!(registry.load_file(&bad).is_err());
    assert_eq!(registry.failures().len(), before + 1);
}
