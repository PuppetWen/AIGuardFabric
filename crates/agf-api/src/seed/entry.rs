//! 灌库入口：开关判断、目录解析与 seed_demo_data 主流程（自 seed.rs 拆出，逻辑未变）。

use super::*;

// ===========================================================================
// 入口
// ===========================================================================

/// 判断开关取值是否开启（`1` / `true` / `yes` / `on`，大小写与空白不敏感）。
#[must_use]
pub fn seed_flag_enabled(raw: Option<&str>) -> bool {
    matches!(raw.map(str::trim).map(str::to_ascii_lowercase).as_deref(), Some("1" | "true" | "yes" | "on"))
}

/// 读取 `AGF_SEED_FIXTURES`：**默认关闭**（生产安全）。
#[must_use]
pub fn seed_enabled() -> bool {
    seed_flag_enabled(std::env::var(ENV_ENABLED).ok().as_deref())
}

/// 解析数据集目录：`AGF_SEED_DIR` 优先（容器 `/app/data/seed`），
/// 否则回退 `<项目根>/data/seed`（复用 [`crate::state::resolve_dir`] 的候选路径逻辑）。
#[must_use]
pub fn seed_dir(project_root: &str) -> PathBuf {
    crate::state::resolve_dir(ENV_DIR, project_root, &["data/seed"])
}

/// 把演示数据灌入 [`ApiStore`]。
///
/// 参数 `redteam_cases` 是 [`crate::state::AppState`] 已加载的真实红队用例库
/// （`redteam/*.yaml`）；为空时跳过合成战役并如实记入报告。
///
/// # Errors
/// 仅当内存后端锁中毒（[`DomainError::Internal`]）时返回错误；其余失败一律降级记录。
///
/// # 幂等
/// 可重复调用：第二次调用所有 [`DatasetReport::inserted`] 为 0，库中无重复数据。
pub fn seed_demo_data(
    store: &ApiStore,
    root: &Path,
    tenant: TenantId,
    quota: &QuotaDefaults,
    redteam_cases: &CaseLibrary,
) -> DomainResult<SeedReport> {
    let mut report = SeedReport::new(root);
    let mut refs = CrossRefs::default();

    seed_assets(store, root, tenant, &mut report, &mut refs)?;
    seed_findings(store, root, tenant, &mut report, &mut refs)?;
    seed_policies(store, root, tenant, &mut report, &mut refs)?;
    seed_alerts(store, root, tenant, &mut report, &mut refs)?;
    seed_cases(store, root, tenant, &mut report, &mut refs)?;
    check_redteam_case_index(root, &mut report, &refs);
    seed_scans(store, tenant, &mut report)?;
    seed_campaign(store, tenant, redteam_cases, &refs, &mut report)?;
    seed_reports(store, tenant, &refs, &mut report)?;
    seed_quotas(store, tenant, quota, &mut report)?;
    seed_route_policies(store, tenant, &refs, &mut report)?;
    seed_soar_runs(store, tenant, &mut report)?;

    Ok(report)
}
