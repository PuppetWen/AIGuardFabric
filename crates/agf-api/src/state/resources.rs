//! 目录/规则包/红队库/解析器/CORS 解析与风险历史落盘（自 `state.rs` 拆出）。

use super::*;

/// 解析目录：环境变量优先，其次若干候选相对路径。
#[must_use]
pub fn resolve_dir(env_key: &str, project_root: &str, candidates: &[&str]) -> PathBuf {
    if let Ok(raw) = std::env::var(env_key) {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    let mut roots: Vec<PathBuf> = vec![PathBuf::from(project_root)];
    roots.push(PathBuf::from("."));
    roots.push(PathBuf::from(".."));
    roots.push(PathBuf::from("../.."));
    for root in roots {
        for candidate in candidates {
            let path = root.join(candidate);
            if path.is_dir() {
                return path;
            }
        }
    }
    PathBuf::from(candidates.first().copied().unwrap_or("."))
}

pub(super) fn load_rules(config: &AppConfig, notes: &mut Vec<String>) -> DomainResult<RulePack> {
    let dir = resolve_dir("AGF_RULES_DIR", &config.project_root, &["rules"]);
    if dir.is_dir() {
        match RulePackLoader::lenient().load_dir(&RulesDir::new(&dir)) {
            Ok(pack) if !pack.is_empty() => return Ok(pack),
            Ok(_) => notes.push(format!("规则目录 {} 为空，已降级为内置最小规则集", dir.display())),
            Err(e) => notes.push(format!("规则目录 {} 加载失败（{e}），已降级为内置最小规则集", dir.display())),
        }
    } else {
        notes.push(format!("规则目录 {} 不存在，已降级为内置最小规则集", dir.display()));
    }
    notes.push("已加载内置最小规则集（每个风险域 1 条），规则覆盖率远低于生产要求".to_string());
    RulePackLoader::lenient().load_inline(fallback_rules()).map_err(|e| {
        warn!(error = %e, "内置最小规则集编译失败");
        e
    })
}

/// 内置最小规则集：规则目录缺失时保证扫描链路可用（每域至少 1 条）。
#[must_use]
pub fn fallback_rules() -> Vec<RuleDefinition> {
    let specs = [
        (RiskDomain::PromptAttack, "内置-提示注入", &["ignore previous instructions", "忽略以上指令"][..]),
        (RiskDomain::CredentialLeak, "内置-凭据泄露", &["AKIA", "agf_live_", "BEGIN RSA PRIVATE KEY"][..]),
        (RiskDomain::RagPoison, "内置-知识库投毒", &["system prompt override", "覆盖系统提示"][..]),
        (RiskDomain::ToolAbuse, "内置-工具滥用", &["rm -rf /", "curl | sh", "chmod 777"][..]),
        (RiskDomain::ModelData, "内置-数据外传", &["exfiltrate", "base64 -d | curl"][..]),
    ];
    specs
        .into_iter()
        .enumerate()
        .map(|(idx, (domain, name, keywords))| RuleDefinition {
            key: format!("fallback-{}-{:03}", domain.as_str(), idx + 1),
            name: name.to_string(),
            description: format!("规则目录缺失时的内置降级规则（{}）", domain.display_zh()),
            domain,
            severity: Severity::High,
            kind: RuleKind::Keyword,
            target: RuleTarget::Prompt,
            action: PolicyAction::Audit,
            enabled: true,
            rollout_percent: 100,
            tags: vec!["fallback".to_string()],
            references: Vec::new(),
            detection: Detection::Keyword { any: keywords.iter().map(|k| (*k).to_string()).collect() },
            samples: RuleSamples {
                positive: vec![keywords.first().copied().unwrap_or("hit").to_string()],
                negative: vec!["正常的业务文本，没有任何命中特征".to_string()],
            },
            remediation: "补充正式规则目录（rules/<domain>/*.yaml）后重新加载".to_string(),
            author: "agf-api".to_string(),
            version: 1,
        })
        .collect()
}

/// 红队用例目录：`AGF_REDTEAM_DIR` 优先，兼容 `.env.example` 已存在的 `AGF_REDTEAM_CASE_DIR` 别名，
/// 最后按 [`resolve_dir`] 的候选路径回退（容器 `/app/redteam` → 项目根 `redteam`）。
fn redteam_dir(config: &AppConfig) -> PathBuf {
    let primary = std::env::var("AGF_REDTEAM_DIR").unwrap_or_default();
    if primary.trim().is_empty() {
        let alias = std::env::var("AGF_REDTEAM_CASE_DIR").unwrap_or_default();
        if !alias.trim().is_empty() {
            return PathBuf::from(alias.trim());
        }
    }
    resolve_dir("AGF_REDTEAM_DIR", &config.project_root, &["redteam"])
}

/// 加载红队用例库。
///
/// **降级铁律**：目录不存在、为空或加载失败一律只记 `warn`/`notes` 并返回空库，
/// 绝不返回错误、绝不让进程退出（用例库不可用时红队端点会给出空库与明确说明）。
pub(super) fn load_redteam_cases(config: &AppConfig, notes: &mut Vec<String>) -> CaseLibrary {
    let dir = redteam_dir(config);
    if !dir.is_dir() {
        warn!(dir = %dir.display(), "红队用例目录不存在，用例库暂不可用");
        notes.push(format!("红队用例目录 {} 不存在，用例库暂不可用", dir.display()));
        return CaseLibrary::from_cases(Vec::new());
    }
    match CaseLibrary::load_dir(&dir) {
        Ok(lib) if !lib.cases().is_empty() => {
            info!(dir = %dir.display(), cases = lib.cases().len(), "红队用例库已加载");
            lib
        }
        Ok(_) => {
            warn!(dir = %dir.display(), "红队用例目录为空，用例库暂不可用");
            notes.push(format!("红队用例目录 {} 为空，用例库暂不可用", dir.display()));
            CaseLibrary::from_cases(Vec::new())
        }
        Err(e) => {
            warn!(dir = %dir.display(), error = %e, "红队用例库加载失败，用例库暂不可用");
            notes.push(format!("红队用例目录 {} 加载失败（{e}），用例库暂不可用", dir.display()));
            CaseLibrary::from_cases(Vec::new())
        }
    }
}

/// 加载解析模板目录（`AGF_PARSERS_DIR`，容器默认 `/app/parsers`，本机回退 `<项目根>/parsers`）。
///
/// 返回的注册表**至少**含 [`ParserRegistry::with_builtins`] 的内置模板：
/// 目录不存在、为空或不可读时只记 `warn`/`notes` 并保留内置模板，
/// 单个模板文件坏掉由 [`ParserRegistry::load_dir`] 内部计入 `invalid` 并跳过，不影响其余模板。
pub(super) fn load_parsers(config: &AppConfig, notes: &mut Vec<String>) -> ParserRegistry {
    let mut registry = ParserRegistry::with_builtins();
    let builtin = registry.stats().builtin;
    let dir = resolve_dir("AGF_PARSERS_DIR", &config.project_root, &["parsers"]);
    if !dir.is_dir() {
        warn!(dir = %dir.display(), builtin, "解析模板目录不存在，仅使用内置模板");
        notes.push(format!(
            "解析模板目录 {} 不存在，仅使用 {builtin} 个内置模板（§4.5 的厂商模板库未加载）",
            dir.display()
        ));
        return registry;
    }
    match registry.load_dir(&dir) {
        Ok(loaded) => {
            let stats = registry.stats();
            if loaded == 0 {
                warn!(dir = %dir.display(), invalid = stats.invalid, "解析模板目录没有可用模板，仅使用内置模板");
                notes.push(format!(
                    "解析模板目录 {} 没有可用模板（{} 个校验失败），仅使用 {builtin} 个内置模板",
                    dir.display(),
                    stats.invalid
                ));
            } else {
                info!(
                    dir = %dir.display(),
                    loaded,
                    builtin,
                    total = registry.all().len(),
                    invalid = stats.invalid,
                    "解析模板库已加载"
                );
                if stats.invalid > 0 {
                    notes.push(format!(
                        "解析模板目录 {} 有 {} 个模板校验失败已跳过（成功 {loaded} 个）",
                        dir.display(),
                        stats.invalid
                    ));
                }
            }
            registry
        }
        Err(e) => {
            warn!(dir = %dir.display(), error = %e, builtin, "解析模板目录加载失败，仅使用内置模板");
            notes.push(format!("解析模板目录 {} 加载失败（{e}），仅使用 {builtin} 个内置模板", dir.display()));
            registry
        }
    }
}

pub(super) fn resolve_cors_origins(config: &AppConfig) -> Vec<String> {
    if let Ok(raw) = std::env::var("AGF_CORS_ALLOW_ORIGINS") {
        let list: Vec<String> =
            raw.split(',').map(str::trim).filter(|s| !s.is_empty()).map(ToString::to_string).collect();
        if !list.is_empty() {
            return list;
        }
    }
    if config.env.is_prod() {
        Vec::new()
    } else {
        vec![
            "http://localhost:5173".to_string(),
            "http://127.0.0.1:5173".to_string(),
            "http://localhost:8081".to_string(),
            "http://127.0.0.1:8081".to_string(),
        ]
    }
}

/// 判断路径是否位于允许的目录内（规则/用例目录相对路径展示用）。
#[must_use]
pub fn display_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// 周期性把进程内风险趋势历史**原子落盘**（跨重启延续；见 `crate::history`）。
///
/// 为什么用后台任务而不是每次 `record` 都写：`record` 在请求路径上（`/overview` 取数时也会采样），
/// 每请求一次磁盘写会放大 IO；这里按 `AGF_RISK_HISTORY_SAVE_SECS`（默认 300s，<5s 夹到 5s 防抖）
/// 快照一次。落盘失败只 `warn`（`save_to` 内部已是"临时文件 + rename"原子替换），**不影响服务**。
///
/// 边界（如实）：单机单文件、无 fsync、多副本各自落盘（最后写入者胜，不做跨副本合并）；
/// 长期序列应由 Prometheus 承载，这里只是让"重启后控制台曲线不空"的本地兜底（`TODO(api-console-history)`）。
pub(super) fn spawn_risk_history_persister(history: Arc<RiskHistory>, path: std::path::PathBuf) {
    let secs = crate::state::env_u64("AGF_RISK_HISTORY_SAVE_SECS", 300).max(5);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(secs));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let samples: Vec<crate::history::Sample> = history
                .tenants()
                .into_iter()
                .flat_map(|tenant| {
                    crate::history::from_points(tenant, history.points(tenant).into_iter().map(|p| (p.at, p.value)))
                })
                .collect();
            if samples.is_empty() {
                continue;
            }
            crate::history::save_to(&path, &samples);
        }
    });
}

/// 读取无符号整型环境变量（空值/非法值回落默认，不报错）。
pub(super) fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key).ok().and_then(|raw| raw.trim().parse::<u64>().ok()).unwrap_or(default)
}
