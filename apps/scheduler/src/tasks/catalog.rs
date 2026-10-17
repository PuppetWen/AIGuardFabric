//! 由 `tasks.rs` 拆分：`catalog`/`new_note_store` 等 22 项（纯搬移，逻辑不变）。
use super::*;

/// 任务目录（唯一真源：`/tasks` 与 `Registry` 都从这里取）。
#[must_use]
pub(crate) fn catalog() -> Vec<TaskDescriptor> {
    vec![
        TaskDescriptor {
            name: "rules-regression", note: "严格加载 <AGF_RULES_DIR>/ 并跑正负样本回归；失败即计失败数"
        },
        TaskDescriptor {
            name: "redteam-cruise",
            note: "使用平台用例库和持久战役 API；需 redteam:read/execute 服务 Key；按执行编号去重，模拟证据和报告可在红队中心查看",
        },
        TaskDescriptor {
            name: "asset-inventory",
            note: "汇总资产台账统计；显式启用 AGF_SCHEDULER_AGENTTEAMS_SYNC_ENABLED 后先同步 AgentTeams，Live 需单独确认和 alicloud:write/assets:write",
        },
        TaskDescriptor {
            name: "log-pull",
            note: "拉取控制台中到期的 HTTP Pull 日志源并实际入库；需 sources:read/write 服务密钥，源凭据与游标由平台管理",
        },
        TaskDescriptor {
            name: "rule-hot-reload",
            note: "严格加载 <AGF_RULES_DIR>/ 后 POST {AGF_SERVER_URL}/api/v1/policies/reload 触达在线策略引擎；需 AGF_SERVER_URL 可达",
        },
        TaskDescriptor {
            name: "cold-archive",
            note: "把 <AGF_REPORT_DIR> 下超过 AGF_SCHEDULER_ARCHIVE_AFTER_DAYS 天的文件 gzip 后上传对象存储；未配置 AGF_S3_* 时降级为本地 gzip 归档到 <AGF_SCHEDULER_ARCHIVE_DIR>",
        },
        TaskDescriptor {
            name: "report-generate",
            note: "汇总规则包/红队/归档/任务执行表生成 Markdown 报表（内容全部来自真实读取）",
        },
        TaskDescriptor {
            name: "alicloud-cms-push",
            note: "全部指标先保存租户隔离 outbox，再接入 CMS 持久队列；需 alicloud:read/write 服务身份与控制台源；Mock 明确降级，Live 默认仅入队，送云需 AGF_SCHEDULER_CMS_CONFIRM_LIVE=true",
        },
    ]
}

/// 新建 note 存储。
#[must_use]
pub(crate) fn new_note_store() -> NoteStore {
    Arc::new(Mutex::new(BTreeMap::new()))
}

/// 读动态 note。
#[must_use]
pub(crate) fn note_get(store: &NoteStore, name: &str) -> Option<String> {
    store.lock().ok().and_then(|m| m.get(name).cloned())
}

/// 写动态 note（写失败只丢诊断信息，不影响任务）。
pub(crate) fn note_set(store: &NoteStore, name: &'static str, note: impl Into<String>) {
    if let Ok(mut m) = store.lock() {
        let _previous = m.insert(name, note.into());
    }
}

impl TaskOutcome {
    /// 成功。
    #[must_use]
    pub(crate) fn ok(note: impl Into<String>) -> Self {
        Self { ok: true, skipped: false, degraded: false, note: note.into(), artifacts: Vec::new() }
    }

    /// 未配置而跳过（不算失败）。
    #[must_use]
    pub(crate) fn skipped(note: impl Into<String>) -> Self {
        Self { ok: true, skipped: true, degraded: false, note: note.into(), artifacts: Vec::new() }
    }

    /// 降级成功（如本地归档 / Mock 上报）。
    #[must_use]
    pub(crate) fn degraded(note: impl Into<String>) -> Self {
        Self { ok: true, skipped: false, degraded: true, note: note.into(), artifacts: Vec::new() }
    }

    /// 失败（外部依赖不可达、规则非法等）。
    #[must_use]
    pub(crate) fn failed(note: impl Into<String>) -> Self {
        Self { ok: false, skipped: false, degraded: false, note: note.into(), artifacts: Vec::new() }
    }

    /// 追加产物路径。
    #[must_use]
    pub(crate) fn with_artifact(mut self, path: impl Into<String>) -> Self {
        self.artifacts.push(path.into());
        self
    }

    /// 状态标签（日志/`/tasks` 用）。
    #[must_use]
    pub(crate) fn status_label(&self) -> &'static str {
        if !self.ok {
            "failed"
        } else if self.skipped {
            "skipped"
        } else if self.degraded {
            "degraded"
        } else {
            "ok"
        }
    }

    /// 一行结论（日志主文案）。
    #[must_use]
    pub(crate) fn summary(&self) -> String {
        if self.artifacts.is_empty() {
            format!("[{}] {}", self.status_label(), self.note)
        } else {
            format!("[{}] {}；产物：{}", self.status_label(), self.note, self.artifacts.join(", "))
        }
    }
}

// ---------------------------------------------------------------------------
// 通用小工具
// ---------------------------------------------------------------------------

/// 时间戳 slug（`YYYYMMDDTHHMMSSZ`，字典序 = 时间序，便于"取最新"）。
#[must_use]
pub(crate) fn ts_slug(at: chrono::DateTime<chrono::Utc>) -> String {
    at.format("%Y%m%dT%H%M%SZ").to_string()
}

/// 当前时间 slug。
#[must_use]
pub(crate) fn now_slug() -> String {
    format!("{}-{}", ts_slug(chrono::Utc::now()), Id::new())
}

/// 布尔环境变量开关（`1/true/yes/on` 为真，空值取默认）。
#[must_use]
pub(crate) fn env_flag(raw: Option<&str>, default: bool) -> bool {
    match raw.map(str::trim) {
        None | Some("") => default,
        Some(v) => matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"),
    }
}

/// 在目录里取"最新"的匹配文件（文件名含可排序时间戳 → 字典序最大者）。
#[must_use]
pub(crate) fn latest_file(dir: &Path, prefix: &str, suffix: &str) -> Option<PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    let mut best: Option<(String, PathBuf)> = None;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with(prefix) || !name.ends_with(suffix) {
            continue;
        }
        let path = entry.path();
        match &best {
            Some((best_name, _)) if best_name.as_str() >= name.as_str() => {}
            _ => best = Some((name, path)),
        }
    }
    best.map(|(_, path)| path)
}

/// 目录里全部匹配文件名（倒序 = 新的在前）。
#[must_use]
pub(crate) fn list_matching(dir: &Path, prefix: &str, suffix: &str, limit: usize) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut names: Vec<String> = entries
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|name| name.starts_with(prefix) && name.ends_with(suffix))
        .collect();
    names.sort_by(|a, b| b.cmp(a));
    names.truncate(limit);
    names
}

impl ApiAuth {
    /// 从环境变量选择凭据：`AGF_SCHEDULER_API_KEY` 优先（API Key），否则 `AGF_SCHEDULER_API_TOKEN`（JWT）。
    ///
    /// 返回 `None` 表示未配置——调用方仍会发请求，但会拿到 401，并在任务结论里如实写明。
    #[must_use]
    pub(crate) fn from_values(api_key: Option<String>, bearer: Option<String>) -> Option<Self> {
        let normalize = |raw: String| {
            let trimmed = raw.trim().to_string();
            if trimmed.is_empty() { None } else { Some(trimmed) }
        };
        if let Some(key) = api_key.and_then(normalize) {
            return Some(Self::ApiKey(key));
        }
        bearer.and_then(normalize).map(Self::Bearer)
    }

    /// 把凭据挂到请求上（**只挂一种**，理由见类型文档）。
    pub(crate) fn apply(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match self {
            Self::ApiKey(key) => request.header("X-AGF-Key", key.clone()),
            Self::Bearer(jwt) => request.bearer_auth(jwt.clone()),
        }
    }
}

/// 带可选凭据的 GET（超时由调用方在 client 上设置）。
pub(crate) async fn http_get(
    client: &reqwest::Client,
    url: &str,
    auth: Option<&ApiAuth>,
) -> anyhow::Result<reqwest::Response> {
    let mut req = client.get(url);
    if let Some(auth) = auth {
        req = auth.apply(req);
    }
    Ok(req.send().await?)
}

/// 带可选凭据的 JSON POST。
pub(crate) async fn http_post_json(
    client: &reqwest::Client,
    url: &str,
    auth: Option<&ApiAuth>,
    body: serde_json::Value,
) -> anyhow::Result<reqwest::Response> {
    let mut req = client.post(url).json(&body);
    if let Some(auth) = auth {
        req = auth.apply(req);
    }
    Ok(req.send().await?)
}

/// 拼接 API 路径（去掉 base 末尾的 `/`）。
#[must_use]
pub(crate) fn api_url(server_url: &str, path: &str) -> String {
    format!("{}{}", server_url.trim_end_matches('/'), path)
}

/// 从真实响应体派生摘要（纯函数，测试用固定 JSON）。
#[must_use]
pub(crate) fn summarize_asset_stats(raw: &str) -> Option<(AssetStatsSummary, serde_json::Value)> {
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;
    let inventory = value.get("inventory");
    let inventory_fields = inventory.and_then(serde_json::Value::as_object).map_or(0, serde_json::Map::len);
    let total = inventory
        .and_then(|v| {
            ["total", "count", "total_assets"].iter().find_map(|key| {
                v.get(*key).and_then(|n| n.as_u64().or_else(|| n.as_str().and_then(|s| s.parse::<u64>().ok())))
            })
        })
        .unwrap_or(0);
    Some((
        AssetStatsSummary { inventory_fields, total, has_inventory: inventory.is_some(), raw_bytes: raw.len() },
        value,
    ))
}

/// 摘要文案。
#[must_use]
pub(crate) fn asset_summary_text(summary: &AssetStatsSummary) -> String {
    if !summary.has_inventory {
        return format!("响应中无 inventory 字段（{} 字节）", summary.raw_bytes);
    }
    format!(
        "资产台账：总量 {}，inventory 字段 {} 个（{} 字节）",
        summary.total, summary.inventory_fields, summary.raw_bytes
    )
}

/// 任务：资产盘点（真实 HTTP；服务不可达 → 失败只 warn）。
pub(crate) async fn run_asset_inventory(
    client: &reqwest::Client,
    server_url: &str,
    auth: Option<&ApiAuth>,
    report_dir: &Path,
) -> TaskOutcome {
    let url = api_url(server_url, "/api/v1/assets/stats");
    let resp = match http_get(client, &url, auth).await {
        Ok(resp) => resp,
        Err(e) => return TaskOutcome::failed(format!("资产盘点失败：GET {url} 不可达（{e}）")),
    };
    if !resp.status().is_success() {
        return TaskOutcome::failed(format!("资产盘点失败：GET {url} 返回 HTTP {}", resp.status().as_u16()));
    }
    let body = match resp.text().await {
        Ok(body) => body,
        Err(e) => return TaskOutcome::failed(format!("资产盘点失败：读取响应体出错（{e}）")),
    };
    let Some((summary, value)) = summarize_asset_stats(&body) else {
        return TaskOutcome::failed("资产盘点失败：响应不是合法 JSON".to_string());
    };
    let mut outcome = TaskOutcome::ok(asset_summary_text(&summary));
    let path = report_dir.join(format!("asset-inventory-{}.json", now_slug()));
    let pretty = serde_json::to_string_pretty(&value).unwrap_or_else(|_| body.clone());
    match std::fs::write(&path, pretty) {
        Ok(()) => outcome = outcome.with_artifact(path.display().to_string()),
        // 落盘是"可选"步骤：失败不把已获取的统计判为失败。
        Err(e) => outcome.note = format!("{}；清单落盘失败（{e}）", outcome.note),
    }
    outcome
}

// ---------------------------------------------------------------------------
// log-pull
// ---------------------------------------------------------------------------

/// 解析 `AGF_SCHEDULER_PULL_URLS`（逗号分隔；去空白、丢空项、保序去重）。
#[must_use]
pub(crate) fn parse_pull_urls(raw: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for part in raw.split(',') {
        let url = part.trim();
        if url.is_empty() {
            continue;
        }
        if !out.iter().any(|existing| existing == url) {
            out.push(url.to_string());
        }
    }
    out
}

/// 逐行喂解析管线：注册表（[`build_log_pull_registry`]：内置 + `parsers/`）的匹配入口内部对命中的
/// parser 调用 `agf_ingest::engine::parse_with`（grok/正则 → ECS 字段）。
///
/// 返回 `(非空行数, 命中数, 未命中数)`；空行不计（避免用空白刷高失败数）。
#[must_use]
pub(crate) fn parse_log_text(
    registry: &mut ParserRegistry,
    protocol: IngestProtocol,
    text: &str,
) -> (usize, usize, usize) {
    let mut lines = 0_usize;
    let mut parsed = 0_usize;
    let mut failed = 0_usize;
    for line in text.lines() {
        let raw = line.trim();
        if raw.is_empty() {
            continue;
        }
        lines += 1;
        if registry.match_raw(raw, protocol, None, None).matched {
            parsed += 1;
        } else {
            failed += 1;
        }
    }
    (lines, parsed, failed)
}

/// 统计文案。
#[must_use]
pub(crate) fn log_pull_text(stats: &LogPullStats) -> String {
    format!(
        "日志拉取：源 {}/{} 成功，非空行 {}，解析命中 {}，未命中 {}",
        stats.fetched, stats.sources, stats.lines, stats.parsed, stats.failed
    )
}

/// 解析模板库目录：`AGF_PARSERS_DIR` 优先；容器内默认 `/app/parsers`；本机回退 `<cwd>/parsers`。
#[must_use]
pub(crate) fn resolve_parsers_dir() -> PathBuf {
    let value = std::env::var("AGF_PARSERS_DIR").unwrap_or_default();
    if !value.trim().is_empty() {
        return PathBuf::from(value.trim());
    }
    let container = PathBuf::from("/app/parsers");
    if container.is_dir() {
        return container;
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")).join("parsers")
}

/// 构造 `log-pull` 用的解析注册表：**内置模板 + `parsers/` 目录下的 YAML 模板库**。
///
/// 为什么必须加载目录（实测，见 `crates/agf-ingest/tests/simulator_parity.rs`）：
/// 内置 18 条模板与仓库自己的样本口径不一致 —— 华为云 HSS 异常进程样本、
/// 2 条 `http-pull` 协议样本在内置注册表下**全部未命中**，在完整模板库下全部命中。
/// `log-pull` 只用 `ParserRegistry::with_builtins()` ⇒ 拉回来的真实日志"解不出来"，
/// `parsed` 恒低于实际可解析量（模拟器实测：`/mixed` 6 行只 parsed 5）。
///
/// 加载失败**只 warn 并继续用内置模板**（与 `apps/ingest` 同样的"永远可启动"策略）。
pub(crate) fn build_log_pull_registry(dir: &Path) -> ParserRegistry {
    let mut registry = ParserRegistry::with_builtins();
    let builtin = registry.all().len();
    match registry.load_dir(dir) {
        Ok(loaded) => tracing::info!(
            dir = %dir.display(),
            loaded,
            builtin,
            total = registry.all().len(),
            "log-pull 解析模板库已加载（内置 + parsers/）"
        ),
        Err(e) => tracing::warn!(
            dir = %dir.display(),
            error = %e,
            "log-pull 模板库目录加载失败：仅使用内置模板继续（可用 AGF_PARSERS_DIR 指定目录）"
        ),
    }
    registry
}
