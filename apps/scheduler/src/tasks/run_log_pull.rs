//! 由 `tasks.rs` 拆分：`run_log_pull`/`run_rule_hot_reload` 等 13 项（纯搬移，逻辑不变）。
use super::*;

/// 任务：日志拉取（未配置源 → 如实 skip，不算失败）。
pub(crate) async fn run_log_pull(
    client: &reqwest::Client,
    raw_urls: &str,
    _auth: Option<&ApiAuth>,
    report_dir: &Path,
) -> TaskOutcome {
    let urls = parse_pull_urls(raw_urls);
    if urls.is_empty() {
        return TaskOutcome::skipped(
            "跳过本轮：未配置拉取源（AGF_SCHEDULER_PULL_URLS 为空）——需要配置 X（拉取地址）才有效",
        );
    }
    // 与 agf-ingest 同一口径：内置模板 + parsers/ 目录（否则仓库自己的样本解不出来）
    let mut registry = build_log_pull_registry(&resolve_parsers_dir());
    let mut stats = LogPullStats { sources: urls.len(), ..LogPullStats::default() };
    for url in &urls {
        let mut stat = SourceStat { url: url.clone(), ..SourceStat::default() };
        // 平台服务密钥不能发送给日志上游；认证源应使用控制台的加密源配置。
        match http_get(client, url, None).await {
            Ok(resp) if resp.status().is_success() => match resp.text().await {
                Ok(body) => {
                    let (lines, parsed, failed) = parse_log_text(&mut registry, IngestProtocol::HttpPull, &body);
                    stat.ok = true;
                    stat.bytes = body.len();
                    stat.lines = lines;
                    stat.parsed = parsed;
                    stat.failed = failed;
                    stats.fetched += 1;
                    stats.lines += lines;
                    stats.parsed += parsed;
                    stats.failed += failed;
                }
                Err(e) => stat.error = Some(format!("读取响应体失败：{e}")),
            },
            Ok(resp) => stat.error = Some(format!("HTTP {}", resp.status().as_u16())),
            Err(e) => stat.error = Some(format!("不可达：{e}")),
        }
        if let Some(error) = &stat.error {
            tracing::warn!(url = %stat.url, error = %error, "日志拉取源失败（继续下一个源）");
        }
        stats.per_source.push(stat);
    }

    let ok = stats.fetched > 0;
    let mut outcome = if ok {
        TaskOutcome::ok(log_pull_text(&stats))
    } else {
        TaskOutcome::failed(format!("全部 {} 个拉取源均失败（{}）", stats.sources, log_pull_text(&stats)))
    };
    if ok && stats.fetched < stats.sources {
        outcome.degraded = true;
        outcome.note = format!("部分源失败：{}", outcome.note);
    }
    outcome.degraded = true;
    outcome.note =
        format!("旧 PULL_URLS 模式仅生成本地解析统计，未入平台事件库；请迁移到控制台日志源。{}", outcome.note);
    let path = report_dir.join(format!("log-pull-{}.json", now_slug()));
    match serde_json::to_string_pretty(&stats) {
        Ok(json) => match std::fs::write(&path, json) {
            Ok(()) => outcome.artifacts.push(path.display().to_string()),
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "日志拉取统计落盘失败");
                outcome.note = format!("{}；统计落盘失败（{e}）", outcome.note);
            }
        },
        Err(e) => {
            tracing::warn!(error = %e, "日志拉取统计序列化失败");
        }
    }
    outcome
}

// ---------------------------------------------------------------------------
// rule-hot-reload
// ---------------------------------------------------------------------------

/// 任务：严格加载本地规则包并推给在线策略引擎（`POST /api/v1/policies/reload`）。
///
/// 请求体按 `routes/governance.rs::reload_policies` 的契约：该 handler 只取
/// State + Principal，**不解析请求体**，因此发送空 JSON 对象 `{}`。
pub(crate) async fn run_rule_hot_reload(
    client: &reqwest::Client,
    server_url: &str,
    auth: Option<&ApiAuth>,
    rules_dir: &Path,
) -> TaskOutcome {
    let dir = RulesDir::new(rules_dir.to_path_buf());
    if !dir.exists() {
        return TaskOutcome::failed(format!("规则目录不存在（{}），无法热重载", rules_dir.display()));
    }
    let pack = match RulePackLoader::strict().load_dir(&dir) {
        Ok(pack) => pack,
        Err(e) => return TaskOutcome::failed(format!("规则包严格加载失败（{e}）")),
    };
    let local_rules = pack.len();
    let url = api_url(server_url, "/api/v1/policies/reload");
    let resp = match http_post_json(client, &url, auth, serde_json::json!({})).await {
        Ok(resp) => resp,
        Err(e) => {
            return TaskOutcome::failed(format!(
                "规则包 {local_rules} 条已在本地严格加载，但 POST {url} 不可达（{e}）"
            ));
        }
    };
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return TaskOutcome::failed(format!("热重载失败：POST {url} 返回 HTTP {}（{}）", status.as_u16(), body.trim()));
    }
    let value: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
    let reloaded = value.get("reloaded").and_then(serde_json::Value::as_u64);
    let total = value.get("total").and_then(serde_json::Value::as_u64);
    match reloaded {
        Some(reloaded) => TaskOutcome::ok(format!(
            "本地规则包 {local_rules} 条已推送热重载；服务端已加载 {reloaded} 条（策略总数 {}）",
            total.map_or_else(|| "未返回".to_string(), |t| t.to_string())
        )),
        // 服务端返回 2xx 但没有 reloaded 字段：如实说明，不假装加载成功。
        None => TaskOutcome::degraded(format!(
            "POST {url} 返回 HTTP {}，但响应缺少 reloaded 字段（本地规则包 {local_rules} 条）；响应片段：{}",
            status.as_u16(),
            body.trim()
        )),
    }
}

impl ArchiveEntry {
    /// 由候选派生。
    #[must_use]
    pub(crate) fn from_candidate(candidate: &ArchiveCandidate) -> Self {
        Self {
            name: candidate.name.clone(),
            bytes: candidate.bytes,
            sha256: candidate.sha256.clone(),
            age_days: candidate.age_days,
        }
    }
}

/// 扫描目录并计算 age/sha256（纯读盘，不联网）。
///
/// # Errors
/// 目录不可读时返回 IO 错误。
pub(crate) fn scan_archive_candidates(dir: &Path, now: SystemTime) -> std::io::Result<Vec<ArchiveCandidate>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        let Ok(data) = std::fs::read(&path) else { continue };
        let modified = meta.modified().unwrap_or(now);
        let age_days = now.duration_since(modified).map_or(0, |d| d.as_secs() / 86_400);
        out.push(ArchiveCandidate { path, name, bytes: meta.len(), modified, age_days, sha256: content_hash(&data) });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// 时间窗口筛选：**严格超过** `after_days` 天（age == after_days 不归档）。
///
/// 结果按修改时间升序（最旧的先归档），`modified` 因此参与排序而非仅作记录。
#[must_use]
pub(crate) fn select_expired(candidates: &[ArchiveCandidate], after_days: u64) -> Vec<ArchiveCandidate> {
    let mut expired: Vec<ArchiveCandidate> = candidates.iter().filter(|c| c.age_days > after_days).cloned().collect();
    expired.sort_by(|a, b| a.modified.cmp(&b.modified).then_with(|| a.name.cmp(&b.name)));
    expired
}

/// 对象键：`<name>.gz`。
#[must_use]
pub(crate) fn archive_key(name: &str) -> String {
    format!("{name}.gz")
}

/// gzip 压缩（复用 `agf_ingest::coldarchive` 的 flate2 实现）。
///
/// # Errors
/// 压缩失败。
pub(crate) fn gzip_payload(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    Ok(agf_ingest::coldarchive::gzip(data)?)
}

/// gzip 解压（往返校验用；生产路径只需压缩，故仅测试/诊断编译）。
///
/// # Errors
/// 解压失败或数据非法。
#[cfg(test)]
pub(crate) fn gunzip_payload(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    Ok(agf_ingest::coldarchive::gunzip(data)?)
}

/// 清单统计：`(文件数, 字节总数, 清单哈希)`。
#[must_use]
pub(crate) fn manifest_totals(entries: &[ArchiveEntry]) -> (usize, u64, String) {
    let bytes: u64 = entries.iter().map(|e| e.bytes).sum();
    let mut joined = String::new();
    for entry in entries {
        let _ = writeln!(joined, "{name}:{hash}", name = entry.name, hash = entry.sha256);
    }
    (entries.len(), bytes, content_hash(joined.as_bytes()))
}

/// 清单 Markdown 摘要（报表与日志共用）。
#[must_use]
pub(crate) fn archive_summary_text(manifest: &ArchiveManifest) -> String {
    format!(
        "归档 {} 个文件 / {} 字节；后端={}{}；清单 sha256={}",
        manifest.files,
        manifest.bytes,
        manifest.backend,
        if manifest.degraded_local { "（降级为本地）" } else { "" },
        manifest.manifest_sha256
    )
}

/// 任务：冷归档。
///
/// 对象存储不可达（`store_note = Some(..)` 或 `put` 失败）时**降级为本地 gzip**
/// 写入 `archive_dir`，并在日志、`/tasks` 动态 note 与返回里明确标注"降级为本地"。
pub(crate) async fn run_cold_archive(job: ArchiveJob, partition: crate::Partition) -> TaskOutcome {
    let now = SystemTime::now();
    let candidates = match scan_archive_candidates(&job.report_dir, now) {
        Ok(candidates) => candidates,
        Err(e) => return TaskOutcome::failed(format!("扫描 {} 失败（{e}）", job.report_dir.display())),
    };
    let expired: Vec<_> = select_expired(&candidates, job.after_days)
        .into_iter()
        .filter(|candidate| partition.owns(&candidate.name))
        .collect();
    if expired.is_empty() {
        return TaskOutcome::skipped(format!(
            "跳过本轮：{} 下没有超过 {} 天的文件（共 {} 个文件）",
            job.report_dir.display(),
            job.after_days,
            candidates.len()
        ));
    }

    let backend = job.store.backend().to_string();
    let remote = job.store_note.is_none();
    let mut manifest = ArchiveManifest {
        at: chrono::Utc::now().to_rfc3339(),
        source_dir: job.report_dir.display().to_string(),
        archive_after_days: job.after_days,
        backend: if remote { backend.clone() } else { "local".to_string() },
        degraded_local: !remote,
        degrade_reason: job.store_note.clone(),
        ..ArchiveManifest::default()
    };
    if let Err(e) = std::fs::create_dir_all(&job.archive_dir) {
        return TaskOutcome::failed(format!("本地归档目录创建失败（{}）：{e}", job.archive_dir.display()));
    }

    for candidate in &expired {
        let entry = ArchiveEntry::from_candidate(candidate);
        let data = match std::fs::read(&candidate.path) {
            Ok(data) => data,
            Err(e) => {
                manifest.errors.push(format!("{}: 读取失败（{e}）", candidate.name));
                continue;
            }
        };
        let gz = match gzip_payload(&data) {
            Ok(gz) => gz,
            Err(e) => {
                manifest.errors.push(format!("{}: gzip 失败（{e}）", candidate.name));
                continue;
            }
        };
        let key = archive_key(&candidate.name);
        let mut uploaded_remote = false;
        if remote {
            match job.store.put(&key, &gz, Some("application/gzip")).await {
                Ok(_) => {
                    uploaded_remote = true;
                    manifest.uploaded.push(key.clone());
                }
                Err(e) => {
                    // 对象存储不可达 → 本轮降级为本地，如实标注（不算失败）。
                    manifest.degraded_local = true;
                    manifest.backend = "local".to_string();
                    manifest.degrade_reason = Some(format!("对象存储上传失败（{e}），降级为本地 gzip"));
                    tracing::warn!(key = %key, error = %e, "对象存储上传失败，降级为本地 gzip 归档");
                }
            }
        }
        if uploaded_remote {
            if job.delete_local {
                match std::fs::remove_file(&candidate.path) {
                    Ok(()) => manifest.deleted_locals.push(candidate.path.display().to_string()),
                    Err(e) => manifest.errors.push(format!("{}: 上传成功但删除本地失败（{e}）", candidate.name)),
                }
            }
        } else {
            let local_path = job.archive_dir.join(&key);
            match std::fs::write(&local_path, &gz) {
                Ok(()) => manifest.local_archives.push(local_path.display().to_string()),
                Err(e) => manifest.errors.push(format!("{}: 本地归档写入失败（{e}）", candidate.name)),
            }
        }
        manifest.entries.push(entry);
    }

    let (files, bytes, manifest_sha256) = manifest_totals(&manifest.entries);
    manifest.files = files;
    manifest.bytes = bytes;
    manifest.manifest_sha256 = manifest_sha256;

    let mut outcome = if manifest.errors.is_empty() {
        if manifest.degraded_local {
            TaskOutcome::degraded(format!(
                "降级为本地：{}（{}）",
                archive_summary_text(&manifest),
                manifest.degrade_reason.clone().unwrap_or_else(|| "对象存储不可用".to_string())
            ))
        } else {
            TaskOutcome::ok(archive_summary_text(&manifest))
        }
    } else {
        TaskOutcome::failed(format!(
            "部分文件归档失败：{}；错误：{}",
            archive_summary_text(&manifest),
            manifest.errors.join("；")
        ))
    };
    let path = job.report_dir.join(format!("archive-{}.json", now_slug()));
    match serde_json::to_string_pretty(&manifest) {
        Ok(json) => match std::fs::write(&path, json) {
            Ok(()) => outcome = outcome.with_artifact(path.display().to_string()),
            Err(e) => tracing::warn!(path = %path.display(), error = %e, "归档清单落盘失败"),
        },
        Err(e) => tracing::warn!(error = %e, "归档清单序列化失败"),
    }
    for archive in &manifest.local_archives {
        outcome.artifacts.push(archive.clone());
    }
    outcome
}

/// 便于把 `Option<T>` 渲染成"值或本期无数据"。
pub(crate) fn or_no_data<T: std::fmt::Display>(value: Option<T>) -> String {
    value.map_or_else(|| NO_DATA.to_string(), |v| v.to_string())
}

/// 渲染 Markdown 报表（纯函数）。
#[must_use]
pub(crate) fn render_report(input: &ReportInput) -> String {
    let mut out = String::new();
    out.push_str("# AIGuardFabric 周期报表\n\n");
    out.push_str(&format!("- 生成时间：{}\n", input.generated_at));
    out.push_str("- 数据来源：本机磁盘读取（规则目录 / 红队用例库 / 历史报表 / 归档清单）+ 进程内任务计数\n\n");

    out.push_str("## 规则库\n\n");
    out.push_str(&format!(
        "- 规则目录：{}（{}）\n",
        input.rules_dir,
        if input.rules_count.is_some() { "可读" } else { NO_DATA }
    ));
    out.push_str(&format!("- 规则包条数：{}\n", or_no_data(input.rules_count)));
    out.push_str(&format!("- 规则包指纹：{}\n\n", or_no_data(input.rules_fingerprint.as_deref())));

    out.push_str("## 红队\n\n");
    out.push_str(&format!("- 用例数：{}\n", or_no_data(input.redteam_cases)));
    if input.redteam_reports.is_empty() {
        out.push_str(&format!("- 最近战役报告：{NO_DATA}\n\n"));
    } else {
        out.push_str("- 最近战役报告：\n");
        for name in &input.redteam_reports {
            out.push_str(&format!("  - {name}\n"));
        }
        out.push('\n');
    }

    out.push_str("## 资产盘点\n\n");
    out.push_str(&format!("- {}\n\n", or_no_data(input.asset_summary.as_deref())));

    out.push_str("## 日志拉取\n\n");
    out.push_str(&format!("- {}\n\n", or_no_data(input.log_pull_summary.as_deref())));

    out.push_str("## 冷归档\n\n");
    match &input.archive {
        Some(manifest) => {
            out.push_str(&format!("- {}\n", archive_summary_text(manifest)));
            out.push_str(&format!("- 扫描目录：{}\n", manifest.source_dir));
            out.push_str(&format!(
                "- 降级为本地：{}（{}）\n\n",
                if manifest.degraded_local { "是" } else { "否" },
                manifest.degrade_reason.clone().unwrap_or_else(|| "对象存储正常".to_string())
            ));
        }
        None => out.push_str(&format!("- {NO_DATA}\n\n")),
    }

    out.push_str("## 云指标上报（alicloud-cms-push）\n\n");
    out.push_str(&format!("- {}\n\n", or_no_data(input.cms_note.as_deref())));

    out.push_str("## 任务执行表\n\n");
    if input.tasks.is_empty() {
        out.push_str(&format!("{NO_DATA}\n"));
    } else {
        out.push_str("| 任务 | runs | failures | last_millis |\n|---|---|---|---|\n");
        for task in &input.tasks {
            out.push_str(&format!("| {} | {} | {} | {} |\n", task.name, task.runs, task.failures, task.last_millis));
        }
    }
    out
}
