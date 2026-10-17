//! 由 `backup.rs` 拆分：`impl_ProcessFailure`/`classify_process_result` 等 14 项（纯搬移，逻辑不变）。
use super::*;

impl ProcessFailure {
    /// 云端可读原因。
    #[must_use]
    pub fn describe(&self, program: &str) -> String {
        match self {
            Self::NotFound => format!("未找到可执行文件 `{program}`（不在 PATH 中）"),
            Self::NonZero(code) => format!("`{program}` 退出码 {code}"),
            Self::Connection(msg) => format!("`{program}` 无法连接数据库: {msg}"),
            Self::Spawn(msg) => format!("启动 `{program}` 失败: {msg}"),
        }
    }

    /// 是否属于"外部依赖不可用"（→ 退出码 2）。
    #[must_use]
    pub const fn is_dependency_unavailable(&self) -> bool {
        matches!(self, Self::NotFound | Self::Connection(_))
    }
}

/// 从一个进程执行结果映射失败原因（纯函数，便于单测）。
///
/// `code = None` 表示进程被信号终止或状态未知，按 `Spawn` 处理。
#[must_use]
pub fn classify_process_result(code: Option<i32>, stderr: &str) -> Option<ProcessFailure> {
    match code {
        Some(0) => None,
        Some(c) => Some(if is_connection_error(stderr) {
            ProcessFailure::Connection(first_line(stderr))
        } else {
            ProcessFailure::NonZero(c)
        }),
        None => Some(ProcessFailure::Spawn("进程被终止且无退出码".to_string())),
    }
}

/// 判断 `pg_dump`/`pg_restore` 的 stderr 是否是连接类错误。
#[must_use]
pub fn is_connection_error(stderr: &str) -> bool {
    let lower = stderr.to_ascii_lowercase();
    [
        "could not connect",
        "connection refused",
        "could not translate host name",
        "no such host",
        "connection to server",
        "server closed the connection",
        "password authentication failed",
        "timeout expired",
        "无法连接",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

pub(crate) fn first_line(text: &str) -> String {
    text.lines().find(|l| !l.trim().is_empty()).unwrap_or("").trim().to_string()
}

impl BackupLayout {
    /// 由目录或 `agf.dump` 路径解析布局（与 `scripts/restore.ps1` 的解析规则一致）。
    #[must_use]
    pub fn resolve(input: &Path) -> Self {
        let (dir, dump) = if input.is_dir() {
            (input.to_path_buf(), input.join(DUMP_NAME))
        } else {
            (input.parent().map_or_else(|| PathBuf::from("."), Path::to_path_buf), input.to_path_buf())
        };
        Self {
            manifest_json: dir.join(MANIFEST_JSON),
            manifest_txt: dir.join(MANIFEST_TXT),
            data_zip: dir.join(DATA_ZIP),
            dir,
            dump,
        }
    }

    /// 结构校验：`agf.dump` 必须存在。
    ///
    /// # Errors
    /// dump 文件缺失。
    pub fn validate(&self) -> Result<(), AppError> {
        if !self.dump.is_file() {
            return Err(AppError::Exit(Exit::failed(format!(
                "找不到备份文件: {}（--in 传备份目录或其中的 {DUMP_NAME}）",
                self.dump.display()
            ))));
        }
        Ok(())
    }
}

/// 逐字节渲染 PowerShell 兼容清单（与 `backup.ps1` 的格式对齐：`{name,-40} {bytes,14}  {sha256}`）。
#[must_use]
pub fn render_manifest_txt(header: &[String], entries: &[ManifestEntry]) -> String {
    let mut lines: Vec<String> = header.to_vec();
    lines.push(String::new());
    lines.push(format!("{:<40} {:>14}  {}", "文件", "字节", "sha256"));
    for e in entries {
        lines.push(format!("{:<40} {:>14}  {}", e.path, e.bytes, e.sha256));
    }
    format!("{}\n", lines.join("\n"))
}

/// 解析 PowerShell 兼容清单的一行（`名字 字节数 sha256`）。
///
/// 非法行（表头、说明、空行）返回 `None`。
#[must_use]
pub fn parse_manifest_txt_line(line: &str) -> Option<ManifestEntry> {
    let mut parts = line.split_whitespace();
    let path = parts.next()?;
    let bytes: u64 = parts.next()?.parse().ok()?;
    let sha256 = parts.next()?;
    if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(ManifestEntry { path: path.to_string(), bytes, sha256: sha256.to_ascii_lowercase() })
}

/// 解析整份文本清单。
#[must_use]
pub fn parse_manifest_txt(text: &str) -> Vec<ManifestEntry> {
    text.lines().filter_map(parse_manifest_txt_line).collect()
}

/// 执行外部命令。
///
/// - `stdout_to`：`Some(path)` 时把 stdout 重定向到文件（`pg_dump -Fc` 是二进制，必须如此）；
/// - 否则 stdout 丢弃（`pg_restore` 不需要 stdout）。
///
/// # Errors
/// 可执行文件不存在（[`ProcessFailure::NotFound`]）、启动失败或退出码非 0。
pub(crate) fn run_command(
    program: &str,
    args: &[String],
    env: &[(String, String)],
    stdout_to: Option<&Path>,
    stdin_from: Option<&Path>,
) -> Result<(), ProcessFailure> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.stdin(if stdin_from.is_some() { Stdio::piped() } else { Stdio::null() });
    cmd.stdout(match stdout_to {
        Some(path) => Stdio::from(std::fs::File::create(path).map_err(|e| ProcessFailure::Spawn(e.to_string()))?),
        None => Stdio::null(),
    });
    cmd.stderr(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(ProcessFailure::NotFound),
        Err(e) => return Err(ProcessFailure::Spawn(e.to_string())),
    };

    if let Some(src) = stdin_from {
        let mut file = std::fs::File::open(src).map_err(|e| ProcessFailure::Spawn(e.to_string()))?;
        if let Some(mut stdin) = child.stdin.take() {
            std::io::copy(&mut file, &mut stdin).map_err(|e| ProcessFailure::Spawn(e.to_string()))?;
        }
    }

    let out = child.wait_with_output().map_err(|e| ProcessFailure::Spawn(e.to_string()))?;
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    match classify_process_result(out.status.code(), &stderr) {
        None => Ok(()),
        Some(failure) => Err(failure),
    }
}

/// 把进程失败映射为带 TODO 锚点的 [`AppError`]。
#[must_use]
pub fn process_error(program: &str, failure: &ProcessFailure, masked_target: &str) -> AppError {
    let describe = failure.describe(program);
    if failure.is_dependency_unavailable() {
        AppError::Exit(Exit::dependency_unavailable(format!(
            "{describe}（目标 {masked_target}）\n\
             提示：安装 PostgreSQL 客户端并把 pg_dump/pg_restore 加入 PATH，\
             或用 AGF_PG_DUMP/AGF_PG_RESTORE 指定可执行文件路径；\
             口令经 PGPASSWORD 传递（不出现在命令行）\n\
             TODO(agfctl-pg-tools)：容器内 pg_dump/pg_restore 路径由 scripts/backup.ps1 覆盖，\
             agfctl 侧需在部署环境（阶段二）验证"
        )))
    } else {
        AppError::Exit(Exit::failed(format!("{describe}（目标 {masked_target}）")))
    }
}

/// 程序名（允许用环境变量覆盖，便于异构环境/测试）。
#[must_use]
pub fn program_or(env_key: &str, default: &str) -> String {
    match std::env::var(env_key) {
        Ok(v) if !v.trim().is_empty() => v,
        _ => default.to_string(),
    }
}

/// 解析备份根目录（`--out` 优先，否则 `<data_dir>/backup/<时间戳>`）。
#[must_use]
pub fn resolve_backup_dir(out: Option<&Path>, data_dir: &Path) -> PathBuf {
    out.map_or_else(
        || data_dir.join("backup").join(chrono::Local::now().format(STAMP_FORMAT).to_string()),
        Path::to_path_buf,
    )
}

/// `backup`。
///
/// # Errors
/// - pg_dump 缺失 / PG 不可达 → 退出码 2；
/// - 数据打包或清单写入失败 → `Fatal`（退出码 1）。
pub async fn backup(out: Option<&Path>, skip_data: bool, url: Option<&str>, output: Output) -> Result<(), AppError> {
    let target = crate::db::resolve_target(url)?;
    // 先做一次真连接：pg_dump 的连接错误信息在不同版本上差异较大，
    // 我们自己的探测能给出更准确的"依赖不可用"结论。
    let pool = crate::db::connect(&target).await?;
    pool.close().await;

    let data_dir = std::env::var("AGF_DATA_DIR").unwrap_or_else(|_| "./data".to_string());
    let dest = resolve_backup_dir(out, Path::new(&data_dir));
    std::fs::create_dir_all(&dest)?;

    let program = program_or("AGF_PG_DUMP", PG_DUMP);
    let dump_path = dest.join(DUMP_NAME);
    let args = vec!["-Fc".to_string(), "-f".to_string(), dump_path.to_string_lossy().to_string()];
    run_command(&program, &args, &target.libpq_env(), None, None)
        .map_err(|f| process_error(&program, &f, &target.masked()))?;
    if !dump_path.is_file() {
        return Err(AppError::Exit(Exit::failed(format!(
            "`{program}` 退出码为 0 但未产出 {}（备份不可信，按失败处理）",
            dump_path.display()
        ))));
    }

    let mut with_data = false;
    if !skip_data {
        let project_root = std::env::var("AGF_PROJECT_ROOT").unwrap_or_else(|_| ".".to_string());
        let dirs: Vec<PathBuf> =
            DATA_SUBDIRS.iter().map(|d| Path::new(&project_root).join(d)).filter(|d| d.is_dir()).collect();
        if dirs.is_empty() {
            output.error("说明：data/{seed,uploads,fixtures} 均不存在，本次只备份数据库");
        } else {
            let zip_path = dest.join(DATA_ZIP);
            let (entries, bytes) = crate::archive::zip_dirs(Path::new(&project_root), &dirs, &zip_path)?;
            with_data = true;
            output.line(&format!("数据目录已打包：{entries} 个文件，{bytes} 字节"));
        }
    }

    // 清单：结构化 JSON + PowerShell 兼容文本
    let mut entries = Vec::new();
    for file in crate::manifest::collect_files(&dest)? {
        let name = file.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_string();
        if name == MANIFEST_JSON || name == MANIFEST_TXT || name == README_TXT {
            continue;
        }
        entries.push(ManifestEntry::from_file(&dest, &file)?);
    }
    entries.sort_by(|a, b| a.path.cmp(&b.path));

    let manifest = BackupManifest {
        generated_at: now_rfc3339(),
        version: crate::VERSION.to_string(),
        target: target.masked(),
        with_data,
        files: entries.clone(),
    };
    std::fs::write(dest.join(MANIFEST_JSON), format!("{}\n", serde_json::to_string_pretty(&manifest)?))?;

    let header = vec![
        format!("备份时间：{}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S")),
        format!("项目根：{}", std::env::var("AGF_PROJECT_ROOT").unwrap_or_else(|_| ".".to_string())),
        format!("数据库：{}（agfctl 本机 pg_dump）", target.masked()),
    ];
    std::fs::write(dest.join(MANIFEST_TXT), render_manifest_txt(&header, &entries))?;

    let readme = format!(
        "AIGuardFabric 备份包（agfctl 生成）\n\n生成：{}\n\n恢复步骤：\n  \
         1) 启动依赖：scripts\\dev-up.ps1 -DepsOnly\n  \
         2) 恢复数据库：agfctl restore --in \"{}\" --force\n  \
         3) 或容器拓扑：scripts\\restore.ps1 -BackupFile \"{}\"\n  \
         4) 恢复数据目录：agfctl restore --in \"{}\" --force --with-data\n  \
         5) 校验：agfctl db check-schema 与 GET /healthz\n",
        manifest.generated_at,
        dest.display(),
        dest.display(),
        dest.display()
    );
    std::fs::write(dest.join(README_TXT), readme)?;

    if output.is_json() {
        output.emit(&serde_json::json!({
            "ok": true,
            "dir": dest.to_string_lossy().replace('\\', "/"),
            "target": target.masked(),
            "with_data": with_data,
            "files": manifest.files,
        }))?;
    } else {
        output.line(&format!("备份完成：{}", dest.display()));
        output.line(&format!("  数据库: {}", target.masked()));
        output.line(&format!("  数据目录: {}", if with_data { "已打包" } else { "未纳入" }));
        for entry in &manifest.files {
            output.line(&format!("  {:<20} {:>12} 字节  {}", entry.path, entry.bytes, entry.sha256));
        }
    }
    Ok(())
}

/// `restore`。
///
/// # Errors
/// - pg_restore 缺失 / PG 不可达 → 退出码 2；
/// - 备份包校验不一致 / pg_restore 执行失败 → 退出码 1。
pub async fn restore(
    input: &Path,
    with_data: bool,
    no_pre_backup: bool,
    force: bool,
    url: Option<&str>,
    output: Output,
) -> Result<(), AppError> {
    let layout = BackupLayout::resolve(input);
    layout.validate()?;

    // 1) 校验备份包完整性（存在清单才校验；缺清单时如实提示而不是假装通过）
    verify_backup_package(&layout, output)?;

    // 2) 破坏性操作必须显式确认
    if !force {
        output.error(&format!(
            "恢复是破坏性操作（pg_restore --clean --if-exists），请加 --force 显式确认；目标库：{}",
            layout.dir.display()
        ));
        return Err(AppError::Exit(Exit::failed("缺少 --force，已中止（未做任何修改）")));
    }

    let target = crate::db::resolve_target(url)?;
    let pool = crate::db::connect(&target).await?;
    pool.close().await;

    if !no_pre_backup {
        output.line("恢复前自动备份当前库（可用 --no-pre-backup 跳过）...");
        let data_dir = std::env::var("AGF_DATA_DIR").unwrap_or_else(|_| "./data".to_string());
        let pre = resolve_backup_dir(None, Path::new(&data_dir));
        backup(Some(&pre), true, Some(&target.dsn()), Output::text()).await?;
        output.line(&format!("  已备份到 {}", pre.display()));
    }

    let program = program_or("AGF_PG_RESTORE", PG_RESTORE);
    let args = vec![
        "--clean".to_string(),
        "--if-exists".to_string(),
        "--no-owner".to_string(),
        "--dbname".to_string(),
        target.database.clone(),
        layout.dump.to_string_lossy().to_string(),
    ];
    run_command(&program, &args, &target.libpq_env(), None, None)
        .map_err(|f| process_error(&program, &f, &target.masked()))?;

    let mut restored_files = 0_usize;
    if with_data {
        if layout.data_zip.is_file() {
            let project_root = std::env::var("AGF_PROJECT_ROOT").unwrap_or_else(|_| ".".to_string());
            restored_files = crate::archive::unzip_into(&layout.data_zip, Path::new(&project_root))?;
        } else {
            output.error("说明：备份包内没有 data-files.zip，跳过数据目录恢复");
        }
    }

    if output.is_json() {
        output.emit(&serde_json::json!({
            "ok": true,
            "dir": layout.dir.to_string_lossy().replace('\\', "/"),
            "dump": layout.dump.to_string_lossy().replace('\\', "/"),
            "target": target.masked(),
            "with_data": with_data,
            "restored_data_files": restored_files,
        }))?;
    } else {
        output.line(&format!("恢复完成：{}", layout.dump.display()));
        output.line(&format!("  目标库: {}", target.masked()));
        output.line("  方式: pg_restore --clean --if-exists --no-owner（不 DROP DATABASE）");
        if with_data {
            output.line(&format!("  数据目录: 解包 {restored_files} 个文件"));
        }
        output.line("  校验建议: agfctl db check-schema；GET /healthz");
    }
    Ok(())
}
