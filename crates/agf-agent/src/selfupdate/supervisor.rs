//! 显式外部更新助手；启动失败时只能停止其自身创建并持有句柄的子进程。
use super::{
    download, health,
    install::{StagedUpdate, UpdateReceipt, receipt},
    journal::{self, Phase},
    paths::{InstallRoot, deny, io},
    trust::VerifiedUpdate,
};
use agf_core::error::DomainResult;
use std::time::{Duration, Instant};
/// 下载并验证程序字节，原子安装明确选择的发布并监督启动健康。
/// 默认采集不调用此函数；安装目标必须由外部更新助手明确管理。
///
/// # Errors
/// 下载、信任、路径或占用检查失败时保留旧程序；新子进程启动失败时
/// 从已验证备份回滚；回滚失败则保留 rollback_pending 供显式恢复。
pub async fn download_and_apply(
    update: &VerifiedUpdate,
    root: InstallRoot,
    arguments: &[String],
) -> DomainResult<UpdateReceipt> {
    // 只有 run 会在初始化前启动原始期限看门狗，并在真实平台回执后确认健康。
    // 其他子命令不得进入下载或事务创建，避免助手崩溃后留下无法监督的目标。
    if arguments.first().map(String::as_str) != Some("run") {
        return Err(deny("Supervised updates support only the run subcommand"));
    }
    let mut staged = StagedUpdate::begin(root, update)?;
    if let Err(error) = download::artifact(update, &staged.candidate()?).await {
        staged.fact.failure = Some("artifact_download_failed".into());
        journal::save(&staged.root, &staged.fact)?;
        return Err(error);
    }
    staged.prepared()?;
    supervise(&mut staged, arguments, Duration::from_millis(journal::HEALTH_MS)).await
}
pub(crate) async fn supervise(
    staged: &mut StagedUpdate,
    arguments: &[String],
    window: Duration,
) -> DomainResult<UpdateReceipt> {
    if arguments.len() > 64 || arguments.iter().any(|arg| arg.len() > 4096 || arg.contains('\0')) {
        return Err(deny("Update child argument budget exceeded"));
    }
    staged.replace(window.as_millis().try_into().map_err(|_| deny("Invalid health budget"))?)?;
    let mut command = tokio::process::Command::new(&staged.root.target);
    command
        .args(arguments)
        .current_dir(&staged.root.root)
        .env(health::ENV_ROOT, &staged.root.root)
        .env(health::ENV_TARGET, &staged.fact.target_name)
        .env(health::ENV_TX, staged.fact.transaction.to_string())
        .env(health::ENV_NONCE, staged.fact.nonce.to_string())
        .stdin(std::process::Stdio::null())
        .kill_on_drop(false);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => {
            staged.fact.failure = Some("new_executable_start_failed".into());
            staged.rollback()?;
            return Ok(receipt(&staged.fact));
        }
    };
    let started = Instant::now();
    loop {
        if child.try_wait().map_err(io)?.is_some() {
            staged.fact.failure = Some("new_executable_exited_before_health".into());
            staged.rollback()?;
            return Ok(receipt(&staged.fact));
        }
        if health::valid(&staged.root, &staged.fact)? {
            staged.fact.phase = Phase::Confirmed;
            journal::save(&staged.root, &staged.fact)?;
            return Ok(receipt(&staged.fact));
        }
        if started.elapsed() >= window || journal::now_ms()? >= staged.fact.health_deadline_ms {
            staged.fact.failure = Some("original_startup_health_deadline".into());
            staged.fact.phase = Phase::RollbackPending;
            journal::save(&staged.root, &staged.fact)?;
            // 仅操作上方创建的子进程句柄，不按查询到的 PID 停止其他服务。
            if child.try_wait().map_err(io)?.is_none() {
                if let Err(error) = child.start_kill() {
                    if child.try_wait().map_err(io)?.is_none() {
                        return Err(io(error));
                    }
                }
                tokio::time::timeout(Duration::from_secs(10), child.wait())
                    .await
                    .map_err(|_| deny("Owned update child did not exit; keep rollback pending"))?
                    .map_err(io)?;
            }
            staged.rollback()?;
            return Ok(receipt(&staged.fact));
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
}
