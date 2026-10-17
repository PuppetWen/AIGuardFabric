//! 冷归档回灌的 **env 驱动入口**（子命令 `agf-ingest archive-replay` 与启动期
//! `AGF_ARCHIVE_REPLAY=1` 共用同一条路径）。
//!
//! 与 [`super::replay`] 的分工：那边是**回灌引擎**（过滤器 / 幂等账本 / 报告 / `ColdReplayer`），
//! 这边只做"把环境变量翻译成一次回灌调用"——不碰解析与落库逻辑（口径只有一份）。
//!
//! 读的环境变量：
//! * `AGF_ARCHIVE_PREFIX` / `AGF_ARCHIVE_FORMAT`（与归档侧同一套配置）；
//! * `AGF_ARCHIVE_REPLAY_FROM` / `_TO` / `_TENANT`（[`ReplayFilter::from_env`]）；
//! * `AGF_ARCHIVE_REPLAY_STATE`（幂等账本路径；未配置 ⇒ 进程内账本）；
//! * `AGF_ARCHIVE_REPLAY_KEYS`（逗号分隔的对象键，**优先**）或
//!   `AGF_ARCHIVE_REPLAY_DATE`（某一天 `dt=` 分区）或（都缺省）整个前缀；
//! * `AGF_ARCHIVE_REPLAY_LIMIT`（单次列举上限，默认 1000）；
//! * `AGF_S3_*`（对象存储端点/凭据；缺省 ⇒ 本地目录，`build_object_store` 的既有降级）。

use super::*;
use crate::pipeline::Sink;

/// 由 env 构造对象存储（复用 `agf-storage` 的选择逻辑：`AGF_S3_*` 齐全 ⇒ S3/MinIO，否则本地目录）。
///
/// 返回 `(store, 降级说明)`——降级说明非空时调用方应 `warn!` 出来（不静默换后端）。
///
/// # Errors
/// 应用配置解析失败。
pub async fn object_store_from_env() -> DomainResult<(Arc<dyn agf_storage::ObjectStore>, Option<String>)> {
    let env_map: std::collections::BTreeMap<String, String> = std::env::vars().collect();
    let app = agf_core::config::from_env_map(&env_map)
        .map_err(|e| DomainError::Config(format!("回灌：应用配置解析失败（{e}）")))?;
    let storage = agf_storage::StorageConfig::from(&app);
    Ok(agf_storage::build_object_store(&storage).await)
}

/// 读一段可选文本 env（空白视为未配置）。
#[must_use]
pub fn env_text(key: &str) -> Option<String> {
    std::env::var(key).ok().map(|value| value.trim().to_string()).filter(|value| !value.is_empty())
}

/// 读一个可选的 usize env（非法值 ⇒ 默认值 + warn，绝不让回灌起不来）。
#[must_use]
pub fn env_usize(key: &str, default: usize) -> usize {
    match env_text(key) {
        Some(text) => match text.parse::<usize>() {
            Ok(value) => value.max(1),
            Err(e) => {
                warn!(key, value = %text, error = %e, "回灌配置项不是正整数，按默认值继续");
                default
            }
        },
        None => default,
    }
}

/// env 驱动的回灌（子命令与启动期开关共用）。
///
/// 回灌写回**传入的 sink**（调用方应传与流水线同一个实例），结束后把账本落盘。
///
/// # Errors
/// 配置非法、列举失败、sink 不可写、账本落盘失败。
pub async fn replay_from_env(sink: Arc<dyn Sink>) -> DomainResult<ReplayReport> {
    let (store, degrade_note) = object_store_from_env().await?;
    if let Some(note) = degrade_note {
        warn!(note = %note, "回灌：对象存储按降级路径使用（本地/内存），对象可能不在预期后端");
    }
    let config = ColdArchiveConfig {
        prefix: env_text("AGF_ARCHIVE_PREFIX").unwrap_or_else(|| ColdArchiveConfig::default().prefix),
        format: ColdFormat::from_env(),
        ..ColdArchiveConfig::default()
    };
    let backend = store.backend();
    let prefix = config.prefix.clone();
    let replayer = ColdReplayer::new(ColdArchiver::new(store, config), sink);
    let filter = ReplayFilter::from_env()?;
    let mut ledger = ReplayLedger::from_env()?;
    let limit = env_usize("AGF_ARCHIVE_REPLAY_LIMIT", 1000);

    let report = if let Some(keys) = env_text("AGF_ARCHIVE_REPLAY_KEYS") {
        let keys: Vec<String> =
            keys.split(',').map(|key| key.trim().to_string()).filter(|key| !key.is_empty()).collect();
        replayer.replay_keys(&keys, &filter, &mut ledger).await?
    } else if let Some(date) = env_text("AGF_ARCHIVE_REPLAY_DATE") {
        replayer.replay_day(&date, limit, &filter, &mut ledger).await?
    } else {
        replayer.replay_prefix(&prefix, limit, &filter, &mut ledger).await?
    };
    ledger.save()?;
    let (loaded, added) = ledger.counts();
    tracing::info!(
        storage = backend,
        sink = replayer.sink_backend(),
        filter = %filter.describe(),
        ledger = ?ledger.path(),
        ledger_loaded = loaded,
        ledger_added = added,
        report = %report.summary(),
        "冷归档回灌完成"
    );
    Ok(report)
}
