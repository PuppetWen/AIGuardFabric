//! 风险历史文件的读写与路径解析（自 `history.rs` 拆出，逻辑未变）。

use super::*;

/// 从磁盘加载采样点。
///
/// 行为（**逐条如实**）：
///
/// | 情况 | 行为 |
/// |---|---|
/// | 文件不存在 | 返回空列表（正常的首次启动，不记 `warn`、不报错） |
/// | JSON 损坏 / 版本过高 | `warn` + Err（装配侧停止自动写入，保留原文件） |
/// | 文件存在但读不动（权限/IO） | `warn` + `Err`——这类失败通常是**部署问题**（挂载点/权限），值得让调用方看见 |
/// | 正常 | 解析后经 [`normalize`]（小时桶合并 + 裁剪；旧版先完整归档再重新观测）返回 |
///
/// 调用方按既定降级铁律处理 `Err`：记 `warn`/`notes` 后继续启动，
/// **不要**让一条 KPI 历史曲线阻断服务（参考 `state` 里 `AGF_*_DIR` 的处理方式）。
///
/// # Errors
/// 读取失败、格式无效或无法完整归档旧版历史。
pub fn load_from(path: impl AsRef<Path>) -> DomainResult<Vec<Sample>> {
    let path = path.as_ref();
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // 首次启动的正常路径：文件还没被写过。
            return Ok(Vec::new());
        }
        Err(error) => {
            warn!(
                path = %path.display(),
                error = %error,
                "风险历史文件不可读（调用方应按降级处理：记 note 后继续启动，不影响服务）"
            );
            return Err(agf_core::error::DomainError::Internal(format!(
                "风险历史文件不可读: {}（{error}）",
                path.display()
            )));
        }
    };
    match parse_samples(&raw) {
        Ok(samples) => {
            if super::migration::archive_legacy(path, &raw)? {
                return Ok(Vec::new());
            }
            Ok(normalize(samples))
        }
        Err(error) => {
            warn!(
                path = %path.display(),
                error = %error,
                "风险历史文件损坏或版本不受支持，按空历史处理（原文件保持不动，交人工处置）"
            );
            Err(agf_core::error::DomainError::Internal(format!("Invalid risk history: {error}")))
        }
    }
}

/// 原子写入采样点。
///
/// 步骤：`create_dir_all(父目录)` → 写唯一临时文件 → `rename` 覆盖目标。
/// **任何一步失败都只 `warn`**（不返回错误、不 panic），失败时尽量清掉临时文件。
pub fn save_to(path: impl AsRef<Path>, samples: &[Sample]) {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            if let Err(error) = std::fs::create_dir_all(parent) {
                warn!(
                    path = %parent.display(),
                    error = %error,
                    "风险历史目录创建失败，本次采样不落盘（不影响请求）"
                );
                return;
            }
        }
    }
    let payload =
        match serde_json::to_string_pretty(&HistoryFile { version: FORMAT_VERSION, samples: samples.to_vec() }) {
            Ok(payload) => payload,
            Err(error) => {
                warn!(error = %error, "风险历史序列化失败，本次采样不落盘（不影响请求）");
                return;
            }
        };
    let temp = temp_path(path);
    if let Err(error) = std::fs::write(&temp, payload.as_bytes()) {
        warn!(
            path = %temp.display(),
            error = %error,
            "风险历史临时文件写入失败，本次采样不落盘（不影响请求）"
        );
        return;
    }
    if let Err(error) = std::fs::rename(&temp, path) {
        warn!(
            path = %path.display(),
            error = %error,
            "风险历史原子替换失败（原文件保持不变），本次采样不落盘"
        );
        let _ = std::fs::remove_file(&temp);
    }
}

/// 缺省文件路径：`AGF_RISK_HISTORY_PATH` 优先，否则 `<AGF_DATA_DIR 或 data>/state/risk-history.json`。
#[must_use]
pub fn default_path() -> PathBuf {
    let override_path = std::env::var_os(ENV_RISK_HISTORY_PATH);
    let data_dir = std::env::var_os(ENV_DATA_DIR);
    path_for(data_dir.as_deref(), override_path.as_deref())
}

/// 路径解析（纯函数，便于单测：不改环境变量也能验证优先级）。
///
/// 优先级：`override_path`（`AGF_RISK_HISTORY_PATH`，非空）＞ `data_dir`（`AGF_DATA_DIR`，非空）
/// ＞ [`DEFAULT_DATA_DIR`]（`data`）。空串一律视为"未设置"（部署脚本里 `VAR=` 很常见）。
#[must_use]
pub fn path_for(data_dir: Option<&OsStr>, override_path: Option<&OsStr>) -> PathBuf {
    if let Some(raw) = override_path.filter(|value| !value.is_empty()) {
        return PathBuf::from(raw);
    }
    let base =
        data_dir.filter(|value| !value.is_empty()).map_or_else(|| PathBuf::from(DEFAULT_DATA_DIR), PathBuf::from);
    base.join(STATE_DIR).join(FILE_NAME)
}
