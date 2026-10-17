//! 通用工具：错误容忍、数据集加载与 JSON 字段取值（自 seed.rs 拆出，逻辑未变）。

use super::*;

// ===========================================================================
// 通用工具
// ===========================================================================

/// 路径展示（`\` → `/`）。
pub(super) fn display_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// 是否为不可降级的后端错误（内存锁中毒）。
pub(super) fn is_fatal_backend_error(error: &DomainError) -> bool {
    matches!(error, DomainError::Internal(_))
}

/// 可降级失败：`warn` + 计入 `errors`，不中断。
pub(super) fn tolerate<T>(
    outcome: DomainResult<T>,
    dataset: &str,
    what: &str,
    stat: &mut DatasetReport,
) -> DomainResult<()> {
    match outcome {
        Ok(_) => Ok(()),
        Err(error) if !is_fatal_backend_error(&error) => {
            warn!(dataset, what, error = %error, "演示数据写入失败，已跳过该条（降级）");
            stat.errors += 1;
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// 写入成功计数 + [`tolerate`]。
pub(super) fn settle<T>(
    outcome: DomainResult<T>,
    dataset: &str,
    what: &str,
    stat: &mut DatasetReport,
) -> DomainResult<()> {
    let ok = outcome.is_ok();
    tolerate(outcome, dataset, what, stat)?;
    if ok {
        stat.inserted += 1;
    }
    Ok(())
}

/// 数据集不可用（文件缺失 / 整体解析失败）：`warn` + 记 `skipped`，绝不返回错误。
pub(super) fn mark_dataset_unavailable(report: &mut SeedReport, dataset: &str, file: &str, reason: &str) {
    warn!(dataset, file, reason, "演示数据集不可用，已跳过（降级，不影响服务启动）");
    report.warnings.push(format!("{dataset}（{file}）：{reason}"));
    let stat = report.stat(dataset, file);
    stat.skipped += 1;
    stat.note = format!("数据集不可用：{reason}");
}

/// 读取 `<root>/<file>` 的 `items` 数组。
///
/// 返回 `(items, 说明)`；`Err` 表示文件缺失或整体解析失败（调用方降级）。
pub(super) fn load_items(root: &Path, file: &str) -> Result<(Vec<Value>, Option<String>), String> {
    let path = root.join(file);
    if !path.is_file() {
        return Err(format!("文件 {} 不存在", display_path(&path)));
    }
    let raw = std::fs::read_to_string(&path).map_err(|e| format!("文件 {} 读取失败：{e}", display_path(&path)))?;
    let doc: Value =
        serde_json::from_str(&raw).map_err(|e| format!("文件 {} JSON 解析失败：{e}", display_path(&path)))?;
    let Some(items) = doc.get("items").and_then(Value::as_array) else {
        return Err(format!("文件 {} 缺少 items 数组", display_path(&path)));
    };
    // index.json 的 count 只是提示：以实际 items 为准，不一致时如实记 warn
    let note = match doc.get("count").and_then(Value::as_u64) {
        Some(declared) if usize::try_from(declared).unwrap_or(usize::MAX) != items.len() => {
            Some(format!("声明 count={declared} 与实际 items={} 不一致，以实际为准", items.len()))
        }
        _ => None,
    };
    Ok((items.clone(), note))
}

/// 必填字符串字段。
pub(super) fn req_str(item: &Value, key: &str) -> Result<String, String> {
    item.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| format!("字段 {key} 缺失或为空"))
}

/// 可选字符串字段。
pub(super) fn opt_str(item: &Value, key: &str) -> Option<String> {
    item.get(key).and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).map(ToString::to_string)
}

/// 可选 `u8` 字段（越界视为缺失）。
pub(super) fn opt_u8(item: &Value, key: &str) -> Option<u8> {
    item.get(key).and_then(Value::as_u64).and_then(|v| u8::try_from(v).ok())
}

/// 可选 `u64` 字段。
pub(super) fn opt_u64(item: &Value, key: &str) -> Option<u64> {
    item.get(key).and_then(Value::as_u64)
}

/// 字符串数组字段。
pub(super) fn str_list(item: &Value, key: &str) -> Vec<String> {
    item.get(key)
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).map(ToString::to_string).collect())
        .unwrap_or_default()
}

/// 可选 RFC 3339 时间字段（解析失败记 `warn` 并按缺失处理）。
pub(super) fn opt_timestamp(item: &Value, key: &str) -> Option<Timestamp> {
    let raw = opt_str(item, key)?;
    match Timestamp::parse_rfc3339(&raw) {
        Ok(at) => Some(at),
        Err(e) => {
            warn!(key, raw = %raw, error = %e, "演示数据时间字段解析失败，已按缺失处理（回退当前时间）");
            None
        }
    }
}
