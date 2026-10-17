//! 由 `playbook.rs` 拆分：`retry` 等 3 个函数（纯搬移，逻辑不变）。
use super::*;

/// 带重试地执行一个异步动作（自由函数，避免与 `&mut self` 借用冲突）。
pub(crate) async fn retry<F, Fut>(max_attempts: u32, mut op: F) -> StepExecution
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<String, String>>,
{
    let max = max_attempts.max(1);
    let mut attempts = 0u32;
    let mut last_error = String::new();
    while attempts < max {
        attempts = attempts.saturating_add(1);
        match op().await {
            Ok(note) => return StepExecution::Succeeded { attempts, note },
            Err(e) => last_error = e,
        }
    }
    StepExecution::Failed { attempts, error: last_error }
}

/// 解析 YAML 剧本集。
///
/// 接受三种形态：
/// - 顶层**单剧本**（映射，带 `steps:`）；
/// - `playbooks:` 下的**剧本列表**（多剧本文件）；
/// - `playbooks:` 下只放**一个剧本**（映射形态，等价于单剧本，便于分文件/分环境裁剪）。
///
/// # Errors
/// YAML 解析失败、单剧本校验失败、列表为空或含非法剧本时返回错误。
pub fn parse_playbooks_yaml(yaml: &str) -> Result<Vec<Playbook>, PlaybookError> {
    let value: serde_yaml::Value =
        serde_yaml::from_str(yaml).map_err(|e| PlaybookError::Invalid(format!("YAML 解析失败：{e}")))?;
    // `playbooks:` 存在时以它为准（顶层其它键忽略，例如注释性的 `version:`）。
    let root = value.get("playbooks").cloned().unwrap_or(value);
    let books = match serde_yaml::from_value::<Vec<Playbook>>(root.clone()) {
        Ok(list) => list,
        // 不是列表 ⇒ 尝试按单个剧本解析（`playbooks:` 下只放一个映射的写法）。
        Err(_) => vec![
            serde_yaml::from_value::<Playbook>(root)
                .map_err(|e| PlaybookError::Invalid(format!("剧本解析失败：{e}")))?,
        ],
    };
    if books.is_empty() {
        return Err(PlaybookError::Invalid("剧本列表为空".to_string()));
    }
    for book in &books {
        book.validate().map_err(|errs| PlaybookError::Invalid(format!("{}：{}", book.key, errs.join("；"))))?;
    }
    Ok(books)
}

/// 便捷：把剧本里的渠道短键（`dingtalk` / `in-app` / `wecom`）解析为 [`core_notify::ChannelKind`]。
///
/// 归一规则：大小写不敏感，`_` 视为 `-`；未知键返回 `None`（由调用方报错，不静默丢弃通知）。
#[must_use]
pub fn parse_channel_key(key: &str) -> Option<core_notify::ChannelKind> {
    let normalized = key.trim().to_ascii_lowercase().replace('_', "-");
    core_notify::ChannelKind::all().into_iter().find(|k| k.as_str() == normalized)
}
