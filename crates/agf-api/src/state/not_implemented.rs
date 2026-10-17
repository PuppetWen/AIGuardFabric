//! `AppState::not_implemented`：未实现端点的 501 构造（自 `state.rs` 拆出）。

use super::*;

impl AppState {
    pub fn not_implemented(anchor: &'static str, what: &str) -> ApiError {
        warn!(anchor, what, "端点尚未实现，返回 501");
        ApiError::not_implemented(anchor, what.to_string())
    }
}
