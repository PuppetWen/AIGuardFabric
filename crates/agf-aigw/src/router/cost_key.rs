//! 由 `router.rs` 拆分：`cost_key` 等 2 个函数（纯搬移，逻辑不变）。
use super::*;

/// 成本排序键：`pricing` 全 0（本地/免费）排最前，其次按输入单价。
pub(crate) fn cost_key(endpoint: &ModelEndpoint) -> (u8, u64) {
    let p = endpoint.pricing;
    let free = u8::from(!p.is_free());
    (free, p.prompt_micro_per_1k.saturating_add(p.completion_micro_per_1k))
}

/// 为请求估算"该端点上一次调用要花多少钱"（成本排序与预算投影共用）。
///
/// `max_completion` 缺省按 1024 估算（与网关预算投影同一默认值）。
#[must_use]
pub fn projected_cost_micro(endpoint: &ModelEndpoint, req: &ChatRequest) -> u64 {
    let prompt = req.estimate_prompt_tokens();
    let completion = u64::from(req.max_tokens.unwrap_or(1024));
    endpoint.estimate_cost_micro(prompt, completion)
}
