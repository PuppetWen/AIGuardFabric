//! 由 `enums.rs` 拆分：`InterceptPoint` 的实现（纯搬移，逻辑不变）。
use super::*;

impl InterceptPoint {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::McpProxy => "mcp-proxy",
            Self::AiGateway => "ai-gateway",
            Self::ProcessHook => "process-hook",
            Self::Collector => "collector",
        }
    }
}
