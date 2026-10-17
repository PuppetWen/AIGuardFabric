//! 由 `engine.rs` 拆分：`RuntimeEngine` 的实现（纯搬移，逻辑不变）。
use super::*;

impl RuntimeEngine {
    /// 记录一次"策略命中"审计（`agf-api` 落 `policy_hits` 表前的内存镜像）。
    ///
    /// **耗时口径（如实标注）**：本函数在调用方**已经拿到决策之后**才被调用，自己测不到
    /// 求值耗时。因此 `latency_micros` 直接取策略引擎**真实测得**的求值耗时
    /// [`PolicyDecision::eval_micros`]（由 [`crate::policy::PolicyEngine`] 用 `Instant` 填充，
    /// 覆盖策略命中与黑名单否决两条路径）；调用方给的决策没有测量值（`eval_micros == 0`，
    /// 如手工构造的决策）时**如实保持 0**（0 = "无测量值"），
    /// 绝不用"构造记录"的几微秒冒充决策时延。
    ///
    /// 与 MCP 代理点（[`crate::mcp_proxy::McpProxy::intercept_request`] 测整段拦截耗时）相比，
    /// 本埋点的口径更窄：**只有策略求值**——这正是 AI 网关 / 进程 Hook 两个点的公开契约
    /// （`evaluate` 求值 + `record_decision` 落链，网关与 Hook 自身不在这条链上）。
    ///
    /// # Errors
    /// 审计链锁中毒。
    pub fn record_decision(
        &self,
        ctx: &PolicyContext,
        decision: &PolicyDecision,
        excerpt: &str,
    ) -> DomainResult<InterceptionRecord> {
        let verdict = InterceptionVerdict::from_action(decision.action, decision.dry_run);
        let mut record =
            InterceptionRecord::new(ctx.tenant_id, &ctx.session_id, ctx.intercept_point, verdict, &decision.reason)
                .with_decision(decision)
                .with_latency_micros(decision.eval_micros)
                .with_excerpt(excerpt);
        record.agent_id = ctx.agent_id;
        record.tool_name = ctx.tool_name.clone();
        self.record_interception(record)
    }
    /// 便捷：是否需要因该决策而阻断（供网关侧直接使用）。
    #[must_use]
    pub fn is_blocking(decision: &PolicyDecision) -> bool {
        decision.is_blocking()
    }
    /// 便捷：动作 → HTTP 状态码建议（网关与 API 共用）。
    #[must_use]
    pub const fn status_for(action: PolicyAction) -> u16 {
        match action {
            PolicyAction::Deny | PolicyAction::Isolate | PolicyAction::CircuitBreak => 403,
            PolicyAction::Throttle | PolicyAction::Quota => 429,
            PolicyAction::Approval => 202,
            _ => 200,
        }
    }
}
