//! GraphQL 端点（`POST /graphql`，`GET /graphql` 返回 GraphiQL）。
//!
//! 至少覆盖 assets / findings / alerts 三类查询，外加平台统计。
//! 授权沿用与 REST 完全相同的 [`Principal::require`]（RBAC + ABAC + 租户隔离），
//! GraphQL 不会绕过权限点检查。

use async_graphql::{Context, EmptyMutation, EmptySubscription, Object, Schema, SimpleObject};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::Router;
use axum::extract::State;
use axum::response::{Html, IntoResponse};
use axum::routing::get;

use crate::middleware::Principal;
use crate::state::AppState;

/// GraphQL Schema 类型别名。
pub type AgfSchema = Schema<QueryRoot, EmptyMutation, EmptySubscription>;

/// 构造 schema（每次请求构造，避免 schema 持有 `AppState` 造成循环依赖）。
#[must_use]
pub fn schema() -> AgfSchema {
    Schema::build(QueryRoot, EmptyMutation, EmptySubscription).finish()
}

/// GraphQL 路由。
pub fn router() -> Router<AppState> {
    Router::new().route("/graphql", get(graphiql).post(execute))
}

/// GraphiQL 控制台。
async fn graphiql() -> impl IntoResponse {
    Html(async_graphql::http::GraphiQLSource::build().endpoint("/graphql").title("AIGuardFabric GraphQL").finish())
}

/// 执行 GraphQL 请求。
async fn execute(
    State(state): State<AppState>,
    principal: Principal,
    request: GraphQLRequest,
) -> Result<GraphQLResponse, crate::error::ApiError> {
    let request = request.into_inner().data(state).data(principal);
    Ok(schema().execute(request).await.into())
}

/// 根查询。
#[derive(Debug, Clone, Copy, Default)]
pub struct QueryRoot;

/// 资产节点。
#[derive(Debug, Clone, SimpleObject)]
pub struct AssetNode {
    /// 资产 id。
    pub id: String,
    /// 名称。
    pub name: String,
    /// 类型。
    pub kind: String,
    /// 生命周期。
    pub lifecycle: String,
    /// 暴露面评分。
    pub exposure_score: i32,
    /// 端点。
    pub endpoint: Option<String>,
    /// 数据分级。
    pub data_class: String,
}

/// 发现节点。
#[derive(Debug, Clone, SimpleObject)]
pub struct FindingNode {
    /// 发现 id。
    pub id: String,
    /// 标题。
    pub title: String,
    /// 严重等级。
    pub severity: String,
    /// 风险域。
    pub domain: String,
    /// 状态。
    pub state: String,
    /// 证据等级。
    pub evidence_level: String,
    /// 目标。
    pub target: String,
}

/// 告警节点。
#[derive(Debug, Clone, SimpleObject)]
pub struct AlertNode {
    /// 告警 id。
    pub id: String,
    /// 标题。
    pub title: String,
    /// 严重等级。
    pub severity: String,
    /// 状态。
    pub state: String,
    /// 聚合次数。
    pub dedup_count: i32,
    /// SLA 是否超时。
    pub sla_breached: bool,
}

/// 平台统计。
#[derive(Debug, Clone, SimpleObject)]
pub struct StatsNode {
    /// 资产总数。
    pub assets: i64,
    /// 生产资产数。
    pub assets_production: i64,
    /// 待处置发现数。
    pub findings_open: i64,
    /// 严重发现数。
    pub findings_critical: i64,
    /// 活动告警数。
    pub alerts_active: i64,
    /// 未关闭案件数。
    pub cases_open: i64,
    /// 策略数。
    pub policies: i64,
}

#[Object]
impl QueryRoot {
    /// 服务版本。
    async fn version(&self) -> &'static str {
        crate::VERSION
    }

    /// 资产列表（最多 `limit` 条，默认 50）。
    async fn assets(
        &self,
        ctx: &Context<'_>,
        limit: Option<i32>,
        kind: Option<String>,
        lifecycle: Option<String>,
    ) -> async_graphql::Result<Vec<AssetNode>> {
        let (state, principal) = guards(ctx, "assets")?;
        let mut assets = state
            .store
            .asset_list_all_durable(principal.tenant)
            .await
            .map_err(|e| async_graphql::Error::new(e.to_string()))?;
        if let Some(kind) = kind {
            assets.retain(|a| a.kind.as_str() == kind);
        }
        if let Some(lifecycle) = lifecycle {
            assets.retain(|a| a.lifecycle.as_str() == lifecycle);
        }
        let limit = usize::try_from(limit.unwrap_or(50).clamp(1, 500)).unwrap_or(50);
        Ok(assets
            .into_iter()
            .take(limit)
            .map(|a| AssetNode {
                id: a.id.to_string(),
                name: a.name,
                kind: a.kind.as_str().to_string(),
                lifecycle: a.lifecycle.as_str().to_string(),
                exposure_score: i32::from(a.exposure_score),
                endpoint: a.endpoint,
                data_class: a.data_class.as_str().to_string(),
            })
            .collect())
    }

    /// 风险发现列表（最多 `limit` 条，默认 50）。
    async fn findings(
        &self,
        ctx: &Context<'_>,
        limit: Option<i32>,
        domain: Option<String>,
        severity: Option<String>,
    ) -> async_graphql::Result<Vec<FindingNode>> {
        let (state, principal) = guards(ctx, "findings")?;
        let mut findings = state
            .store
            .finding_list_all_durable(principal.tenant)
            .await
            .map_err(|e| async_graphql::Error::new(e.to_string()))?;
        if let Some(domain) = domain {
            findings.retain(|f| f.domain.as_str() == domain);
        }
        if let Some(severity) = severity {
            findings.retain(|f| f.severity.as_str() == severity);
        }
        let limit = usize::try_from(limit.unwrap_or(50).clamp(1, 500)).unwrap_or(50);
        Ok(findings
            .into_iter()
            .take(limit)
            .map(|f| FindingNode {
                id: f.id.to_string(),
                title: f.title,
                severity: f.severity.as_str().to_string(),
                domain: f.domain.as_str().to_string(),
                state: f.state.as_str().to_string(),
                evidence_level: f.evidence_level.as_str().to_string(),
                target: f.target,
            })
            .collect())
    }

    /// 告警列表（最多 `limit` 条，默认 50）。
    async fn alerts(
        &self,
        ctx: &Context<'_>,
        limit: Option<i32>,
        state_filter: Option<String>,
    ) -> async_graphql::Result<Vec<AlertNode>> {
        let (state, principal) = guards(ctx, "alerts")?;
        let alert_state = match state_filter.as_deref() {
            Some(raw) => {
                Some(crate::routes::soc::parse_alert_state(raw).map_err(|e| async_graphql::Error::new(e.to_string()))?)
            }
            None => None,
        };
        let alerts = state
            .store
            .alert_list_durable(principal.tenant, alert_state, None)
            .await
            .map_err(|e| async_graphql::Error::new(e.to_string()))?;
        let limit = usize::try_from(limit.unwrap_or(50).clamp(1, 500)).unwrap_or(50);
        Ok(alerts
            .into_iter()
            .take(limit)
            .map(|a| AlertNode {
                id: a.id.to_string(),
                title: a.title,
                severity: a.severity.as_str().to_string(),
                state: a.state.as_str().to_string(),
                dedup_count: i32::try_from(a.dedup_count).unwrap_or(i32::MAX),
                sla_breached: a.sla_breached,
            })
            .collect())
    }

    /// 平台统计。
    async fn platform_stats(&self, ctx: &Context<'_>) -> async_graphql::Result<StatsNode> {
        let (state, principal) = guards(ctx, "reports")?;
        let snapshot = state
            .store
            .platform_snapshot_durable(principal.tenant)
            .await
            .map_err(|e| async_graphql::Error::new(e.to_string()))?;
        Ok(StatsNode {
            assets: snapshot.assets,
            assets_production: snapshot.assets_production,
            findings_open: snapshot.findings_open,
            findings_critical: snapshot.findings_critical,
            alerts_active: snapshot.alerts_active,
            cases_open: snapshot.cases_open,
            policies: snapshot.policies,
        })
    }
}

fn guards<'a>(ctx: &'a Context<'_>, group: &str) -> async_graphql::Result<(&'a AppState, &'a Principal)> {
    let state = ctx.data::<AppState>()?;
    let principal = ctx.data::<Principal>()?;
    principal.require(state, group, "read").map_err(|e| async_graphql::Error::new(e.to_string()))?;
    Ok((state, principal))
}
