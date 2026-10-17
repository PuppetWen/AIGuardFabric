//! 平台统计快照、`AssetBackend` 适配与公共助手函数。

use super::*;

/// 平台统计快照（内存后端版本）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PlatformSnapshot {
    /// 资产总数。
    pub assets: i64,
    /// 生产环境资产数。
    pub assets_production: i64,
    /// 未评审的 MCP 资产数。
    pub shadow_mcps: i64,
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
    /// 扫描任务数。
    pub scans: i64,
}

#[async_trait]
impl AssetBackend for ApiStore {
    async fn find_by_fingerprint(&self, tenant: TenantId, fingerprint: &str) -> DomainResult<Option<Asset>> {
        self.asset_find_by_fingerprint(tenant, fingerprint)
    }

    async fn find(&self, tenant: TenantId, id: Id) -> DomainResult<Option<Asset>> {
        self.asset_get(tenant, id)
    }

    async fn list_all(&self, tenant: TenantId) -> DomainResult<Vec<Asset>> {
        self.asset_list_all(tenant)
    }

    async fn upsert(&self, _tenant: TenantId, asset: &Asset) -> DomainResult<Id> {
        self.asset_upsert(asset)
    }

    async fn record_change(&self, _tenant: TenantId, change: &AssetChange) -> DomainResult<()> {
        self.asset_record_change(change)
    }

    async fn snapshot(&self, tenant: TenantId, date: &str, asset: &Asset) -> DomainResult<()> {
        self.asset_snapshot(tenant, date, asset)
    }

    async fn snapshot_hashes(&self, tenant: TenantId, date: &str) -> DomainResult<BTreeMap<Id, String>> {
        self.asset_snapshot_hashes(tenant, date)
    }
}

/// 构造"最近 N 秒"的时间窗口（报表与统计复用）。
#[must_use]
pub fn recent_window(secs: i64) -> TimeRange {
    TimeRange::last_secs(secs)
}

/// 报表构造助手（Markdown 报表生成路径的公共部分）。
#[must_use]
pub fn new_report(
    tenant: TenantId,
    kind: ReportKind,
    title: impl Into<String>,
    range: TimeRange,
    body: String,
    created_by: Option<Id>,
) -> Report {
    let now = Timestamp::now();
    let id = Id::new();
    Report {
        id,
        tenant_id: tenant,
        kind,
        title: title.into(),
        state: ReportState::Completed,
        range,
        format: ReportFormat::Markdown,
        template_key: None,
        filters: serde_json::Value::Null,
        content_hash: Some(agf_core::secret::content_hash(&body)),
        artifact_bytes: Some(u64::try_from(body.len()).unwrap_or(u64::MAX)),
        body: Some(body),
        // 内存后端的报表体就是产物本身；`artifact_ref` 用于 `Report::is_downloadable()`
        // 与"产物在哪儿"的可追溯性（当前仅支持内存，见 TODO(api-persistence)）。
        artifact_ref: Some(format!("memory://reports/{id}")),
        ai_generated: false,
        model: None,
        mocked: false,
        error: None,
        created_by,
        schedule_id: None,
        created_at: now,
        completed_at: Some(now),
    }
}

/// 解析案件编号 `CASE-<年>-<序号>`（水合时恢复 `case_seq` 用；格式非法返回 `None`）。
#[must_use]
pub fn parse_case_code(code: &str) -> Option<(i32, u32)> {
    let rest = code.strip_prefix("CASE-")?;
    let (year, seq) = rest.split_once('-')?;
    Some((year.parse().ok()?, seq.parse().ok()?))
}

/// 策略动作 → 指标标签（供 `/metrics` 的 `agf_interceptions_total` 使用）。
#[must_use]
pub fn action_label(action: agf_core::enums::PolicyAction) -> &'static str {
    action.as_str()
}
