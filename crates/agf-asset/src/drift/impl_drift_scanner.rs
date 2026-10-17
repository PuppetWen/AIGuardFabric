//! 由 `drift.rs` 拆分：`DriftReport`/`DriftScanner`/`DriftSummary` 的实现（纯搬移，逻辑不变）。
use super::*;

impl Default for DriftScanner {
    fn default() -> Self {
        Self {
            risky_fields: [
                "endpoint",
                "protocol",
                "version",
                "vendor",
                "data_class",
                "content_sha256",
                "skill_package_sha256",
            ]
            .into_iter()
            .collect(),
            flag_new_unreviewed: true,
        }
    }
}

impl DriftScanner {
    /// 默认检测器。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 自定义"高风险字段"。
    #[must_use]
    pub fn with_risky_fields(mut self, fields: &[&'static str]) -> Self {
        self.risky_fields = fields.iter().copied().collect();
        self
    }

    /// 是否标记新增未评审资产。
    #[must_use]
    pub const fn with_flag_new_unreviewed(mut self, flag: bool) -> Self {
        self.flag_new_unreviewed = flag;
        self
    }

    /// 对两份资产集合做差分。
    ///
    /// - `before`：基线（例如昨日快照）
    /// - `after`：当前
    ///
    /// 返回变更列表（未持久化）。
    #[must_use]
    pub fn diff(&self, before: &[Asset], after: &[Asset]) -> Vec<AssetChange> {
        let before_map: BTreeMap<Id, &Asset> = before.iter().map(|a| (a.id, a)).collect();
        let after_map: BTreeMap<Id, &Asset> = after.iter().map(|a| (a.id, a)).collect();
        let mut changes = Vec::new();
        let now = Timestamp::now();

        // 新增
        for (id, a) in &after_map {
            if before_map.contains_key(id) {
                continue;
            }
            let risky = self.flag_new_unreviewed
                && !matches!(a.lifecycle, LifecycleState::Production)
                && matches!(
                    a.kind,
                    AssetKind::McpServer | AssetKind::Skill | AssetKind::Agent | AssetKind::ModelEndpoint
                );
            changes.push(AssetChange {
                id: Id::new(),
                tenant_id: a.tenant_id,
                asset_id: *id,
                kind: a.kind,
                change_kind: ChangeKind::Added,
                field: None,
                old_value: None,
                new_value: Some(serde_json::to_value(a).unwrap_or(serde_json::Value::Null)),
                risky,
                risk_note: risky
                    .then(|| format!("发现未授权/未评审的 {} 资产（{}），请确认来源与用途", a.kind.as_str(), a.name)),
                domain: risky.then_some(RiskDomain::ToolAbuse),
                detected_at: now,
            });
        }

        // 删除
        for (id, a) in &before_map {
            if after_map.contains_key(id) {
                continue;
            }
            // 归档导致的消失不算异常
            let archived = a.lifecycle == LifecycleState::Archived;
            changes.push(AssetChange {
                id: Id::new(),
                tenant_id: a.tenant_id,
                asset_id: *id,
                kind: a.kind,
                change_kind: ChangeKind::Removed,
                field: None,
                old_value: Some(serde_json::to_value(a).unwrap_or(serde_json::Value::Null)),
                new_value: None,
                risky: !archived && matches!(a.kind, AssetKind::McpServer | AssetKind::Agent),
                risk_note: (!archived).then(|| "资产从台账消失（可能被删除或采集失效），需确认".to_string()),
                domain: None,
                detected_at: now,
            });
        }

        // 变更
        for (id, new) in &after_map {
            let Some(old) = before_map.get(id) else { continue };
            changes.extend(self.diff_one(old, new, now));
        }

        changes.sort_by(|a, b| {
            (a.change_kind.as_str(), a.asset_id.to_string()).cmp(&(b.change_kind.as_str(), b.asset_id.to_string()))
        });
        changes
    }

    /// 单资产差分。
    #[must_use]
    pub fn diff_one(&self, before: &Asset, after: &Asset, now: Timestamp) -> Vec<AssetChange> {
        let mut out = Vec::new();
        let mut push = |field: &'static str, old: serde_json::Value, new: serde_json::Value| {
            let risky = self.risky_fields.contains(field);
            out.push(AssetChange {
                id: Id::new(),
                tenant_id: after.tenant_id,
                asset_id: after.id,
                kind: after.kind,
                change_kind: ChangeKind::Modified,
                field: Some(field.to_string()),
                old_value: Some(old),
                new_value: Some(new),
                risky,
                risk_note: risky.then(|| format!("安全相关字段 {field} 发生变更，需确认是否授权")),
                domain: risky.then_some(RiskDomain::ToolAbuse),
                detected_at: now,
            });
        };

        if before.endpoint != after.endpoint {
            push(
                "endpoint",
                serde_json::Value::from(before.endpoint.clone()),
                serde_json::Value::from(after.endpoint.clone()),
            );
        }
        if before.protocol != after.protocol {
            push(
                "protocol",
                serde_json::to_value(before.protocol).unwrap_or(serde_json::Value::Null),
                serde_json::to_value(after.protocol).unwrap_or(serde_json::Value::Null),
            );
        }
        if before.version != after.version {
            push(
                "version",
                serde_json::Value::from(before.version.clone()),
                serde_json::Value::from(after.version.clone()),
            );
        }
        if before.vendor != after.vendor {
            push(
                "vendor",
                serde_json::Value::from(before.vendor.clone()),
                serde_json::Value::from(after.vendor.clone()),
            );
        }
        if before.data_class != after.data_class {
            push(
                "data_class",
                serde_json::Value::from(before.data_class.as_str()),
                serde_json::Value::from(after.data_class.as_str()),
            );
        }
        if before.lifecycle != after.lifecycle {
            push(
                "lifecycle",
                serde_json::Value::from(before.lifecycle.as_str()),
                serde_json::Value::from(after.lifecycle.as_str()),
            );
        }
        if before.exposure_score != after.exposure_score {
            push(
                "exposure_score",
                serde_json::Value::from(before.exposure_score),
                serde_json::Value::from(after.exposure_score),
            );
        }
        if before.dependencies != after.dependencies {
            push(
                "dependencies",
                serde_json::to_value(&before.dependencies).unwrap_or(serde_json::Value::Null),
                serde_json::to_value(&after.dependencies).unwrap_or(serde_json::Value::Null),
            );
        }
        if before.attributes.get("content_sha256") != after.attributes.get("content_sha256") {
            push(
                "content_sha256",
                before.attributes.get("content_sha256").cloned().unwrap_or_default(),
                after.attributes.get("content_sha256").cloned().unwrap_or_default(),
            );
        }
        package::differences(before, after, &mut push);
        out
    }

    /// 内容哈希比较（快速判断"是否变化"，用于决定是否需要做字段级 diff）。
    #[must_use]
    pub fn content_hash(asset: &Asset) -> String {
        asset_content_hash(
            asset.kind,
            asset.endpoint.as_deref(),
            asset.protocol,
            asset.version.as_deref(),
            asset.vendor.as_deref(),
            asset.data_class,
            asset.lifecycle,
            &asset.dependencies,
            asset.discovery_source,
        )
    }

    /// 快速差分：只对比内容哈希（`asset_id → hash`），返回 `(新增, 消失, 变更)` 三组 id。
    #[must_use]
    pub fn hash_diff(before: &BTreeMap<Id, String>, after: &BTreeMap<Id, String>) -> (Vec<Id>, Vec<Id>, Vec<Id>) {
        let added: Vec<Id> = after.keys().filter(|k| !before.contains_key(*k)).copied().collect();
        let removed: Vec<Id> = before.keys().filter(|k| !after.contains_key(*k)).copied().collect();
        let modified: Vec<Id> =
            after.iter().filter(|(k, v)| before.get(*k).is_some_and(|old| old != *v)).map(|(k, _)| *k).collect();
        (added, removed, modified)
    }

    /// 对变更列表做风险定级汇总。
    #[must_use]
    pub fn summarize(changes: &[AssetChange]) -> DriftSummary {
        let risky: Vec<&AssetChange> = changes.iter().filter(|c| c.risky).collect();
        let by_kind = |k: ChangeKind| changes.iter().filter(|c| c.change_kind == k).count();
        let severity = if risky.iter().any(|c| matches!(c.kind, AssetKind::McpServer | AssetKind::Agent)) {
            Severity::High
        } else if risky.is_empty() {
            Severity::Info
        } else {
            Severity::Medium
        };
        DriftSummary {
            total: changes.len(),
            added: by_kind(ChangeKind::Added),
            removed: by_kind(ChangeKind::Removed),
            modified: by_kind(ChangeKind::Modified),
            risky: risky.len(),
            severity,
            risky_assets: risky.iter().map(|c| (c.asset_id, c.kind, c.risk_note.clone())).collect(),
        }
    }
}

impl DriftSummary {
    /// 是否需要人工确认（控制台红点）。
    #[must_use]
    pub const fn needs_attention(&self) -> bool {
        self.risky > 0
    }
}

impl DriftReport {
    /// 由变更列表构造报告。
    #[must_use]
    pub fn new(
        tenant_id: agf_core::ids::TenantId,
        baseline_date: impl Into<String>,
        current_date: impl Into<String>,
        changes: Vec<AssetChange>,
    ) -> Self {
        let summary = DriftScanner::summarize(&changes);
        Self {
            tenant_id,
            baseline_date: baseline_date.into(),
            current_date: current_date.into(),
            changes,
            summary,
            generated_at: Timestamp::now(),
        }
    }

    /// 渲染为 Markdown（日报邮件/控制台预览）。
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!("# 资产漂移报告（{} → {}）\n\n", self.baseline_date, self.current_date));
        s.push_str(&format!(
            "- 变更总数：{}（新增 {} / 消失 {} / 变更 {}）\n- 高风险项：{}\n- 综合等级：{}\n\n",
            self.summary.total,
            self.summary.added,
            self.summary.removed,
            self.summary.modified,
            self.summary.risky,
            self.summary.severity
        ));
        if self.summary.needs_attention() {
            s.push_str("## 需人工确认\n\n");
            for (id, kind, note) in &self.summary.risky_assets {
                s.push_str(&format!(
                    "- [{}] `{}` — {}\n",
                    kind.as_str(),
                    id,
                    note.clone().unwrap_or_else(|| "无说明".to_string())
                ));
            }
            s.push('\n');
        }
        s.push_str("## 明细\n\n| 类型 | 资产 | 字段 | 高风险 |\n|---|---|---|---|\n");
        for c in &self.changes {
            s.push_str(&format!(
                "| {} | `{}` | {} | {} |\n",
                c.change_kind.as_str(),
                c.asset_id,
                c.field.clone().unwrap_or_else(|| "-".to_string()),
                if c.risky { "是" } else { "否" }
            ));
        }
        s
    }
}
