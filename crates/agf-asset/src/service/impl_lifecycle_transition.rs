//! 由 `service.rs` 拆分：`AssetService`/`IngestStats`/`InventoryStats`/`LifecycleTransition` 的实现（纯搬移，逻辑不变）。
use super::*;

impl LifecycleTransition {
    /// 构造。
    #[must_use]
    pub fn new(asset_id: Id, to: LifecycleState, actor: impl Into<String>, note: impl Into<String>) -> Self {
        Self { asset_id, to, actor: actor.into(), note: note.into(), data_class: None, owner: None, department: None }
    }

    /// 流转到生产时的必填校验。
    ///
    /// # Errors
    /// 缺少归属人或数据分级时返回校验错误（防止"没评审就上线"）。
    pub fn validate_for_production(&self) -> DomainResult<()> {
        if self.to != LifecycleState::Production {
            return Ok(());
        }
        if self.owner.as_deref().unwrap_or("").trim().is_empty() {
            return Err(DomainError::Validation("流转到生产必须指定归属人".to_string()));
        }
        if self.data_class.is_none() {
            return Err(DomainError::Validation("流转到生产必须完成数据分级评审".to_string()));
        }
        Ok(())
    }
}

impl IngestStats {
    /// 是否有需要人工确认的高风险变更。
    #[must_use]
    pub const fn needs_attention(&self) -> bool {
        self.risky_changes > 0
    }
}

impl InventoryStats {
    /// 由资产列表计算。
    #[must_use]
    pub fn from_assets(assets: &[Asset]) -> Self {
        let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
        let mut by_lifecycle: BTreeMap<String, usize> = BTreeMap::new();
        let mut by_source: BTreeMap<String, usize> = BTreeMap::new();
        let mut exposure_sum: u64 = 0;
        let mut high = 0;
        let mut shadow = 0;
        let mut plaintext = 0;
        for a in assets {
            *by_kind.entry(a.kind.as_str().to_string()).or_insert(0) += 1;
            *by_lifecycle.entry(a.lifecycle.as_str().to_string()).or_insert(0) += 1;
            *by_source.entry(a.discovery_source.as_str().to_string()).or_insert(0) += 1;
            exposure_sum += u64::from(a.exposure_score);
            if a.exposure_score >= 70 {
                high += 1;
            }
            if a.lifecycle == LifecycleState::Trial && a.discovery_source != DiscoverySource::Manual {
                shadow += 1;
            }
            if a.attributes.get("has_plaintext_secret").and_then(serde_json::Value::as_bool) == Some(true)
                || a.attributes.get("hasPlaintextSecret").and_then(serde_json::Value::as_bool) == Some(true)
            {
                plaintext += 1;
            }
        }
        #[allow(clippy::cast_precision_loss)]
        let avg = if assets.is_empty() { 0.0 } else { exposure_sum as f32 / assets.len() as f32 };
        Self {
            total: assets.len(),
            by_kind,
            by_lifecycle,
            by_source,
            shadow,
            high_exposure: high,
            with_plaintext_secret: plaintext,
            avg_exposure: avg,
        }
    }

    /// 总体健康等级。
    #[must_use]
    pub fn severity(&self) -> Severity {
        if self.high_exposure > 5 || self.shadow > 10 {
            Severity::High
        } else if self.high_exposure > 0 || self.shadow > 0 {
            Severity::Medium
        } else {
            Severity::Low
        }
    }
}

impl Default for AssetService {
    fn default() -> Self {
        Self::new()
    }
}

impl AssetService {
    /// 构造。
    #[must_use]
    pub fn new() -> Self {
        Self { drift: DriftScanner::new() }
    }

    /// 发现入库（幂等）。
    ///
    /// 流程：
    /// 1. 对每个发现项生成/复用确定性 id 与指纹；
    /// 2. 指纹命中 → 做字段级 diff，写变更记录；指纹未命中 → 新建（初始为 `trial`）；
    /// 3. 全部写快照（当日基线）。
    ///
    /// # Errors
    /// 存储错误。
    pub async fn ingest<B: AssetBackend>(
        &self,
        backend: &B,
        tenant: TenantId,
        batch: &DiscoveryBatch,
    ) -> DomainResult<IngestStats> {
        let mut stats = IngestStats {
            warnings: batch.warnings.clone(),
            credentials: batch.credentials.len(),
            ..Default::default()
        };
        let today = Date::today().to_iso();
        for discovered in &batch.assets {
            let mut candidate = to_asset(discovered, tenant);
            crate::drift::package::remember_verified(&mut candidate);
            match backend.find_by_fingerprint(tenant, &candidate.fingerprint).await? {
                Some(mut existing) => {
                    // **必须先留快照再改写**：下面会用发现结果刷新 existing 的可观测字段，
                    // 一旦改完再 diff 就永远得到空集（曾经的 bug：变更台账整片缺失）。
                    let before_snapshot = existing.clone();
                    let before_hash = asset_content_hash(
                        existing.kind,
                        existing.endpoint.as_deref(),
                        existing.protocol,
                        existing.version.as_deref(),
                        existing.vendor.as_deref(),
                        existing.data_class,
                        existing.lifecycle,
                        &existing.dependencies,
                        existing.discovery_source,
                    );
                    // 用发现结果刷新"可观测字段"，但保留人工维护的归属/生命周期/分级
                    existing.endpoint = candidate.endpoint.clone().or(existing.endpoint);
                    existing.protocol = candidate.protocol.or(existing.protocol);
                    existing.version = candidate.version.clone().or(existing.version);
                    existing.vendor = candidate.vendor.clone().or(existing.vendor);
                    existing.exposure_score = candidate.exposure_score;
                    existing.last_seen_at = Some(Timestamp::now());
                    existing.updated_at = Timestamp::now();
                    let last_verified = existing.attributes.get("skill_package_last_verified").cloned();
                    let last_received = existing.attributes.get("skill_package_last_verified_at").cloned();
                    existing.attributes.extend(candidate.attributes.clone());
                    if let Some(value) = last_verified {
                        existing.attributes.insert("skill_package_last_verified".into(), value);
                    }
                    if let Some(value) = last_received {
                        existing.attributes.insert("skill_package_last_verified_at".into(), value);
                    }
                    crate::drift::package::remember_verified(&mut existing);
                    existing.owner = existing.owner.or(candidate.owner.clone());
                    existing.department = existing.department.or(candidate.department.clone());

                    let after_hash = asset_content_hash(
                        existing.kind,
                        existing.endpoint.as_deref(),
                        existing.protocol,
                        existing.version.as_deref(),
                        existing.vendor.as_deref(),
                        existing.data_class,
                        existing.lifecycle,
                        &existing.dependencies,
                        existing.discovery_source,
                    );
                    if before_hash == after_hash
                        && before_snapshot.attributes.get("content_sha256") == existing.attributes.get("content_sha256")
                        && before_snapshot.attributes.get("skill_package") == existing.attributes.get("skill_package")
                    {
                        stats.unchanged += 1;
                    } else {
                        // `diff_one(发现前的快照, 合并后的状态)`：得到的每条 AssetChange 都要落库
                        // ——否则"内容变了的既有资产"只在统计里加一次 updated，
                        // 变更台账（控制台"资产变更"页与风险回溯）会整片缺失。
                        let changes = self.drift.diff_one(&before_snapshot, &existing, Timestamp::now());
                        for change in &changes {
                            stats.risky_changes += usize::from(change.risky);
                            backend.record_change(tenant, change).await?;
                            stats.changes += 1;
                        }
                        stats.updated += 1;
                    }
                    backend.upsert(tenant, &existing).await?;
                    backend.snapshot(tenant, &today, &existing).await?;
                }
                None => {
                    backend.upsert(tenant, &candidate).await?;
                    backend.snapshot(tenant, &today, &candidate).await?;
                    let change = Self::change_for_new(&candidate);
                    stats.risky_changes += usize::from(change.risky);
                    backend.record_change(tenant, &change).await?;
                    stats.created += 1;
                    stats.changes += 1;
                    info!(fingerprint = %candidate.fingerprint, kind = candidate.kind.as_str(), "发现新资产");
                }
            }
        }
        Ok(stats)
    }

    /// 生成"新资产"变更记录。
    pub(crate) fn change_for_new(asset: &Asset) -> AssetChange {
        let risky =
            matches!(asset.kind, AssetKind::McpServer | AssetKind::Skill | AssetKind::Agent | AssetKind::ModelEndpoint);
        AssetChange {
            id: Id::new(),
            tenant_id: asset.tenant_id,
            asset_id: asset.id,
            kind: asset.kind,
            change_kind: agf_core::asset::ChangeKind::Added,
            field: None,
            old_value: None,
            new_value: Some(serde_json::to_value(asset).unwrap_or(serde_json::Value::Null)),
            risky,
            risk_note: risky.then(|| {
                format!(
                    "新发现 {} 资产「{}」（来源 {}），需确认是否为授权使用",
                    asset.kind.as_str(),
                    asset.name,
                    asset.discovery_source.as_str()
                )
            }),
            domain: risky.then_some(agf_core::enums::RiskDomain::ToolAbuse),
            detected_at: Timestamp::now(),
        }
    }

    /// 生命周期流转（含状态机校验与审批记录）。
    ///
    /// # Errors
    /// - 资产不存在；
    /// - 非法流转（如 `archived → trial`）；
    /// - 流转到生产但缺少归属人/数据分级。
    pub async fn transition<B: AssetBackend>(
        &self,
        backend: &B,
        tenant: TenantId,
        req: &LifecycleTransition,
    ) -> DomainResult<Asset> {
        req.validate_for_production()?;
        let Some(mut asset) = backend.find(tenant, req.asset_id).await? else {
            return Err(DomainError::NotFound { entity: "asset", id: req.asset_id.to_string() });
        };
        let change = apply_review(&mut asset, req)?;
        backend.upsert(tenant, &asset).await?;
        backend.record_change(tenant, &change).await?;
        Ok(asset)
    }

    /// 盘点统计。
    ///
    /// # Errors
    /// 存储错误。
    pub async fn inventory<B: AssetBackend>(&self, backend: &B, tenant: TenantId) -> DomainResult<InventoryStats> {
        let assets = backend.list_all(tenant).await?;
        Ok(InventoryStats::from_assets(&assets))
    }

    /// 补齐当日首次观测快照并计算即时差异，不重复写入资产变更台账。
    ///
    /// 返回 `(快照数量, 漂移报告)`；`baseline_date` 为 `None` 时自动取昨天。
    ///
    /// # Errors
    /// 存储错误。
    pub async fn snapshot_and_drift<B: AssetBackend>(
        &self,
        backend: &B,
        tenant: TenantId,
        baseline_date: Option<&str>,
    ) -> DomainResult<(usize, DriftReport)> {
        let assets = backend.list_all(tenant).await?;
        let today = Date::today().to_iso();
        let baseline = baseline_date.map(ToString::to_string).unwrap_or_else(|| {
            let yesterday = chrono::Utc::now() - chrono::Duration::days(1);
            yesterday.format("%Y-%m-%d").to_string()
        });
        let date = Date::parse(&baseline).map_err(DomainError::Validation)?;
        if date.to_iso() != baseline || date.as_naive() > Date::today().as_naive() {
            return Err(DomainError::Validation("Baseline must be a YYYY-MM-DD date no later than today".into()));
        }

        for a in &assets {
            backend.snapshot(tenant, &today, a).await?;
        }

        let before_hashes = backend.snapshot_hashes(tenant, &baseline).await?;
        let after_hashes: BTreeMap<Id, String> = assets
            .iter()
            .map(|a| {
                (
                    a.id,
                    asset_content_hash(
                        a.kind,
                        a.endpoint.as_deref(),
                        a.protocol,
                        a.version.as_deref(),
                        a.vendor.as_deref(),
                        a.data_class,
                        a.lifecycle,
                        &a.dependencies,
                        a.discovery_source,
                    ),
                )
            })
            .collect();

        let (added, removed, modified) = DriftScanner::hash_diff(&before_hashes, &after_hashes);
        let mut changes = Vec::new();
        for id in added {
            if let Some(a) = assets.iter().find(|x| x.id == id) {
                changes.push(Self::change_for_new(a));
            }
        }
        for id in removed {
            changes.push(AssetChange {
                id: Id::new(),
                tenant_id: tenant,
                asset_id: id,
                kind: AssetKind::Other,
                change_kind: agf_core::asset::ChangeKind::Removed,
                field: None,
                old_value: None,
                new_value: None,
                risky: true,
                risk_note: Some("资产从当日盘点中消失，需确认是否被删除或采集失效".to_string()),
                domain: None,
                detected_at: Timestamp::now(),
            });
        }
        for id in modified {
            if let Some(a) = assets.iter().find(|x| x.id == id) {
                changes.push(AssetChange {
                    id: Id::new(),
                    tenant_id: tenant,
                    asset_id: id,
                    kind: a.kind,
                    change_kind: agf_core::asset::ChangeKind::Modified,
                    field: Some("content_hash".to_string()),
                    old_value: before_hashes.get(&id).cloned().map(serde_json::Value::from),
                    new_value: after_hashes.get(&id).cloned().map(serde_json::Value::from),
                    risky: true,
                    risk_note: Some(format!("资产「{}」的安全相关属性发生变化", a.name)),
                    domain: Some(agf_core::enums::RiskDomain::ToolAbuse),
                    detected_at: Timestamp::now(),
                });
            }
        }

        // Discovery/lifecycle operations already record changes. A repeated comparison is not a new event.
        for change in &mut changes {
            change.id = agf_core::ids::deterministic_id(
                "legacy-asset-drift",
                &format!(
                    "{tenant}:{baseline}:{today}:{}:{:?}:{:?}",
                    change.asset_id,
                    before_hashes.get(&change.asset_id),
                    after_hashes.get(&change.asset_id),
                ),
            );
        }
        let report = DriftReport::new(tenant, baseline, today, changes);
        if report.summary.needs_attention() {
            warn!(risky = report.summary.risky, "资产漂移检出高风险变更");
        }
        Ok((assets.len(), report))
    }

    /// 找出"应下线但仍在生产"的资产（生命周期未评审的老资产）。
    #[must_use]
    pub fn stale_trial_assets(assets: &[Asset], max_trial_days: i64, now: Timestamp) -> Vec<&Asset> {
        assets
            .iter()
            .filter(|a| a.lifecycle == LifecycleState::Trial)
            .filter(|a| now.since_secs(&a.created_at) > max_trial_days * 86_400)
            .collect()
    }

    /// 找出长时间无心跳的 Agent（终端失联）。
    #[must_use]
    pub fn silent_agents(assets: &[Asset], max_silent_secs: i64, now: Timestamp) -> Vec<&Asset> {
        assets
            .iter()
            .filter(|a| a.kind == AssetKind::Agent)
            .filter(|a| a.last_seen_at.is_none_or(|t| now.since_secs(&t) > max_silent_secs))
            .collect()
    }
}
