//! 启动水化（包括审计链的本地投影）与平台统计。

use super::*;

impl ApiStore {
    // ------------------------------------------------------------ 持久化

    /// 启动水合：把 PG 读回的资产写进内存缓存（**不**产生写回，因此不经写后队列）。
    ///
    /// # Errors
    /// 锁中毒。
    pub(crate) fn hydrate_asset(&self, asset: &Asset) -> DomainResult<()> {
        self.lock()?.assets.insert((asset.tenant_id, asset.id), asset.clone());
        Ok(())
    }

    /// 启动水合：发现（证据明细不回读，见 [`crate::persistence`] 模块文档）。
    ///
    /// # Errors
    /// 锁中毒。
    pub(crate) fn hydrate_finding(&self, finding: &Finding) -> DomainResult<()> {
        self.lock()?.findings.insert((finding.tenant_id, finding.id), finding.clone());
        Ok(())
    }

    /// 启动水合：策略。
    ///
    /// # Errors
    /// 锁中毒。
    pub(crate) fn hydrate_policy(&self, policy: &Policy) -> DomainResult<()> {
        self.lock()?.policies.insert((policy.tenant_id, policy.id), policy.clone());
        Ok(())
    }

    /// 启动水合：告警。
    ///
    /// # Errors
    /// 锁中毒。
    pub(crate) fn hydrate_alert(&self, alert: &agf_core::alert::Alert) -> DomainResult<()> {
        self.lock()?.alerts.insert((alert.tenant_id, alert.id), alert.clone());
        Ok(())
    }

    /// 启动水合：案件（同时把编号里的年度序号写回 `case_seq`）。
    ///
    /// ## 为什么必须恢复 `case_seq`
    /// 案件编号 `CASE-<年>-<序号>` 由内存计数器生成；不恢复会让重启后新建的第一个案件
    /// 重新从 `0001` 开始，与 PG 里已有编号撞 `ux_cases_code` 唯一索引（写入失败）。
    /// 这里按已有编号取**最大值**，保证新案件编号单调且不冲突。
    ///
    /// # Errors
    /// 锁中毒。
    pub(crate) fn hydrate_case(&self, case: &Case) -> DomainResult<()> {
        let mut mem = self.lock()?;
        if let Some((year, seq)) = parse_case_code(&case.code) {
            let slot = mem.case_seq.entry(year).or_insert(0);
            *slot = (*slot).max(seq);
        }
        mem.cases.insert((case.tenant_id, case.id), case.clone());
        Ok(())
    }

    /// 启动水合：案件时间线事件。
    ///
    /// # Errors
    /// 锁中毒。
    pub(crate) fn hydrate_case_event(&self, event: &CaseEvent) -> DomainResult<()> {
        let mut memory = self.lock()?;
        if !memory.case_events.iter().any(|saved| saved.id == event.id && saved.tenant_id == event.tenant_id) {
            memory.case_events.push(event.clone());
        }
        Ok(())
    }

    /// 启动水合：审计哈希链条目（按 `sequence` 升序回放，链尾校验因此继续成立）。
    ///
    /// # Errors
    /// 锁中毒。
    pub(crate) fn hydrate_audit(&self, entry: &AuditLog) -> DomainResult<()> {
        self.lock()?.audits.entry(entry.tenant_id).or_default().push(entry.clone());
        Ok(())
    }

    /// 启动水合：API Key（**明文从不落库**，这里只回读指纹/前缀/scope/租户/吊销状态）。
    ///
    /// 同 id 覆盖（幂等），使"重启后服务凭据仍可用"而不是被清空。
    ///
    /// # Errors
    /// 锁中毒。
    pub(crate) fn hydrate_api_key(&self, key: &ApiKey) -> DomainResult<()> {
        let mut mem = self.lock()?;
        match mem.api_keys.iter_mut().find(|k| k.id == key.id) {
            Some(slot) => *slot = key.clone(),
            None => mem.api_keys.push(key.clone()),
        }
        Ok(())
    }

    /// 平台统计快照。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn platform_snapshot(&self, tenant: TenantId) -> DomainResult<PlatformSnapshot> {
        let mem = self.lock()?;
        let assets = mem.assets.iter().filter(|((t, _), _)| *t == tenant).count();
        let production =
            mem.assets.iter().filter(|((t, _), a)| *t == tenant && a.lifecycle == LifecycleState::Production).count();
        let shadow_mcps = mem
            .assets
            .iter()
            .filter(|((t, _), a)| {
                *t == tenant
                    && a.kind == agf_core::enums::AssetKind::McpServer
                    && a.lifecycle != LifecycleState::Production
            })
            .count();
        let findings_open = mem
            .findings
            .iter()
            .filter(|((t, _), f)| {
                *t == tenant
                    && !matches!(
                        f.state,
                        agf_core::risk::FindingState::Fixed | agf_core::risk::FindingState::FalsePositive
                    )
            })
            .count();
        let findings_critical = mem
            .findings
            .iter()
            .filter(|((t, _), f)| {
                *t == tenant
                    && f.severity == Severity::Critical
                    && !matches!(
                        f.state,
                        agf_core::risk::FindingState::FalsePositive | agf_core::risk::FindingState::Fixed
                    )
            })
            .count();
        let alerts_active = mem.alerts.iter().filter(|((t, _), a)| *t == tenant && a.is_active()).count();
        let cases_open = mem.cases.iter().filter(|((t, _), c)| *t == tenant && c.state != CaseState::Closed).count();
        let policies = mem.policies.iter().filter(|((t, _), _)| *t == tenant).count();
        let scans = mem.scans.iter().filter(|((t, _), _)| *t == tenant).count();
        Ok(PlatformSnapshot {
            assets: i64::try_from(assets).unwrap_or(i64::MAX),
            assets_production: i64::try_from(production).unwrap_or(i64::MAX),
            shadow_mcps: i64::try_from(shadow_mcps).unwrap_or(i64::MAX),
            findings_open: i64::try_from(findings_open).unwrap_or(i64::MAX),
            findings_critical: i64::try_from(findings_critical).unwrap_or(i64::MAX),
            alerts_active: i64::try_from(alerts_active).unwrap_or(i64::MAX),
            cases_open: i64::try_from(cases_open).unwrap_or(i64::MAX),
            policies: i64::try_from(policies).unwrap_or(i64::MAX),
            scans: i64::try_from(scans).unwrap_or(i64::MAX),
        })
    }
}
