//! 扫描任务、红队战役与报表。

use super::*;

impl ApiStore {
    // ---------------------------------------------------------------- 扫描

    /// 写入扫描任务。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn scan_insert(&self, job: ScanJob) -> DomainResult<Id> {
        self.lock()?.scans.insert((job.tenant_id, job.id), job.clone());
        Ok(job.id)
    }

    /// 读取扫描任务。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn scan_get(&self, tenant: TenantId, id: Id) -> DomainResult<Option<ScanJob>> {
        Ok(self.lock()?.scans.get(&(tenant, id)).cloned())
    }

    /// 列出扫描任务。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn scan_list(&self, tenant: TenantId) -> DomainResult<Vec<ScanJob>> {
        let mut items: Vec<ScanJob> =
            self.lock()?.scans.iter().filter(|((t, _), _)| *t == tenant).map(|(_, j)| j.clone()).collect();
        items.sort_by_key(|c| std::cmp::Reverse(c.created_at));
        Ok(items)
    }

    /// 更新扫描任务。
    ///
    /// # Errors
    /// 不存在或锁中毒。
    pub fn scan_update<F: FnOnce(&mut ScanJob)>(&self, tenant: TenantId, id: Id, f: F) -> DomainResult<ScanJob> {
        let mut mem = self.lock()?;
        let Some(job) = mem.scans.get_mut(&(tenant, id)) else {
            return Err(DomainError::NotFound { entity: "scan-job", id: id.to_string() });
        };
        f(job);
        Ok(job.clone())
    }

    // ---------------------------------------------------------------- 红队

    /// 写入战役。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn campaign_insert(&self, campaign: RedteamCampaign) -> DomainResult<Id> {
        self.lock()?.campaigns.insert((campaign.tenant_id, campaign.id), campaign.clone());
        Ok(campaign.id)
    }

    /// 读取战役。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn campaign_get(&self, tenant: TenantId, id: Id) -> DomainResult<Option<RedteamCampaign>> {
        Ok(self.lock()?.campaigns.get(&(tenant, id)).cloned())
    }

    /// 列出战役。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn campaign_list(&self, tenant: TenantId) -> DomainResult<Vec<RedteamCampaign>> {
        let mut items: Vec<RedteamCampaign> =
            self.lock()?.campaigns.iter().filter(|((t, _), _)| *t == tenant).map(|(_, c)| c.clone()).collect();
        items.sort_by_key(|c| std::cmp::Reverse(c.created_at));
        Ok(items)
    }

    /// 写入战役结果与报告。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn campaign_store_outcome(
        &self,
        tenant: TenantId,
        campaign_id: Id,
        results: Vec<RedteamResult>,
        report: RedteamReport,
    ) -> DomainResult<()> {
        let mut mem = self.lock()?;
        mem.campaign_results.insert((tenant, campaign_id), results);
        mem.campaign_reports.insert((tenant, campaign_id), report);
        Ok(())
    }

    /// 战役结果。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn campaign_results(&self, tenant: TenantId, campaign_id: Id) -> DomainResult<Vec<RedteamResult>> {
        Ok(self.lock()?.campaign_results.get(&(tenant, campaign_id)).cloned().unwrap_or_default())
    }

    /// 战役报告。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn campaign_report(&self, tenant: TenantId, campaign_id: Id) -> DomainResult<Option<RedteamReport>> {
        Ok(self.lock()?.campaign_reports.get(&(tenant, campaign_id)).cloned())
    }

    // ---------------------------------------------------------------- 报表

    /// 写入报表。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn report_insert(&self, report: Report) -> DomainResult<Id> {
        self.lock()?.reports.insert((report.tenant_id, report.id), report.clone());
        Ok(report.id)
    }

    /// 读取报表。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn report_get(&self, tenant: TenantId, id: Id) -> DomainResult<Option<Report>> {
        Ok(self.lock()?.reports.get(&(tenant, id)).cloned())
    }

    /// 列出报表。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn report_list(&self, tenant: TenantId) -> DomainResult<Vec<Report>> {
        let mut items: Vec<Report> =
            self.lock()?.reports.iter().filter(|((t, _), _)| *t == tenant).map(|(_, r)| r.clone()).collect();
        items.sort_by_key(|c| std::cmp::Reverse(c.created_at));
        Ok(items)
    }
}
