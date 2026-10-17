//! A successful campaign write is committed before returning to the caller.
use super::campaign_sql::{missing, read, save};
use super::*;
use agf_core::{
    alert::Alert,
    audit::{AuditAction, AuditOutcome},
    enums::AssetKind,
    redteam::CampaignState,
};
use agf_storage::{AlertRepo, AssetRepo, AuditRepo, FindingRepo};

impl ApiStore {
    /// Import one trusted, already completed simulator fixture into SQL without replacing
    /// an existing campaign. Normal user submissions must use `campaign_submit_durable`.
    pub(crate) async fn campaign_seed_completed_durable(&self, record: &CampaignRecord) -> DomainResult<bool> {
        validate(record)?;
        let Some(db) = &self.database else { return Ok(false) };
        let tenant = record.campaign.tenant_id;
        let mut tx = db.db().begin_tenant(tenant).await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!("redteam-submit:{}:{}", tenant, record.campaign.id))
            .execute(&mut *tx)
            .await
            .map_err(|e| agf_storage::map_sqlx_err("campaign_seed_lock", &e))?;
        if let Some(existing) = read(&mut tx, record.campaign.id).await? {
            if existing.campaign.name != record.campaign.name
                || existing.campaign.launched_by != record.campaign.launched_by
            {
                return Err(DomainError::Conflict("演示战役 ID 与现有战役冲突".into()));
            }
            tx.commit().await?;
            return Ok(false);
        }
        save(&mut tx, record, true).await?;
        // INSERT fills the JSON aggregate; UPDATE also fills the summary counters.
        save(&mut tx, record, false).await?;
        tx.commit().await?;
        Ok(true)
    }

    pub async fn campaign_insert_durable(&self, record: &CampaignRecord) -> DomainResult<()> {
        let (_, inserted) = self.campaign_submit_durable(record).await?;
        if !inserted {
            return Err(DomainError::Conflict("Campaign ID already exists".into()));
        }
        Ok(())
    }

    /// Serializes first submission and all retries, including across server instances.
    pub async fn campaign_submit_durable(&self, record: &CampaignRecord) -> DomainResult<(CampaignRecord, bool)> {
        if record.campaign.state != CampaignState::Queued
            || record.terminal()
            || !record.results.is_empty()
            || record.report.is_some()
        {
            return Err(DomainError::Validation("New campaign must be queued without results".into()));
        }
        if let Some(db) = &self.database {
            let mut tx = db.db().begin_tenant(record.campaign.tenant_id).await?;
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
                .bind(format!("redteam-submit:{}:{}", record.campaign.tenant_id, record.campaign.id))
                .execute(&mut *tx)
                .await
                .map_err(|e| agf_storage::map_sqlx_err("campaign_submit_lock", &e))?;
            if let Some(existing) = read(&mut tx, record.campaign.id).await? {
                same_submission(&existing, record)?;
                tx.commit().await?;
                return Ok((existing, false));
            }
            save(&mut tx, record, true).await?;
            tx.commit().await?;
        } else {
            let mut mem = self.lock()?;
            let key = (record.campaign.tenant_id, record.campaign.id);
            if let Some(existing) = mem.campaign_records.get(&key) {
                same_submission(existing, record)?;
                return Ok((existing.clone(), false));
            }
            if mem.campaigns.contains_key(&key) {
                return Err(DomainError::Conflict("Campaign ID already exists".into()));
            }
            mem.campaign_records.insert(key, record.clone());
        }
        Ok((record.clone(), true))
    }

    pub async fn campaign_get_durable(&self, tenant: TenantId, id: Id) -> DomainResult<Option<CampaignRecord>> {
        if let Some(db) = &self.database {
            let mut tx = db.db().begin_tenant(tenant).await?;
            let mut record = read(&mut tx, id).await?;
            if let Some(record) = &mut record {
                let previous = record.campaign.state;
                record.expire();
                if previous != record.campaign.state {
                    save(&mut tx, record, false).await?;
                }
            }
            tx.commit().await?;
            Ok(record)
        } else {
            let mut mem = self.lock()?;
            if let Some(record) = mem.campaign_records.get_mut(&(tenant, id)) {
                record.expire();
                return Ok(Some(record.clone()));
            }
            Ok(mem.campaigns.get(&(tenant, id)).map(|c| {
                CampaignRecord::legacy(
                    c.clone(),
                    mem.campaign_results.get(&(tenant, id)).cloned().unwrap_or_default(),
                    mem.campaign_reports.get(&(tenant, id)).cloned(),
                )
            }))
        }
    }

    pub async fn campaign_transition_durable(
        &self,
        tenant: TenantId,
        id: Id,
        next: CampaignState,
        error: Option<String>,
    ) -> DomainResult<CampaignRecord> {
        if let Some(db) = &self.database {
            let mut tx = db.db().begin_tenant(tenant).await?;
            let mut record = read(&mut tx, id).await?.ok_or_else(|| missing(id))?;
            transition(&mut record, next, error)?;
            save(&mut tx, &record, false).await?;
            tx.commit().await?;
            Ok(record)
        } else {
            let mut mem = self.lock()?;
            let record = mem.campaign_records.get_mut(&(tenant, id)).ok_or_else(|| missing(id))?;
            transition(record, next, error)?;
            Ok(record.clone())
        }
    }

    /// Commit an operator cancellation and its success audit in one tenant transaction.
    /// Repeated cancellation or an already terminal campaign produces no duplicate audit.
    pub async fn campaign_cancel_audited(
        &self,
        tenant: TenantId,
        id: Id,
        mut audit: AuditLog,
    ) -> DomainResult<CampaignRecord> {
        let expected_id = id.to_string();
        if audit.tenant_id != tenant
            || audit.action != AuditAction::Update
            || audit.outcome != AuditOutcome::Success
            || audit.target.kind != "redteam-campaign"
            || audit.target.id.as_deref() != Some(expected_id.as_str())
        {
            return Err(DomainError::Validation("Cancellation audit does not match the campaign".into()));
        }
        if let Some(db) = &self.database {
            let mut tx = db.db().begin_tenant(tenant).await?;
            let mut record = read(&mut tx, id).await?.ok_or_else(|| missing(id))?;
            let previous = record.campaign.state;
            transition(&mut record, CampaignState::Cancelled, None)?;
            let cancelled = previous != CampaignState::Cancelled && record.campaign.state == CampaignState::Cancelled;
            let sealed = if cancelled { Some(AuditRepo::append_log(&mut tx, audit).await?) } else { None };
            if previous != record.campaign.state {
                save(&mut tx, &record, false).await?;
            }
            tx.commit().await?;
            if let Some(sealed) = sealed {
                if let Err(error) = self.hydrate_audit(&sealed) {
                    tracing::warn!(campaign_id=%id,%error,"Committed campaign cancellation audit projection failed");
                }
            }
            Ok(record)
        } else {
            let mut mem = self.lock()?;
            let record = mem.campaign_records.get_mut(&(tenant, id)).ok_or_else(|| missing(id))?;
            let previous = record.campaign.state;
            transition(record, CampaignState::Cancelled, None)?;
            let cancelled = previous != CampaignState::Cancelled && record.campaign.state == CampaignState::Cancelled;
            let result = record.clone();
            if cancelled {
                let chain = mem.audits.entry(tenant).or_default();
                audit.sequence = chain.last().map_or(1, |last| last.sequence + 1);
                audit.prev_hash = chain.last().map_or_else(|| GENESIS_HASH.to_string(), |last| last.entry_hash.clone());
                audit.seal();
                chain.push(audit);
            }
            Ok(result)
        }
    }

    /// The aggregate's inputs cannot change. Cancellation/deadline wins before any evidence becomes visible.
    pub async fn campaign_complete_durable(&self, completed: &CampaignRecord) -> DomainResult<CampaignRecord> {
        let tenant = completed.campaign.tenant_id;
        let id = completed.campaign.id;
        let mut completed = completed.clone();
        let findings = super::campaign_findings::prepare(&mut completed)?;
        let alerts = super::campaign_alerts::prepare(id, &findings)?;
        validate(&completed)?;
        let expected_kind = if completed.execution_mode.as_deref() == Some("agent-http") {
            AssetKind::Agent
        } else {
            AssetKind::McpServer
        };
        if let Some(db) = &self.database {
            let mut tx = db.db().begin_tenant(tenant).await?;
            let mut published_alerts = Vec::new();
            let mut record = read(&mut tx, id).await?.ok_or_else(|| missing(id))?;
            let was_terminal = record.terminal();
            finish(&mut record, &completed)?;
            let published = !was_terminal && record.campaign.state == CampaignState::Completed;
            if published {
                for finding in &findings {
                    let asset_id = finding
                        .asset_id
                        .ok_or_else(|| DomainError::Validation("Red-team finding lacks an asset".into()))?;
                    let asset = AssetRepo::get(&mut tx, asset_id).await?;
                    if !asset.is_some_and(|asset| asset.kind == expected_kind && asset.is_live()) {
                        return Err(DomainError::Conflict("Red-team asset changed before evidence commit".into()));
                    }
                    FindingRepo::insert(&mut tx, finding).await?;
                }
                for alert in &alerts {
                    let (alert_id, _) = AlertRepo::upsert_dedup(
                        &mut tx,
                        &alert.dedup_key,
                        &alert.title,
                        &alert.description,
                        alert.severity,
                        Some(alert.domain),
                        &[alert.asset_id],
                        &alert.finding_ids,
                        Some(Timestamp::now().offset_secs(Alert::sla_secs(alert.severity))),
                    )
                    .await?;
                    let saved = AlertRepo::get(&mut tx, alert_id)
                        .await?
                        .ok_or_else(|| DomainError::Internal("Red-team alert is missing".into()))?;
                    published_alerts.push(saved);
                }
            }
            save(&mut tx, &record, false).await?;
            tx.commit().await?;
            if published {
                for finding in &findings {
                    if let Err(error) = self.hydrate_finding(finding) {
                        tracing::warn!(finding_id=%finding.id,error=%error,"Committed finding cache refresh failed");
                    }
                }
                for alert in &published_alerts {
                    if let Err(error) = self.hydrate_alert(alert) {
                        tracing::warn!(alert_id=%alert.id,error=%error,"Committed red-team alert cache refresh failed");
                    }
                }
            }
            Ok(record)
        } else {
            let mut mem = self.lock()?;
            let current = mem.campaign_records.get(&(tenant, id)).cloned().ok_or_else(|| missing(id))?;
            let mut next = current.clone();
            finish(&mut next, &completed)?;
            if !current.terminal() && next.campaign.state == CampaignState::Completed {
                for finding in &findings {
                    let asset_id = finding
                        .asset_id
                        .ok_or_else(|| DomainError::Validation("Red-team finding lacks an asset".into()))?;
                    let asset = mem.assets.get(&(tenant, asset_id));
                    if !asset.is_some_and(|asset| asset.kind == expected_kind && asset.is_live()) {
                        return Err(DomainError::Conflict("Red-team asset changed before evidence commit".into()));
                    }
                    if mem.findings.contains_key(&(tenant, finding.id)) {
                        return Err(DomainError::Conflict("Red-team finding ID already exists".into()));
                    }
                }
                for finding in findings {
                    mem.findings.insert((tenant, finding.id), finding);
                }
                for alert in alerts {
                    super::campaign_alerts::insert_memory(&mut mem, tenant, alert);
                }
            }
            mem.campaign_records.insert((tenant, id), next.clone());
            Ok(next)
        }
    }
}

fn same_submission(existing: &CampaignRecord, input: &CampaignRecord) -> DomainResult<()> {
    if input.request_fingerprint.is_none()
        || existing.request_fingerprint != input.request_fingerprint
        || existing.campaign.launched_by != input.campaign.launched_by
    {
        return Err(DomainError::Conflict("Campaign ID already belongs to a different request".into()));
    }
    Ok(())
}

fn transition(record: &mut CampaignRecord, next: CampaignState, error: Option<String>) -> DomainResult<()> {
    record.expire();
    if record.terminal() {
        return Ok(());
    }
    match (record.campaign.state, next) {
        (CampaignState::Queued, CampaignState::Running) => record.campaign.started_at = Some(Timestamp::now()),
        (_, CampaignState::Failed | CampaignState::Cancelled) => {
            record.campaign.finished_at = Some(Timestamp::now());
            record.error = error;
        }
        _ => return Err(DomainError::Conflict("Invalid campaign transition".into())),
    }
    record.campaign.state = next;
    Ok(())
}

fn validate(record: &CampaignRecord) -> DomainResult<()> {
    let c = &record.campaign;
    let identity = (c.tenant_id, c.id);
    let Some(report) = &record.report else {
        return Err(DomainError::Validation("Completed campaign requires a report".into()));
    };
    let ids: std::collections::BTreeSet<_> = record.results.iter().map(|r| r.id).collect();
    let keys: std::collections::BTreeSet<_> = record.results.iter().map(|r| r.case_key.as_str()).collect();
    if c.state != CampaignState::Completed
        || c.total_cases as usize != record.cases.len()
        || c.executed_cases as usize != record.results.len()
        || c.executed_cases != c.total_cases
        || c.succeeded_cases as usize != record.results.iter().filter(|r| r.succeeded).count()
        || ids.len() != record.results.len()
        || keys.len() != record.results.len()
        || record.results.iter().any(|r| (r.tenant_id, r.campaign_id) != identity || !c.case_keys.contains(&r.case_key))
        || (report.tenant_id, report.campaign_id) != identity
        || report.executed != c.executed_cases
        || report.succeeded != c.succeeded_cases
        || report.total_cases != c.total_cases
    {
        return Err(DomainError::Validation("Campaign evidence does not match its task".into()));
    }
    Ok(())
}

fn finish(record: &mut CampaignRecord, completed: &CampaignRecord) -> DomainResult<()> {
    record.expire();
    if record.terminal() {
        return Ok(());
    }
    if record.campaign.state != CampaignState::Running {
        return Err(DomainError::Conflict("Campaign has not started".into()));
    }
    let mut expected = record.clone();
    expected.campaign.state = completed.campaign.state;
    expected.campaign.executed_cases = completed.campaign.executed_cases;
    expected.campaign.succeeded_cases = completed.campaign.succeeded_cases;
    expected.campaign.finished_at = completed.campaign.finished_at;
    expected.results.clone_from(&completed.results);
    expected.report.clone_from(&completed.report);
    expected.comparison.clone_from(&completed.comparison);
    if serde_json::to_value(&expected)? != serde_json::to_value(completed)? {
        return Err(DomainError::Conflict("Campaign inputs are immutable".into()));
    }
    *record = expected;
    Ok(())
}
