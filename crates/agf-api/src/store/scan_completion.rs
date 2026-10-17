//! Commit a terminal scan summary and all findings in one transaction.
use super::scan_records::{expire, missing, read, save};
use super::*;
use agf_scan::engine::ScanResult;
use agf_storage::{AssetRepo, FindingRepo};

fn finish(job: &mut ScanJob, result: &ScanResult) {
    job.state = ScanJobState::Succeeded;
    job.progress = 100;
    job.rule_hits.clone_from(&result.rule_hits);
    job.finding_count = result.findings.len();
    job.risk_score = Some(result.risk_score);
    job.finding_ids = result.findings.iter().map(|f| f.id).collect();
    job.llm_mocked = result.judgements.as_ref().is_some_and(|items| !items.is_empty()).then_some(result.llm_mocked);
    job.judgement_count = result.judgements.as_ref().map_or(0, Vec::len);
    job.judgement_failures = result.judgement_failures;
    job.max_severity = result.max_severity.as_str().into();
    job.summary = result.summary_line();
    job.elapsed_ms = result.elapsed_ms;
    job.finished_at = Some(Timestamp::now());
}

impl ApiStore {
    /// Cancelled/expired tasks cannot publish findings; a repeated completion has no side effects.
    pub async fn scan_complete_durable(
        &self,
        tenant: TenantId,
        id: Id,
        assets: &[Id],
        result: &ScanResult,
    ) -> DomainResult<ScanJob> {
        if result.tenant_id != tenant
            || result
                .findings
                .iter()
                .any(|f| f.tenant_id != tenant || f.asset_id.is_some_and(|id| !assets.contains(&id)))
        {
            return Err(DomainError::TenantViolation { tenant: tenant.to_string(), resource: id.to_string() });
        }
        if let Some(db) = &self.database {
            let mut tx = db.db().begin_tenant(tenant).await?;
            let mut job = read(&mut tx, id).await?.ok_or_else(|| missing(id))?;
            expire(&mut job);
            if job.state.is_terminal() {
                save(&mut tx, &job, false).await?;
                tx.commit().await?;
                return Ok(job);
            }
            if job.state != ScanJobState::Running {
                return Err(DomainError::Conflict("Scan has not started".into()));
            }
            for asset_id in assets {
                if AssetRepo::get(&mut tx, *asset_id).await?.is_none() {
                    return Err(DomainError::NotFound { entity: "asset", id: asset_id.to_string() });
                }
            }
            for finding in &result.findings {
                FindingRepo::insert(&mut tx, finding).await?;
            }
            // Storage contention also consumes the execution deadline.
            expire(&mut job);
            if job.state == ScanJobState::Failed {
                return Err(DomainError::PreconditionFailed("Scan expired before commit".into()));
            }
            finish(&mut job, result);
            save(&mut tx, &job, false).await?;
            tx.commit().await?;
            for finding in &result.findings {
                self.hydrate_finding(finding)?;
            }
            Ok(job)
        } else {
            let mut mem = self.lock()?;
            let mut job = mem.scans.get(&(tenant, id)).cloned().ok_or_else(|| missing(id))?;
            expire(&mut job);
            if job.state.is_terminal() {
                mem.scans.insert((tenant, id), job.clone());
                return Ok(job);
            }
            if job.state != ScanJobState::Running {
                return Err(DomainError::Conflict("Scan has not started".into()));
            }
            for asset_id in assets {
                if !mem.assets.contains_key(&(tenant, *asset_id)) {
                    return Err(DomainError::NotFound { entity: "asset", id: asset_id.to_string() });
                }
            }
            let unique: std::collections::BTreeSet<_> = result.findings.iter().map(|f| f.id).collect();
            if unique.len() != result.findings.len()
                || unique.iter().any(|id| mem.findings.contains_key(&(tenant, *id)))
            {
                return Err(DomainError::Conflict("Finding ID already exists".into()));
            }
            for finding in &result.findings {
                mem.findings.insert((tenant, finding.id), finding.clone());
            }
            finish(&mut job, result);
            mem.scans.insert((tenant, id), job.clone());
            Ok(job)
        }
    }
}
