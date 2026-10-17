//! Tenant-scoped scan reads and transitions are committed before API success.
use super::scan_records::{expire, missing, read, save, transition};
use super::*;

impl ApiStore {
    pub async fn scan_insert_durable(&self, job: &ScanJob) -> DomainResult<Id> {
        if let Some(db) = &self.database {
            let mut tx = db.db().begin_tenant(job.tenant_id).await?;
            save(&mut tx, job, true).await?;
            tx.commit().await?;
        } else {
            let mut mem = self.lock()?;
            if mem.scans.contains_key(&(job.tenant_id, job.id)) {
                return Err(DomainError::Conflict("Scan ID already exists".into()));
            }
            mem.scans.insert((job.tenant_id, job.id), job.clone());
        }
        Ok(job.id)
    }

    pub async fn scan_get_durable(&self, tenant: TenantId, id: Id) -> DomainResult<Option<ScanJob>> {
        if let Some(db) = &self.database {
            let mut tx = db.db().begin_tenant(tenant).await?;
            let mut job = read(&mut tx, id).await?;
            if let Some(job) = &mut job {
                let previous = job.state;
                expire(job);
                if previous != job.state {
                    save(&mut tx, job, false).await?;
                }
            }
            tx.commit().await?;
            Ok(job)
        } else {
            let mut mem = self.lock()?;
            let job = mem.scans.get_mut(&(tenant, id));
            if let Some(job) = job {
                expire(job);
                Ok(Some(job.clone()))
            } else {
                Ok(None)
            }
        }
    }

    pub async fn scan_list_durable(&self, tenant: TenantId) -> DomainResult<Vec<ScanJob>> {
        if let Some(db) = &self.database {
            let mut tx = db.db().begin_tenant(tenant).await?;
            // Stable locking order matches individual transitions; reject oversized history without truncation.
            let values: Vec<serde_json::Value> = sqlx::query_scalar(
                "SELECT result FROM scan_jobs WHERE deleted_at IS NULL ORDER BY id LIMIT 100001 FOR UPDATE",
            )
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| agf_storage::map_sqlx_err("scan_list", &e))?;
            if values.len() > 100_000 {
                return Err(DomainError::PreconditionFailed("Scan history exceeds 100000 records".into()));
            }
            let mut jobs = Vec::with_capacity(values.len());
            for value in values {
                let mut job: ScanJob = serde_json::from_value(value)?;
                let previous = job.state;
                expire(&mut job);
                if previous != job.state {
                    save(&mut tx, &job, false).await?;
                }
                jobs.push(job);
            }
            tx.commit().await?;
            jobs.sort_by_key(|j| (std::cmp::Reverse(j.created_at), j.id));
            Ok(jobs)
        } else {
            let mut mem = self.lock()?;
            let mut jobs = Vec::new();
            for ((t, _), job) in &mut mem.scans {
                if *t == tenant {
                    expire(job);
                    jobs.push(job.clone());
                }
            }
            jobs.sort_by_key(|j| (std::cmp::Reverse(j.created_at), j.id));
            Ok(jobs)
        }
    }

    pub async fn scan_transition_durable(
        &self,
        tenant: TenantId,
        id: Id,
        next: ScanJobState,
        error: Option<String>,
    ) -> DomainResult<ScanJob> {
        if let Some(db) = &self.database {
            let mut tx = db.db().begin_tenant(tenant).await?;
            let mut job = read(&mut tx, id).await?.ok_or_else(|| missing(id))?;
            transition(&mut job, next, error)?;
            save(&mut tx, &job, false).await?;
            tx.commit().await?;
            Ok(job)
        } else {
            let mut mem = self.lock()?;
            let job = mem.scans.get_mut(&(tenant, id)).ok_or_else(|| missing(id))?;
            transition(job, next, error)?;
            Ok(job.clone())
        }
    }
}
