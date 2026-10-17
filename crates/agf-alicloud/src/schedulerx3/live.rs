//! Actual SchedulerX3 API contract, bounded pagination and explicit job publication.
use super::*;
use crate::openapi::contract;
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub(super) fn job_id(raw: &str) -> DomainResult<i64> {
    raw.parse::<i64>()
        .ok()
        .filter(|id| *id > 0)
        .ok_or_else(|| DomainError::Validation("SchedulerX3 JobId 必须为正整数".into()))
}
fn number(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| value.as_str()?.parse().ok())
}
fn checked(response: &Value) -> DomainResult<()> {
    if response.get("Success").and_then(Value::as_bool) != Some(true) {
        return Err(DomainError::Parse("SchedulerX3 响应未明确确认 Success=true".into()));
    }
    Ok(())
}

impl SchedulerX3Adapter {
    fn scope(&self, app: &str) -> DomainResult<Value> {
        if self.cluster_id.trim().is_empty() || app.trim().is_empty() {
            return Err(DomainError::Config("SchedulerX3 需要 cluster_id 和 app_name".into()));
        }
        if app != self.namespace {
            return Err(DomainError::Validation("任务应用名称与适配器配置不一致".into()));
        }
        Ok(json!({"ClusterId":self.cluster_id,"AppName":app}))
    }
    async fn pages(&self, action: &str, mut input: Value, identity: &str) -> DomainResult<Vec<Value>> {
        let api = contract(AliCloudService::SchedulerX3, action)?;
        let mut rows = Vec::new();
        let mut seen = BTreeSet::new();
        for page in 1..=20 {
            input["PageNum"] = json!(page);
            input["PageSize"] = json!(100);
            let response = api.call(self.live_client()?, &input).await?;
            checked(&response.body)?;
            let data = &response.body["Data"];
            let items = data["Records"]
                .as_array()
                .ok_or_else(|| DomainError::Parse(format!("{action} 缺少 Data.Records 数组")))?;
            for item in items {
                let id = item[identity]
                    .as_str()
                    .map(str::to_string)
                    .or_else(|| number(&item[identity]).map(|id| id.to_string()))
                    .filter(|id| !id.is_empty())
                    .ok_or_else(|| DomainError::Parse(format!("{action} 缺少 {identity}")))?;
                if !seen.insert(id) {
                    return Err(DomainError::Parse(format!("{action} 返回重复记录，分页未完成")));
                }
                if item.get("AppName").and_then(Value::as_str).is_some_and(|app| app != self.namespace) {
                    return Err(DomainError::Parse("SchedulerX3 返回了其他应用的数据".into()));
                }
                rows.push(item.clone());
            }
            let total = number(&data["Total"]);
            if total.is_some_and(|total| rows.len() as u64 > total) {
                return Err(DomainError::Parse("SchedulerX3 分页记录数与 Total 不一致".into()));
            }
            if total.is_some_and(|total| rows.len() as u64 >= total) || (total.is_none() && items.len() < 100) {
                return Ok(rows);
            }
            if items.is_empty() {
                return Err(DomainError::Parse("SchedulerX3 分页提前结束".into()));
            }
        }
        Err(DomainError::Validation("SchedulerX3 查询超过 20 页，请缩小应用或任务范围".into()))
    }
    fn scoped_id(&self, id: &str) -> Id {
        deterministic_id(
            NS_SCHEDULE,
            &format!(
                "{}:{}:{:?}:{}:{}:{id}",
                self.core.tenant_id, self.core.account_id, self.core.region, self.cluster_id, self.namespace
            ),
        )
    }
    fn parse_job(&self, row: Value) -> DomainResult<SchedulerX3Job> {
        let cloud_id = number(&row["JobId"])
            .filter(|id| *id > 0)
            .ok_or_else(|| DomainError::Parse("SchedulerX3 JobId 无效".into()))?
            .to_string();
        let name = row["Name"]
            .as_str()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| DomainError::Parse("SchedulerX3 缺少任务名称".into()))?;
        let allowed: BTreeMap<_, _> = contract(AliCloudService::SchedulerX3, "CreateJob")?
            .parameters
            .into_iter()
            .chain(contract(AliCloudService::SchedulerX3, "UpdateJob")?.parameters)
            .map(|p| (p.name, p.schema))
            .collect();
        let mut parameters: BTreeMap<_, _> = row
            .as_object()
            .ok_or_else(|| DomainError::Parse("任务须为对象".into()))?
            .iter()
            .filter(|(key, value)| {
                allowed.contains_key(*key)
                    && !value.is_null()
                    && !matches!(key.as_str(), "ClusterId" | "AppName" | "JobId")
            })
            .map(|(key, value)| (key.clone(), super::registration::normalize(value, &allowed[key])))
            .collect();
        // Public list response spells this field Xattrs; Create/Update spell it XAttrs.
        if let Some(value) = row.get("Xattrs") {
            parameters.insert("XAttrs".into(), value.clone());
        }
        if !parameters.contains_key("Timezone") {
            if let Some(value) = row.get("TimeZone").filter(|value| !value.is_null()) {
                parameters.insert("Timezone".into(), value.clone());
            }
        }
        Ok(SchedulerX3Job {
            id: self.scoped_id(&cloud_id),
            cloud_parameters: parameters,
            name: name.into(),
            job_kind: normalize_job_kind(name),
            cron: row["TimeExpression"].as_str().unwrap_or_default().into(),
            shard_count: u32::from(number(&row["RouteStrategy"]) != Some(8)),
            max_retries: number(&row["MaxAttempt"]).and_then(|v| v.try_into().ok()).unwrap_or(0),
            depends_on: Vec::new(),
            enabled: number(&row["Status"]) == Some(1),
            backend: ScheduleBackend::SchedulerX3,
            cloud_job_id: Some(cloud_id),
            handler: row["JobHandler"].as_str().unwrap_or_default().into(),
        })
    }
}

#[async_trait]
impl SchedulerX3Api for SchedulerX3Adapter {
    async fn pull_jobs(&self) -> DomainResult<Vec<SchedulerX3Job>> {
        if self.core.is_mock() {
            return Ok(mock::schedulerx3_jobs(self.core.tenant_id));
        }
        let rows = self.pages("ListJobs", self.scope(&self.namespace)?, "JobId").await?;
        let mut jobs: Vec<_> = rows.into_iter().map(|row| self.parse_job(row)).collect::<DomainResult<_>>()?;
        let links: Vec<_> = jobs
            .iter()
            .flat_map(|parent| {
                parent
                    .cloud_parameters
                    .get("ChildJobId")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .split(',')
                    .filter_map(|id| job_id(id.trim()).ok())
                    .map(|id| (parent.id, self.scoped_id(&id.to_string())))
                    .collect::<Vec<_>>()
            })
            .collect();
        for (parent, child) in links {
            if let Some(job) = jobs.iter_mut().find(|job| job.id == child) {
                job.depends_on.push(parent);
            }
        }
        Ok(jobs)
    }

    async fn create_job(&self, job: &SchedulerX3Job, app: &str) -> DomainResult<String> {
        if self.core.is_mock() {
            return Ok(format!("cloud-job-mock-{}", job.job_kind));
        }
        self.scope(app)?;
        let action = if job.cloud_job_id.is_some() { "UpdateJob" } else { "CreateJob" };
        let body = job.parameters(&self.cluster_id, app)?;
        let response = contract(AliCloudService::SchedulerX3, action)?.call(self.live_client()?, &body).await?;
        checked(&response.body)?;
        let id = if let Some(id) = &job.cloud_job_id {
            id.clone()
        } else {
            number(&response.body["Data"]["JobId"])
                .filter(|id| *id > 0)
                .ok_or_else(|| DomainError::Parse("CreateJob 响应缺少 Data.JobId；请查询云端确认，勿盲目重建".into()))?
                .to_string()
        };
        if job.cloud_job_id.is_some() {
            let action = if job.enabled { "OperateEnableJobs" } else { "OperateDisableJobs" };
            let mut input = self.scope(app)?;
            input["JobIds"] = json!([job_id(&id)?]);
            let response = contract(AliCloudService::SchedulerX3, action)?.call(self.live_client()?, &input).await?;
            checked(&response.body)?;
        }
        Ok(id)
    }

    async fn delete_job(&self, id: &str, app: &str) -> DomainResult<()> {
        if self.core.is_mock() {
            return Ok(());
        }
        let mut input = self.scope(app)?;
        input["JobIds"] = json!([job_id(id)?]);
        let response = contract(AliCloudService::SchedulerX3, "DeleteJobs")?.call(self.live_client()?, &input).await?;
        checked(&response.body)
    }

    async fn pull_executions(&self, id: Option<&str>) -> DomainResult<Vec<SchedulerX3Execution>> {
        if self.core.is_mock() {
            let mut rows = mock::schedulerx3_executions();
            if let Some(id) = id {
                rows.retain(|row| row.job_id == id);
            }
            return Ok(rows);
        }
        let mut input = self.scope(&self.namespace)?;
        if let Some(id) = id {
            input["JobId"] = json!(job_id(id)?);
        }
        self.pages("ListJobExecutions", input, "JobExecutionId")
            .await?
            .into_iter()
            .map(|row| {
                let execution_job = number(&row["JobId"])
                    .filter(|id| *id > 0)
                    .ok_or_else(|| DomainError::Parse("执行记录缺少 JobId".into()))?
                    .to_string();
                if id.is_some_and(|requested| requested != execution_job) {
                    return Err(DomainError::Parse("SchedulerX3 返回了其他任务的执行记录".into()));
                }
                let raw = row["ScheduleTime"].as_str().map(str::to_string);
                let at = raw
                    .as_deref()
                    .and_then(|raw| chrono::DateTime::parse_from_rfc3339(raw).ok())
                    .and_then(|at| Timestamp::from_unix_millis(at.timestamp_millis()).ok());
                let status = match number(&row["Status"]) {
                    Some(0) => "UNKNOWN",
                    Some(1) => "WAITING",
                    Some(2) => "READY",
                    Some(3) => "RUNNING",
                    Some(4) => "SUCCESS",
                    Some(5) => "FAILED",
                    Some(6) => "PAUSED",
                    Some(7) => "SUBMITTED",
                    Some(8) => "REJECTED",
                    Some(9) => "ACCEPTED",
                    Some(10) => "PARTIAL_FAILED",
                    Some(11) => "SKIPPED",
                    Some(12) => "REMOVED",
                    _ => "UNKNOWN",
                };
                Ok(SchedulerX3Execution {
                    job_id: execution_job,
                    execution_id: row["JobExecutionId"].as_str().unwrap_or_default().into(),
                    shard_index: None,
                    status: status.into(),
                    at,
                    scheduled_at_raw: raw,
                    duration_ms: None,
                    duration_native: number(&row["Duration"]),
                    result: row["Result"].as_str().unwrap_or_default().into(),
                })
            })
            .collect()
    }

    async fn register_platform_jobs(&self, tenant: TenantId) -> DomainResult<JobRegistrationReport> {
        if tenant != self.core.tenant_id {
            return Err(DomainError::Validation("任务租户与适配器不一致".into()));
        }
        let jobs = if self.core.is_mock() {
            SchedulerX3Job::platform_defaults(tenant)
        } else {
            self.prepare_registration(tenant).await?
        };
        let mut report = JobRegistrationReport::default();
        for job in jobs {
            match self.create_job(&job, &self.namespace).await {
                Ok(id) => {
                    if job.cloud_job_id.is_some() {
                        report.updated += 1;
                    } else {
                        report.created += 1;
                    }
                    report.cloud_job_ids.insert(job.job_kind, id);
                }
                Err(error) => {
                    report.failed += 1;
                    report.errors.insert(job.job_kind, error.to_string());
                }
            }
        }
        Ok(report)
    }
}

impl std::fmt::Debug for SchedulerX3Job {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SchedulerX3Job")
            .field("id", &self.id)
            .field("job_kind", &self.job_kind)
            .field("cloud_job_id", &self.cloud_job_id)
            .finish_non_exhaustive()
    }
}
