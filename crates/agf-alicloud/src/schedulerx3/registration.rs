//! Repeated registration binds only explicit cloud ids or jobs bearing this tenant's ownership label.
use super::*;
use serde_json::{Value, json};

pub(super) fn normalize(value: &Value, schema: &Value) -> Value {
    let value = if matches!(schema["type"].as_str(), Some("object" | "array")) {
        value.as_str().and_then(|raw| serde_json::from_str(raw).ok()).unwrap_or_else(|| value.clone())
    } else {
        value.clone()
    };
    if schema["type"] == "string" && value.is_number() {
        return Value::String(value.to_string());
    }
    if let (Some(object), Some(properties)) = (value.as_object(), schema["properties"].as_object()) {
        return Value::Object(
            object
                .iter()
                .filter_map(|(key, value)| {
                    let (name, field) = properties.iter().find(|(name, _)| name.eq_ignore_ascii_case(key))?;
                    Some((name.clone(), normalize(value, field)))
                })
                .collect(),
        );
    }
    if let (Some(items), Some(item_schema)) = (value.as_array(), schema.get("items")) {
        return Value::Array(items.iter().map(|item| normalize(item, item_schema)).collect());
    }
    value
}

impl SchedulerX3Adapter {
    pub(super) async fn prepare_registration(&self, tenant: TenantId) -> DomainResult<Vec<SchedulerX3Job>> {
        if self.registration_jobs.is_empty() {
            return Err(DomainError::Config("请配置 platform_jobs 及真实执行器参数；不会自动发布演示任务".into()));
        }
        let mut jobs = self.registration_jobs.clone();
        let mut kinds = std::collections::BTreeSet::new();
        for job in &mut jobs {
            if job.job_kind.trim().is_empty() || !kinds.insert(job.job_kind.clone()) {
                return Err(DomainError::Validation("platform_jobs 的 job_kind 必须非空且不重复".into()));
            }
            if !job.depends_on.is_empty() {
                return Err(DomainError::Validation(
                    "云端依赖请填写实际 ChildJobId 或工作流配置，不能发送本地任务 UUID".into(),
                ));
            }
            let raw = job.cloud_parameters.get("Label").and_then(Value::as_str).unwrap_or("{}");
            let mut label: Value = serde_json::from_str(raw)
                .map_err(|_| DomainError::Validation("平台任务 Label 须为 JSON 对象".into()))?;
            let object =
                label.as_object_mut().ok_or_else(|| DomainError::Validation("平台任务 Label 须为 JSON 对象".into()))?;
            object.insert("agf_tenant".into(), json!(tenant));
            object.insert("agf_job_kind".into(), json!(job.job_kind));
            job.cloud_parameters.insert("Label".into(), json!(label.to_string()));
            // Validate every definition before the first network write.
            job.parameters(&self.cluster_id, &self.namespace)?;
        }
        let existing = self.pull_jobs().await?;
        for job in &mut jobs {
            if job.cloud_job_id.is_some() {
                continue;
            }
            let matches: Vec<_> = existing
                .iter()
                .filter(|cloud| {
                    let label = cloud
                        .cloud_parameters
                        .get("Label")
                        .and_then(Value::as_str)
                        .and_then(|raw| serde_json::from_str::<Value>(raw).ok());
                    label.is_some_and(|label| {
                        label["agf_tenant"] == tenant.to_string() && label["agf_job_kind"] == job.job_kind
                    })
                })
                .collect();
            if matches.len() > 1 {
                return Err(DomainError::Conflict(format!(
                    "{} 有多条带相同归属标签的云任务，请先核对重复项",
                    job.job_kind
                )));
            }
            if let Some(cloud) = matches.first() {
                job.cloud_job_id.clone_from(&cloud.cloud_job_id);
            }
        }
        // Binding an existing task changes CreateJob into UpdateJob; preflight that contract too.
        for job in &jobs {
            job.parameters(&self.cluster_id, &self.namespace)?;
        }
        Ok(jobs)
    }
}
