//! Scheduled CMS uses immutable local payloads plus the platform's audited durable queue.
use super::{ApiAuth, Id, PathBuf, TaskOutcome, TaskSnapshot, TenantId, Timestamp, cms_metrics};
use super::{
    cms_queue_client::{BASE, Client},
    cms_queue_delivery,
    cms_queue_outbox::{Outbox, Run},
};
use agf_core::ids::deterministic_id;
use serde_json::{Value, json};

#[derive(Clone)]
pub(crate) struct CmsQueueConfig {
    pub(crate) server: String,
    pub(crate) auth: Option<ApiAuth>,
    pub(crate) tenant: TenantId,
    pub(crate) output: PathBuf,
    pub(crate) confirm_live: bool,
}
pub(super) fn identity(tenant: TenantId, execution: &str, purpose: &str) -> Id {
    deterministic_id("agf.scheduler.cms.v1", &format!("{tenant}:{execution}:{purpose}"))
}
pub(super) fn number(value: &Value, key: &str) -> anyhow::Result<u64> {
    value[key].as_u64().ok_or_else(|| anyhow::anyhow!("CMS 回执缺少有效数值 {key}"))
}
pub(super) fn payload(
    run: &Run,
    config: &CmsQueueConfig,
    execution: &str,
    metrics: &[(String, f64)],
) -> anyhow::Result<Value> {
    if let Some(value) = run.read("payload")? {
        check_payload(run, config, &value)?;
        anyhow::ensure!(value["execution"] == execution, "CMS 周期身份不匹配");
        return Ok(value);
    }
    anyhow::ensure!(
        (1..=20).contains(&metrics.len()) && metrics.iter().all(|(_, v)| v.is_finite()),
        "CMS 指标必须有限且在批量预算内"
    );
    let at = Timestamp::now();
    let items = metrics
        .iter()
        .map(|(name, value)| {
            json!({"kind":"metric","name":name,"value":value,
        "dimensions":{"service":"agf-scheduler"},"at":at})
        })
        .collect::<Vec<_>>();
    let value = json!({"format":"agf-scheduler-cms-outbox-v1","tenant":config.tenant,"execution":execution,
        "platform":config.server.trim_end_matches('/'),"enqueueId":identity(config.tenant,execution,"enqueue"),
        "sendId":identity(config.tenant,execution,"send"),"items":items});
    run.save("payload", &value)?;
    Ok(value)
}
pub(super) fn check_payload(run: &Run, config: &CmsQueueConfig, value: &Value) -> anyhow::Result<()> {
    let execution = value["execution"].as_str().ok_or_else(|| anyhow::anyhow!("CMS 原周期编号缺失"))?;
    anyhow::ensure!(
        value["format"] == "agf-scheduler-cms-outbox-v1"
            && value["tenant"] == config.tenant.to_string()
            && value["platform"] == config.server.trim_end_matches('/')
            && run.id == identity(config.tenant, execution, "run")
            && value["enqueueId"] == identity(config.tenant, execution, "enqueue").to_string()
            && value["sendId"] == identity(config.tenant, execution, "send").to_string()
            && value["items"].as_array().is_some_and(|items| (1..=20).contains(&items.len())),
        "CMS 原 payload 的周期、平台或租户变化；禁止更换意图"
    );
    Ok(())
}
async fn enqueue(client: &Client, run: &Run, intent: &Value) -> anyhow::Result<Value> {
    let id: Id = serde_json::from_value(intent["enqueueId"].clone())?;
    let existing = client.original(id).await?;
    let wire = if let Some(wire) = run.read("enqueue")? {
        wire
    } else {
        anyhow::ensure!(existing.is_none(), "CMS 原请求存在但本地 wire 缺失，停止猜测");
        let state = client.get(BASE).await?;
        let source = &state["source"];
        anyhow::ensure!(source.is_object(), "CMS 当前没有启用的控制台源；payload 已保留本地");
        let seed = source["transportMode"] == "mock"
            && source["region"] == "cn-hangzhou"
            && source["groupId"] == "agf-cms-demo";
        let wire = json!({"request_id":id,"configuration_version":number(source,"configurationVersion")?,
            "expected_generation":number(&state,"generation")?,"items":intent["items"],"initialize_mock_fixture":seed});
        run.save("enqueue", &wire)?;
        wire
    };
    anyhow::ensure!(
        wire["request_id"] == id.to_string() && wire["items"] == intent["items"],
        "CMS 原 enqueue wire 与 payload 不匹配"
    );
    let receipt = match existing {
        Some(value) => value,
        None => client.post(&format!("{BASE}/enqueue"), &wire).await?,
    };
    cms_queue_delivery::check(&receipt, &wire, "enqueue", intent)?;
    Ok(receipt)
}
async fn one(client: &Client, config: &CmsQueueConfig, run: &Run) -> anyhow::Result<TaskOutcome> {
    let intent = run.read("payload")?.ok_or_else(|| anyhow::anyhow!("CMS 原 payload 缺失"))?;
    check_payload(run, config, &intent)?;
    let queued = enqueue(client, run, &intent).await?;
    cms_queue_delivery::deliver(client, config, run, &intent, queued).await
}
async fn drain(config: &CmsQueueConfig, outbox: &Outbox, current: &Run) -> anyhow::Result<TaskOutcome> {
    let Some(auth) = config.auth.as_ref() else {
        return Ok(TaskOutcome::degraded(
            "CMS 离线：无平台服务身份，全部原 payload 已持久保存；未入平台队列、未获 Mock/云接受，providerWriteAttempted=false",
        ));
    };
    let client = Client::new(&config.server, auth, config.tenant)?;
    client.identity().await?;
    let mut runs = vec![outbox.run(current.id)?];
    runs.extend(outbox.pending(current.id)?);
    let mut notes = Vec::new();
    let mut failed = false;
    let mut degraded = false;
    for run in runs {
        match one(&client, config, &run).await {
            Ok(outcome) => {
                failed |= !outcome.ok;
                degraded |= outcome.degraded;
                notes.push(outcome.note);
            }
            Err(error) => {
                failed = true;
                degraded = true;
                notes.push(format!("周期 {}：{error}；全部 payload/wire 保留，不自动创建新 send intent", run.id));
            }
        }
    }
    let mut outcome = if failed { TaskOutcome::failed(notes.join("；")) } else { TaskOutcome::ok(notes.join("；")) };
    outcome.degraded = degraded;
    Ok(outcome)
}
pub(crate) async fn run_cms_queue(
    config: &CmsQueueConfig,
    tasks: Vec<TaskSnapshot>,
    rules: Option<usize>,
    rate: Option<f64>,
) -> TaskOutcome {
    let Ok(execution) = crate::dispatch::EXECUTION_ID.try_with(Clone::clone) else {
        return TaskOutcome::failed("CMS 缺少稳定周期编号；拒绝创建无法去重的 intent");
    };
    let prepared = (|| -> anyhow::Result<_> {
        let outbox = Outbox::open(&config.output, config.tenant)?;
        let current = outbox.run(identity(config.tenant, &execution, "run"))?;
        payload(&current, config, &execution, &cms_metrics(&tasks, rules, rate))?;
        Ok((outbox, current))
    })();
    let (outbox, current) = match prepared {
        Ok(value) => value,
        Err(error) => return TaskOutcome::failed(format!("CMS payload 无法可信持久化，未调用云端：{error}")),
    };
    let result = tokio::time::timeout(std::time::Duration::from_secs(90), drain(config, &outbox, &current)).await;
    let outcome = match result {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(error)) => {
            let mut result = TaskOutcome::failed(format!("CMS payload 已保存，平台未确认：{error}；不代表云接受"));
            result.degraded = true;
            result
        }
        Err(_) => TaskOutcome::failed("CMS 本轮预算耗尽；保留原 payload/请求编号，未知 send 只查询原回执"),
    };
    outcome.with_artifact(current.artifact())
}

#[cfg(test)]
#[path = "cms_queue_task_tests.rs"]
mod tests;
