//! Scheduled runs use the platform's durable campaign and immutable evidence APIs.
use super::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub(crate) struct CruiseConfig {
    pub server: String,
    pub auth: Option<ApiAuth>,
    pub tenant: TenantId,
    pub output: PathBuf,
    pub guard: u8,
}

async fn body(mut response: reqwest::Response) -> anyhow::Result<Value> {
    anyhow::ensure!(response.status().is_success(), "红队平台接口返回 HTTP {}", response.status().as_u16());
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| anyhow::anyhow!("读取红队响应失败"))? {
        anyhow::ensure!(bytes.len() + chunk.len() <= 16 * 1024 * 1024, "红队证据超过 16 MiB，请增加分片数");
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("红队响应不是有效 JSON"))
}

fn request(client: &reqwest::Client, config: &CruiseConfig, path: &str) -> anyhow::Result<reqwest::RequestBuilder> {
    let auth = config.auth.as_ref().ok_or_else(|| anyhow::anyhow!("红队巡航需要 redteam:read/execute 服务 API Key"))?;
    Ok(auth.apply(client.get(api_url(&config.server, path))).header("x-agf-tenant", config.tenant.to_string()))
}

async fn get(client: &reqwest::Client, config: &CruiseConfig, path: &str) -> anyhow::Result<Value> {
    body(request(client, config, path)?.send().await.map_err(|_| anyhow::anyhow!("红队平台连接失败"))?).await
}

fn save(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::{Read, Write};
    match std::fs::OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => {
            if file.write_all(bytes).and_then(|()| file.sync_all()).is_err() {
                drop(file);
                let _ = std::fs::remove_file(path);
                anyhow::bail!("红队证据写入失败，请检查报告目录空间和权限");
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let mut existing = Vec::new();
            std::fs::File::open(path)?.take(bytes.len() as u64 + 1).read_to_end(&mut existing)?;
            anyhow::ensure!(existing == bytes, "既有红队证据不同，停止覆盖");
            Ok(())
        }
        Err(_) => anyhow::bail!("红队证据文件创建失败，请检查报告目录权限"),
    }
}

fn archive(config: &CruiseConfig, id: Id, evidence: &Value) -> anyhow::Result<TaskOutcome> {
    let record = &evidence["record"];
    let campaign = &record["campaign"];
    let report = &record["report"];
    let total = campaign["total_cases"].as_u64().ok_or_else(|| anyhow::anyhow!("红队报告缺少用例数"))?;
    let results = record["results"].as_array().ok_or_else(|| anyhow::anyhow!("红队报告缺少逐项结果"))?;
    anyhow::ensure!(
        evidence["format"] == "agf-redteam-evidence-v1"
            && record["execution_mode"] == "simulator"
            && campaign["state"] == "completed"
            && campaign["id"] == id.to_string()
            && campaign["tenant_id"] == config.tenant.to_string()
            && campaign["scheduled"] == true
            && campaign["ci_gate"] == false
            && report["campaign_id"] == id.to_string()
            && report["tenant_id"] == config.tenant.to_string()
            && total > 0
            && campaign["executed_cases"] == total
            && report["executed"] == total
            && results.len() as u64 == total,
        "红队证据身份、模式或完成数量不一致，不能标记成功"
    );
    let markdown =
        report["markdown"].as_str().filter(|s| !s.is_empty()).ok_or_else(|| anyhow::anyhow!("红队报告为空"))?;
    let json = config.output.join(format!("redteam-cruise-{id}.json"));
    let md = config.output.join(format!("redteam-cruise-{id}.md"));
    std::fs::create_dir_all(&config.output).map_err(|_| anyhow::anyhow!("报告目录创建失败"))?;
    save(&json, &serde_json::to_vec_pretty(evidence)?)?;
    save(&md, markdown.as_bytes())?;
    Ok(TaskOutcome::ok(format!(
        "模拟巡航 {id} 完成：{total} 条；已保存控制台任务、逐项证据和报告；未启用 CI，不代表真实目标通过"
    ))
    .with_artifact(json.display().to_string())
    .with_artifact(md.display().to_string()))
}

async fn run(
    client: &reqwest::Client,
    config: &CruiseConfig,
    partition: crate::Partition,
    execution: &str,
) -> anyhow::Result<TaskOutcome> {
    let auth = config.auth.as_ref().ok_or_else(|| anyhow::anyhow!("红队巡航需要 redteam:read/execute 服务 API Key"))?;
    let key = format!("scheduler-redteam-{:x}-{}", Sha256::digest(execution.as_bytes()), partition.index);
    let payload = json!({"name":format!("scheduler-cruise-{}-p{}", &key[18..34], partition.index),
        "execution_mode":"simulator","target_name":"scheduler-local-simulator","guard_strength":config.guard,
        "max_cases":500,"ci_gate":false,"scheduled":true,"partition":partition});
    let response = auth
        .apply(client.post(api_url(&config.server, "/api/v1/redteam/campaigns")))
        .header("x-agf-tenant", config.tenant.to_string())
        .header("idempotency-key", key)
        .json(&payload)
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("巡航提交连接失败；保留执行编号重试，不创建新编号"))?;
    let response = body(response).await?;
    if response["skipped"] == true {
        return Ok(TaskOutcome::skipped("平台用例库在本分片没有用例"));
    }
    let id: Id = response["task_id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("巡航提交缺少有效任务 ID"))?;
    let poll = async {
        loop {
            let state = get(client, config, &format!("/api/v1/redteam/campaigns/{id}")).await?;
            match state["campaign"]["state"].as_str() {
                Some("completed") => break,
                Some("queued" | "running") => tokio::time::sleep(std::time::Duration::from_millis(250)).await,
                Some("failed" | "cancelled") => anyhow::bail!("巡航 {id} 未完成；请在红队中心核对，复测需新执行编号"),
                _ => anyhow::bail!("巡航 {id} 返回未知状态"),
            }
        }
        let evidence = get(client, config, &format!("/api/v1/redteam/campaigns/{id}/evidence")).await?;
        archive(config, id, &evidence)
    };
    tokio::time::timeout(std::time::Duration::from_mins(4), poll)
        .await
        .map_err(|_| anyhow::anyhow!("巡航 {id} 尚未完成；保留执行编号重试可继续读取同一任务"))?
}

pub(crate) async fn run_redteam_cruise(
    client: &reqwest::Client,
    config: &CruiseConfig,
    partition: crate::Partition,
) -> TaskOutcome {
    let Ok(execution) = crate::dispatch::EXECUTION_ID.try_with(Clone::clone) else {
        return TaskOutcome::failed("缺少持久执行编号，拒绝发起无法去重的巡航");
    };
    match run(client, config, partition, &execution).await {
        Ok(outcome) => outcome,
        Err(error) => TaskOutcome::failed(error.to_string()),
    }
}

#[cfg(test)]
#[path = "redteam_cruise_tests.rs"]
mod tests;
