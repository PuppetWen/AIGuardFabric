//! 六类任务共用依赖图。本地可补跑缺失上游，云回调等待完整上游批次。
use super::*;
use agf_alicloud::schedulerx3::SchedulerX3Job;
use agf_core::error::{DomainError, DomainResult};
use std::collections::BTreeSet;

fn runtime_name(name: &str) -> String {
    match name {
        "report" => "report-generate",
        "archive" => "cold-archive",
        name => name,
    }
    .into()
}
fn graph(tenant: TenantId) -> BTreeMap<String, Vec<String>> {
    let jobs = SchedulerX3Job::platform_defaults(tenant);
    jobs.iter()
        .map(|job| {
            (
                runtime_name(&job.job_kind),
                job.depends_on
                    .iter()
                    .filter_map(|id| jobs.iter().find(|candidate| candidate.id == *id))
                    .map(|parent| runtime_name(&parent.job_kind))
                    .collect(),
            )
        })
        .collect()
}
fn visit(
    name: &str,
    graph: &BTreeMap<String, Vec<String>>,
    active: &mut BTreeSet<String>,
    ordered: &mut Vec<String>,
) -> DomainResult<()> {
    if !active.insert(name.into()) {
        return Err(DomainError::Config("任务依赖存在循环".into()));
    }
    for parent in graph.get(name).into_iter().flatten() {
        if ordered.contains(parent) {
            continue;
        }
        visit(parent, graph, active, ordered)?;
        ordered.push(parent.clone());
    }
    active.remove(name);
    Ok(())
}
pub(crate) async fn run(
    registry: &Registry,
    name: &str,
    execution_id: &str,
    handler: dispatch::Handler,
    partition: Partition,
) -> DomainResult<TaskOutcome> {
    // 已成功的同一执行只返回回执；上游后续失败不能改变历史执行结果。
    if let Some(result) = dispatch::completed(registry, name, execution_id, partition).await? {
        return Ok(result);
    }
    let graph = graph(registry.execution.tenant);
    let mut ordered = Vec::new();
    visit(name, &graph, &mut BTreeSet::new(), &mut ordered)?;
    for parent in ordered {
        let parent_handler = registry
            .handlers
            .lock()
            .map_err(|_| DomainError::Internal("任务注册表不可用".into()))?
            .get(parent.as_str())
            .cloned()
            .ok_or_else(|| DomainError::PreconditionFailed(format!("上游任务 {parent} 已停用")))?;
        if dispatch::recent_completion(registry, &parent, 86_400).await? {
            continue;
        }
        if registry.execution.cloud {
            return Err(DomainError::PreconditionFailed(format!(
                "等待上游 {parent} 最近批次全部分片成功（有效期 24 小时）"
            )));
        }
        // 同一五分钟窗口的多个下游共用补跑编号；成功后通过完成记录复用。
        let dependency_id = format!("dependency:{parent}:{}", chrono::Utc::now().timestamp() / 300);
        let result = dispatch::execute(registry, &parent, &dependency_id, parent_handler).await?;
        if !result.ok {
            return Err(DomainError::PreconditionFailed(format!("上游 {parent} 失败：{}", result.note)));
        }
    }
    dispatch::execute_partitioned(registry, name, execution_id, handler, partition).await
}

#[cfg(test)]
mod tests {
    use super::*;
    fn register(
        registry: &Registry,
        name: &'static str,
        calls: Arc<Mutex<Vec<&'static str>>>,
        ok: bool,
    ) -> dispatch::Handler {
        let handler: dispatch::Handler = Arc::new(move |_partition| {
            let calls = Arc::clone(&calls);
            Box::pin(async move {
                calls.lock().unwrap().push(name);
                if ok { TaskOutcome::ok(name) } else { TaskOutcome::failed(name) }
            })
        });
        registry.handlers.lock().unwrap().insert(name, Arc::clone(&handler));
        handler
    }
    #[tokio::test]
    async fn local_dependencies_execute_in_order_and_reuse_success() {
        let registry = Registry::new();
        let calls = Arc::new(Mutex::new(Vec::new()));
        register(&registry, "asset-inventory", Arc::clone(&calls), true);
        register(&registry, "log-pull", Arc::clone(&calls), true);
        let report = register(&registry, "report-generate", Arc::clone(&calls), true);
        assert!(run(&registry, "report-generate", "one", Arc::clone(&report), Partition::default()).await.unwrap().ok);
        assert!(run(&registry, "report-generate", "two", report, Partition::default()).await.unwrap().ok);
        assert_eq!(*calls.lock().unwrap(), vec!["asset-inventory", "log-pull", "report-generate", "report-generate"]);
    }
    #[tokio::test]
    async fn failed_parent_blocks_child_and_new_failure_invalidates_old_success() {
        let registry = Registry::new();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let good = register(&registry, "asset-inventory", Arc::clone(&calls), true);
        dispatch::execute(&registry, "asset-inventory", "old", good).await.unwrap();
        let bad = register(&registry, "asset-inventory", Arc::clone(&calls), false);
        dispatch::execute(&registry, "asset-inventory", "new", bad).await.unwrap();
        assert!(!dispatch::recent_completion(&registry, "asset-inventory", 86_400).await.unwrap());
        let child = register(&registry, "log-pull", Arc::clone(&calls), true);
        assert!(run(&registry, "log-pull", "one", child, Partition::default()).await.is_err());
        assert!(!calls.lock().unwrap().contains(&"log-pull"));
    }
    #[tokio::test]
    async fn child_replay_keeps_receipt_after_new_parent_failure() {
        let mut registry = Registry::new();
        registry.execution.cloud = true;
        let calls = Arc::new(Mutex::new(Vec::new()));
        let parent = register(&registry, "asset-inventory", Arc::clone(&calls), true);
        dispatch::execute(&registry, "asset-inventory", "old", parent).await.unwrap();
        let child = register(&registry, "log-pull", Arc::clone(&calls), true);
        run(&registry, "log-pull", "child", Arc::clone(&child), Partition::default()).await.unwrap();
        let bad = register(&registry, "asset-inventory", Arc::clone(&calls), false);
        dispatch::execute(&registry, "asset-inventory", "new", bad).await.unwrap();
        assert!(run(&registry, "log-pull", "child", Arc::clone(&child), Partition::default()).await.unwrap().ok);
        assert!(run(&registry, "log-pull", "new-child", child, Partition::default()).await.is_err());
        assert_eq!(calls.lock().unwrap().iter().filter(|name| **name == "log-pull").count(), 1);
    }
    #[tokio::test]
    async fn cloud_waits_for_all_parent_shards_before_running_child() {
        let mut registry = Registry::new();
        registry.execution.cloud = true;
        let calls = Arc::new(Mutex::new(Vec::new()));
        let parent = register(&registry, "asset-inventory", Arc::clone(&calls), true);
        let child = register(&registry, "log-pull", Arc::clone(&calls), true);
        dispatch::execute_partitioned(
            &registry,
            "asset-inventory",
            "upstream",
            Arc::clone(&parent),
            Partition { index: 0, total: 2 },
        )
        .await
        .unwrap();
        assert!(run(&registry, "log-pull", "child", Arc::clone(&child), Partition::default()).await.is_err());
        dispatch::execute_partitioned(
            &registry,
            "asset-inventory",
            "upstream",
            parent,
            Partition { index: 1, total: 2 },
        )
        .await
        .unwrap();
        assert!(run(&registry, "log-pull", "child", child, Partition::default()).await.unwrap().ok);
        assert_eq!(*calls.lock().unwrap(), vec!["asset-inventory", "asset-inventory", "log-pull"]);
    }
}
