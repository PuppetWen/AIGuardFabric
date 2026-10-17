//! 本地周期执行记录；云回调只通过平台永久领取和一次性启动校验执行。
use super::*;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, deterministic_id},
};
use agf_storage::configuration::ConfigStore;
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};

pub(crate) type Handler = Arc<dyn Fn(Partition) -> BoxFuture<'static, TaskOutcome> + Send + Sync>;
tokio::task_local! {
    /// Stable scheduler execution identity, shared by retries of the same receipt.
    pub(crate) static EXECUTION_ID: String;
}
pub(crate) struct Execution {
    pub cloud: bool,
    pub persistent: bool,
    pub tenant: TenantId,
    pub store: Arc<ConfigStore>,
    pub token: String,
    pub app_id: String,
    pub binding: Option<Arc<crate::callback_binding::Client>>,
    pub artifact_roots: Vec<PathBuf>,
}
impl Execution {
    pub(crate) fn offline() -> Self {
        Self {
            cloud: false,
            persistent: false,
            tenant: TenantId::default_tenant(),
            store: Arc::new(ConfigStore::new(None)),
            token: String::new(),
            app_id: String::new(),
            binding: None,
            artifact_roots: Vec::new(),
        }
    }
}

#[derive(Default, Serialize, Deserialize)]
struct Lane {
    #[serde(default)]
    next_sequence: u64,
    records: BTreeMap<String, Receipt>,
}
#[derive(Clone, Serialize, Deserialize)]
struct Receipt {
    sequence: u64,
    execution_id: String,
    partition: Partition,
    claim: Id,
    state: String,
    lease_until: i64,
    updated_at: i64,
    attempts: u32,
    result: Option<TaskOutcome>,
}
const KIND: &str = "scheduler-execution";
pub(crate) async fn completed(
    registry: &Registry,
    name: &str,
    execution_id: &str,
    partition: Partition,
) -> DomainResult<Option<TaskOutcome>> {
    let config = &registry.execution;
    let id = deterministic_id(KIND, &format!("{}:{name}", config.tenant));
    let Some(lane) = config.store.get::<Lane>(config.tenant, KIND, id).await? else { return Ok(None) };
    let key = format!("{execution_id}#{}", partition.index);
    let Some(row) = lane.records.get(&key) else { return Ok(None) };
    if row.partition != partition {
        return Err(conflict("同一执行批次不能中途改变分片总数"));
    }
    if row.state == "succeeded" {
        return row.result.clone().map(Some).ok_or_else(|| conflict("已完成执行的回执损坏，停止重复执行"));
    }
    Ok(None)
}
fn conflict(message: &str) -> DomainError {
    DomainError::Conflict(message.into())
}

pub(crate) async fn execute(
    registry: &Registry,
    name: &str,
    execution_id: &str,
    handler: Handler,
) -> DomainResult<TaskOutcome> {
    execute_partitioned(registry, name, execution_id, handler, Partition::default()).await
}

pub(crate) async fn execute_partitioned(
    registry: &Registry,
    name: &str,
    execution_id: &str,
    handler: Handler,
    partition: Partition,
) -> DomainResult<TaskOutcome> {
    if partition.total == 0 || partition.total > 256 || partition.index >= partition.total {
        return Err(DomainError::Validation("分片参数无效".into()));
    }
    let config = &registry.execution;
    let now = chrono::Utc::now().timestamp();
    let id = deterministic_id(KIND, &format!("{}:{name}", config.tenant));
    let claim = Id::new();
    let mut cached = None;
    let record_key = format!("{execution_id}#{}", partition.index);
    config
        .store
        .mutate::<Lane, _>(config.tenant, KIND, id, |lane| {
            lane.records.retain(|_, row| row.updated_at > now - 30 * 86_400 || row.state == "running");
            if lane
                .records
                .values()
                .any(|row| row.execution_id == execution_id && row.partition.total != partition.total)
            {
                return Err(conflict("同一执行批次不能中途改变分片总数"));
            }
            if let Some(row) = lane.records.get(&record_key) {
                if row.state == "succeeded" {
                    cached = Some(row.result.clone().ok_or_else(|| conflict("已完成执行的回执损坏，停止重复执行"))?);
                    return Ok(());
                }
                if row.state == "uncertain" || (row.state == "running" && row.lease_until <= now) {
                    return Err(conflict("前次执行中断，结果不确定；请先核对制品和业务记录，不会自动重跑"));
                }
                if row.attempts >= 8 {
                    return Err(conflict("同一执行编号已达 8 次尝试上限"));
                }
            }
            if lane.records.values().any(|row| {
                row.state == "running"
                    && row.lease_until > now
                    && (row.partition.index == partition.index || row.partition.total != partition.total)
            }) {
                return Err(conflict("该任务正在执行，请稍后使用相同执行编号重试"));
            }
            if !lane.records.contains_key(&record_key) && lane.records.len() >= 2048 {
                let oldest = lane
                    .records
                    .iter()
                    .filter(|(_, row)| row.state != "running")
                    .min_by_key(|(_, row)| row.updated_at)
                    .map(|(key, _)| key.clone());
                if let Some(key) = oldest {
                    lane.records.remove(&key);
                } else {
                    return Err(conflict("执行记录已满，请检查未结束任务"));
                }
            }
            let attempts = lane.records.get(&record_key).map_or(1, |row| row.attempts + 1);
            let sequence = lane
                .records
                .values()
                .find(|row| row.execution_id == execution_id)
                .map(|row| row.sequence)
                .unwrap_or_else(|| {
                    lane.next_sequence = lane.next_sequence.saturating_add(1);
                    lane.next_sequence
                });
            lane.records.insert(
                record_key.clone(),
                Receipt {
                    sequence,
                    execution_id: execution_id.into(),
                    partition,
                    claim,
                    state: "running".into(),
                    lease_until: now + 3600,
                    updated_at: now,
                    attempts,
                    result: None,
                },
            );
            Ok(())
        })
        .await?;
    if let Some(result) = cached {
        return Ok(result);
    }
    let started = std::time::Instant::now();
    let outcome =
        tokio::time::timeout(Duration::from_mins(5), EXECUTION_ID.scope(execution_id.to_owned(), handler(partition)))
            .await;
    let (state, result) = match outcome {
        Ok(result) => (if result.ok { "succeeded" } else { "failed" }, result),
        Err(_) => ("uncertain", TaskOutcome::failed("执行超过 300 秒，结果不确定；请核对记录后再处理")),
    };
    let summary = result.clone();
    config
        .store
        .mutate::<Lane, _>(config.tenant, KIND, id, |lane| {
            let row = lane
                .records
                .get_mut(&record_key)
                .filter(|row| row.claim == claim)
                .ok_or_else(|| conflict("执行记录已被其他实例修改"))?;
            row.state = state.into();
            row.result = Some(summary);
            row.updated_at = chrono::Utc::now().timestamp();
            row.lease_until = 0;
            Ok(())
        })
        .await?;
    registry.record(name, result.ok, millis(started));
    if let Some((name, _)) = registry.tasks.iter().find(|(registered, _)| *registered == name) {
        tasks::note_set(&registry.notes, name, result.summary());
    }
    Ok(result)
}

/// 依赖只有在最近批次的所有分片成功且未过期时才满足，不能用旧成功覆盖新失败。
pub(crate) async fn recent_completion(registry: &Registry, name: &str, max_age: i64) -> DomainResult<bool> {
    let config = &registry.execution;
    let id = deterministic_id(KIND, &format!("{}:{name}", config.tenant));
    let Some(lane) = config.store.get::<Lane>(config.tenant, KIND, id).await? else { return Ok(false) };
    let Some(latest) = lane.records.values().max_by_key(|row| row.sequence) else { return Ok(false) };
    let rows: Vec<_> = lane.records.values().filter(|row| row.sequence == latest.sequence).collect();
    let cutoff = chrono::Utc::now().timestamp() - max_age;
    Ok(rows.len() == latest.partition.total as usize
        && rows.iter().all(|row| {
            row.state == "succeeded" && row.updated_at >= cutoff && row.result.as_ref().is_some_and(|result| result.ok)
        }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn independent_shards_run_concurrently_but_cannot_resize_a_batch() {
        let registry = Registry::new();
        let calls = Arc::new(AtomicU64::new(0));
        let counter = Arc::clone(&calls);
        let run: Handler = Arc::new(move |partition| {
            let counter = Arc::clone(&counter);
            Box::pin(async move {
                counter.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(20)).await;
                TaskOutcome::ok(format!("partition {}", partition.index))
            })
        });
        let (a, b) = tokio::join!(
            execute_partitioned(&registry, "log-pull", "batch", Arc::clone(&run), Partition { index: 0, total: 2 }),
            execute_partitioned(&registry, "log-pull", "batch", Arc::clone(&run), Partition { index: 1, total: 2 })
        );
        assert!(a.unwrap().ok && b.unwrap().ok);
        assert!(
            execute_partitioned(&registry, "log-pull", "batch", Arc::clone(&run), Partition { index: 0, total: 2 })
                .await
                .unwrap()
                .ok
        );
        assert!(
            execute_partitioned(&registry, "log-pull", "batch", run, Partition { index: 2, total: 3 }).await.is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
    #[tokio::test]
    async fn concurrent_calls_and_completed_replays_run_once() {
        let registry = Arc::new(Registry::new());
        let calls = Arc::new(AtomicU64::new(0));
        let counter = Arc::clone(&calls);
        let run: Handler = Arc::new(move |_partition| {
            let counter = Arc::clone(&counter);
            Box::pin(async move {
                counter.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(30)).await;
                TaskOutcome::ok("done")
            })
        });
        let (a, b) = tokio::join!(
            execute(&registry, "asset-inventory", "e1", Arc::clone(&run)),
            execute(&registry, "asset-inventory", "e1", Arc::clone(&run))
        );
        assert!(a.is_ok() || b.is_ok());
        assert!(a.is_err() || b.is_err());
        assert!(execute(&registry, "asset-inventory", "e1", run).await.unwrap().ok);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
    #[tokio::test]
    async fn explicit_failure_retries_and_receipt_survives_new_registry() {
        let registry = Registry::new();
        let first: Handler = Arc::new(|_partition| Box::pin(async { TaskOutcome::failed("upstream failed") }));
        assert!(!execute(&registry, "log-pull", "e1", first).await.unwrap().ok);
        let mut fresh = Registry::new();
        fresh.execution.store = Arc::clone(&registry.execution.store);
        let next: Handler = Arc::new(|_partition| Box::pin(async { TaskOutcome::ok("recovered") }));
        assert!(execute(&fresh, "log-pull", "e1", Arc::clone(&next)).await.unwrap().ok);
        assert_eq!(fresh.state("log-pull").unwrap().runs.load(Ordering::SeqCst), 1);
        assert!(execute(&fresh, "log-pull", "e1", next).await.unwrap().ok);
        assert_eq!(fresh.state("log-pull").unwrap().runs.load(Ordering::SeqCst), 1);
    }
}
