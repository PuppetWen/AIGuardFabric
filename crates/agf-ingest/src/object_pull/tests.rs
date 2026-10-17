//! 对象拉取单元测试：游标幂等、轮询取数、错误降级与指标。

use super::*;
use crate::bus::NoopEventBus;
use crate::pipeline::{InMemorySink, IngestConfig, Sink};
use crate::registry::ParserRegistry;
use agf_core::enums::HealthState;
use agf_core::ids::{Id, TenantId};
use agf_core::source::{CollectionMode, SourceConnection};
use agf_core::time::Timestamp;

const LINE_A: &str =
    r#"{"time":"2026-02-21T10:23:45Z","host":"a","real_client_ip":"203.0.113.9","rule_id":"R1","acl_action":"block"}"#;
const LINE_B: &str =
    r#"{"time":"2026-02-21T10:23:46Z","host":"b","real_client_ip":"203.0.113.10","rule_id":"R2","acl_action":"block"}"#;

/// 内存对象源：可注入对象与读取失败，**不依赖任何网络/容器**。
#[derive(Debug, Default)]
struct MemoryObjectSource {
    objects: Mutex<BTreeMap<String, (ObjectMeta, Vec<u8>)>>,
    fail_keys: Mutex<Vec<String>>,
    list_calls: Mutex<usize>,
}

impl MemoryObjectSource {
    fn put(&self, key: &str, etag: &str, body: &str) {
        let meta = ObjectMeta {
            key: key.to_string(),
            etag: Some(etag.to_string()),
            last_modified: Some("1770985425.000000000".to_string()),
            size: u64::try_from(body.len()).unwrap_or(0),
        };
        if let Ok(mut objects) = self.objects.lock() {
            objects.insert(key.to_string(), (meta, body.as_bytes().to_vec()));
        }
    }

    fn fail(&self, key: &str) {
        if let Ok(mut fails) = self.fail_keys.lock() {
            fails.push(key.to_string());
        }
    }

    fn list_calls(&self) -> usize {
        self.list_calls.lock().map(|c| *c).unwrap_or(0)
    }
}

#[async_trait]
impl ObjectSource for MemoryObjectSource {
    async fn list(&self, prefix: &str, max: usize) -> DomainResult<Vec<ObjectMeta>> {
        if let Ok(mut calls) = self.list_calls.lock() {
            *calls += 1;
        }
        let objects = self.objects.lock().map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))?;
        Ok(objects
            .values()
            .filter(|(meta, _)| meta.key.starts_with(prefix))
            .map(|(meta, _)| meta.clone())
            .take(max)
            .collect())
    }

    async fn get(&self, key: &str) -> DomainResult<Vec<u8>> {
        let failing = self.fail_keys.lock().map(|f| f.contains(&key.to_string())).unwrap_or(false);
        if failing {
            return Err(DomainError::DependencyUnavailable {
                dependency: "s3".to_string(),
                cause: format!("注入的读取失败: {key}"),
            });
        }
        let objects = self.objects.lock().map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))?;
        objects
            .get(key)
            .map(|(_, body)| body.clone())
            .ok_or_else(|| DomainError::NotFound { entity: "object", id: key.to_string() })
    }

    fn describe(&self) -> String {
        "memory://test".to_string()
    }
}

fn log_source() -> LogSource {
    let now = Timestamp::now();
    LogSource {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        name: "object-pull-test".to_string(),
        protocol: IngestProtocol::ObjectStorage,
        vendor: "generic".to_string(),
        product: "json".to_string(),
        enabled: true,
        parser_id: None,
        connection: SourceConnection::default(),
        mode: CollectionMode::Pull,
        poll_interval_secs: Some(5),
        require_mtls: false,
        allowed_cidrs: vec![],
        max_message_bytes: 1_048_576,
        max_eps: 0,
        tags: vec![],
        health: HealthState::Healthy,
        last_event_at: None,
        total_events: 0,
        last_error: None,
        created_at: now,
        updated_at: now,
    }
}

fn pipeline_and_sink() -> (Arc<IngestPipeline>, Arc<InMemorySink>) {
    let sink = Arc::new(InMemorySink::new());
    let pipeline = IngestPipeline::new(
        ParserRegistry::with_builtins(),
        Arc::clone(&sink) as Arc<dyn Sink>,
        Arc::new(NoopEventBus),
        IngestConfig { emit_to_bus: false, ..IngestConfig::default() },
    );
    (Arc::new(pipeline), sink)
}

fn receiver(source: Arc<dyn ObjectSource>, cursor_path: Option<PathBuf>) -> ObjectPullReceiver {
    ObjectPullReceiver::new(
        source,
        ObjectPullConfig { bucket: "agf-raw-logs".to_string(), cursor_path, ..ObjectPullConfig::default() },
    )
}

#[test]
fn cursor_detects_new_and_changed_objects() {
    let mut cursor = ObjectCursor::new();
    assert!(cursor.is_empty());
    let first = ObjectMeta {
        key: "2026/02/a.ndjson".to_string(),
        etag: Some("etag-1".to_string()),
        last_modified: Some("1770985425.000000000".to_string()),
        size: 10,
    };
    assert!(cursor.needs_pull(&first), "未出现过的 key 必须拉取");
    cursor.mark(&first);
    assert_eq!(cursor.len(), 1);
    assert!(!cursor.needs_pull(&first), "同 ETag 不得重复拉取（幂等）");

    let changed = ObjectMeta { etag: Some("etag-2".to_string()), ..first.clone() };
    assert!(cursor.needs_pull(&changed), "ETag 变化必须重新拉取");
    cursor.mark(&changed);
    assert!(!cursor.needs_pull(&changed));

    // 后端不给 ETag 时退化为 (LastModified, size)
    let mut no_etag_cursor = ObjectCursor::new();
    let no_etag = ObjectMeta {
        key: "2026/02/b.ndjson".to_string(),
        etag: None,
        last_modified: Some("1770985425.000000000".to_string()),
        size: 10,
    };
    assert!(no_etag_cursor.needs_pull(&no_etag), "无 ETag 时按 LastModified+size 判定");
    no_etag_cursor.mark(&no_etag);
    assert!(!no_etag_cursor.needs_pull(&no_etag));
    let grown = ObjectMeta { size: 99, ..no_etag.clone() };
    assert!(no_etag_cursor.needs_pull(&grown), "size 变化必须重新拉取");
    let touched = ObjectMeta { last_modified: Some("1770985499.000000000".to_string()), ..no_etag.clone() };
    assert!(no_etag_cursor.needs_pull(&touched), "LastModified 变化必须重新拉取");
}

#[test]
fn cursor_roundtrips_through_disk_and_survives_corruption() {
    let dir = std::env::temp_dir().join(format!("agf-objcursor-{}", uuid::Uuid::new_v4()));
    assert!(std::fs::create_dir_all(&dir).is_ok());
    let path = dir.join("cursor.json");
    let mut cursor = ObjectCursor::new();
    cursor.mark(&ObjectMeta { key: "k".to_string(), etag: Some("e".to_string()), last_modified: None, size: 3 });
    assert!(cursor.save(&path).is_ok());
    let loaded = ObjectCursor::load(&path);
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded.objects.get("k").map(|s| s.etag.clone()).unwrap_or(None), Some("e".to_string()));

    // 损坏文件 ⇒ 空游标（不 panic、不让进程起不来）
    assert!(std::fs::write(&path, b"{not json").is_ok());
    assert!(ObjectCursor::load(&path).is_empty());
    // 不存在 ⇒ 空游标
    assert!(ObjectCursor::load(&dir.join("missing.json")).is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn receiver_pulls_new_objects_and_is_idempotent() {
    let source = Arc::new(MemoryObjectSource::default());
    source.put("2026/02/a.ndjson", "etag-a", &format!("{LINE_A}\n{LINE_B}\n"));
    let receiver = receiver(Arc::clone(&source) as Arc<dyn ObjectSource>, None);
    let (pipeline, sink) = pipeline_and_sink();
    let log_source = log_source();

    let first = receiver.pull_once(&pipeline, &log_source, 10).await;
    assert!(first.is_ok(), "{first:?}");
    let Ok(first) = first else { return };
    assert_eq!(first.listed, 1);
    assert_eq!(first.objects, 1);
    assert_eq!(first.records, 2, "NDJSON 两行各成一条记录");
    assert_eq!(first.persisted, 2);
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(2));

    // 第二轮：同一个对象 ETag 未变 ⇒ 一条都不再拉
    let second = receiver.pull_once(&pipeline, &log_source, 10).await;
    assert!(second.is_ok());
    let Ok(second) = second else { return };
    assert_eq!(second.objects, 0, "幂等：同 ETag 对象不得重复拉取");
    assert_eq!(second.records, 0);
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(2), "事件数不得翻倍");
    assert!(source.list_calls() >= 2, "列举必须每轮都发生（否则发现不了新对象）");

    // 对象被覆盖（ETag 变化）⇒ 重新拉取
    source.put("2026/02/a.ndjson", "etag-a2", &format!("{LINE_A}\n{LINE_B}\n"));
    let third = receiver.pull_once(&pipeline, &log_source, 10).await;
    assert!(third.is_ok());
    let Ok(third) = third else { return };
    assert_eq!(third.objects, 1, "ETag 变化必须重新拉取");
}

#[tokio::test]
async fn receiver_survives_object_errors_and_oversize() {
    let source = Arc::new(MemoryObjectSource::default());
    source.put("a.ndjson", "e1", LINE_A);
    source.put("b.ndjson", "e2", LINE_B);
    source.fail("a.ndjson");
    let config = ObjectPullConfig {
        bucket: "b".to_string(),
        max_object_bytes: 8, // 故意极小：b.ndjson 必然超限
        cursor_path: None,
        ..ObjectPullConfig::default()
    };
    let receiver = ObjectPullReceiver::new(Arc::clone(&source) as Arc<dyn ObjectSource>, config);
    let (pipeline, sink) = pipeline_and_sink();
    let report = receiver.pull_once(&pipeline, &log_source(), 10).await;
    assert!(report.is_ok(), "单对象失败不得让整轮失败: {report:?}");
    let Ok(report) = report else { return };
    assert_eq!(report.failed, 1, "读取失败的对象计数");
    assert_eq!(report.oversized, 1, "超限对象计数");
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(0));
    assert_eq!(receiver.cursor_snapshot().len(), 1, "超限对象必须标记已处理（避免活锁）");
    assert_eq!(receiver.counters().snapshot().dropped, 2);

    // 超限对象下一轮不再重试
    let again = receiver.pull_once(&pipeline, &log_source(), 10).await;
    assert_eq!(again.map(|r| r.objects).unwrap_or(99), 0);
}

#[tokio::test]
async fn cursor_file_prevents_reprocessing_after_restart() {
    let dir = std::env::temp_dir().join(format!("agf-objrestart-{}", uuid::Uuid::new_v4()));
    assert!(std::fs::create_dir_all(&dir).is_ok());
    let path = dir.join("cursor.json");
    let source = Arc::new(MemoryObjectSource::default());
    source.put("a.ndjson", "e1", LINE_A);
    let (pipeline, sink) = pipeline_and_sink();
    let source_trait = Arc::clone(&source) as Arc<dyn ObjectSource>;

    let first = receiver(Arc::clone(&source_trait), Some(path.clone()));
    assert_eq!(first.pull_once(&pipeline, &log_source(), 10).await.map(|r| r.records).unwrap_or(0), 1);
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(1));
    drop(first);

    // "重启"：新的接收器从游标文件恢复 ⇒ 不重复拉取
    let restarted = receiver(source_trait, Some(path.clone()));
    assert_eq!(restarted.cursor_snapshot().len(), 1, "游标必须从磁盘恢复");
    assert_eq!(restarted.pull_once(&pipeline, &log_source(), 10).await.map(|r| r.records).unwrap_or(99), 0);
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(1), "重启后不得重复落库");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn describe_reports_ready_and_s3_config_is_validated() {
    let source = Arc::new(MemoryObjectSource::default());
    let receiver = receiver(source, None);
    let descriptor = receiver.describe();
    assert_eq!(descriptor.status, ReceiverStatus::Ready);
    assert_eq!(descriptor.protocol, IngestProtocol::ObjectStorage);
    assert!(descriptor.todo.is_none());
    assert!(descriptor.note.contains("S3/OSS"));
    assert_eq!(receiver.protocol(), IngestProtocol::ObjectStorage);
    // 端点/凭据缺失 ⇒ 明确 Configuration 错误（不是静默成功）
    assert!(S3ObjectSource::new("", "us-east-1", "k", "s", "b", true).is_err());
    assert!(S3ObjectSource::new("http://127.0.0.1:9000", "us-east-1", "k", "s", "", true).is_err());
    assert!(S3ObjectSource::new("http://127.0.0.1:9000", "us-east-1", "k", "s", "b", true).is_ok());
}
