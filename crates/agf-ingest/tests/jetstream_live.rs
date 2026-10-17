//! 对**真实 NATS + JetStream**（`AGF_E2E_JETSTREAM_URL`）的入向订阅验证：durable `provision`
//! 幂等、`ack_with(AckKind)` **真的**把应答发给服务端（pending/redelivered 归零）、
//! `term` 后不再重投、新连接（= 进程重启）从 ack 水位续投不重不漏。
//!
//! 为什么必须真机：修复前 `AsyncNatsJetStream::ack()` 是**空实现**（只 `debug!` + `Ok(())`，
//! 从不 `ack_with`），12 个离线用例全绿却掩盖了"真机上永远不 ack"——服务端只会按 `ack_wait`
//! 无限重投。本文件用**服务端 consumer 统计**（`num_ack_pending` / `num_redelivered`）把它钉死。
//!
//! 运行方式（NATS 已在跑，`/jsz` 的 `store_dir` 非空即 JetStream 已开启）：
//!
//! ```text
//! set AGF_E2E_JETSTREAM_URL=nats://127.0.0.1:4222
//! cargo test -p agf-ingest --test jetstream_live -- --ignored --nocapture
//! ```
//!
//! 未设置该环境变量时用例直接跳过（`#[ignore]` 保证常规 `cargo test` 不依赖任何外部服务）。
#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used, clippy::print_stdout)]

use std::sync::Arc;
use std::time::Duration;

use agf_core::enums::{HealthState, IngestProtocol};
use agf_core::ids::{Id, TenantId};
use agf_core::source::{CollectionMode, LogSource, SourceConnection};
use agf_core::time::Timestamp;
use agf_ingest::bus::NoopEventBus;
use agf_ingest::jetstream::{AsyncNatsJetStream, ConsumerPlan, JetAckAction, JetMode, JetStreamReceiver, StreamPlan};
use agf_ingest::pipeline::{InMemorySink, IngestConfig, IngestPipeline, Sink};
use agf_ingest::registry::ParserRegistry;

/// 被测 NATS 地址（如 `nats://127.0.0.1:4222`）。
const ENV_URL: &str = "AGF_E2E_JETSTREAM_URL";

/// 本用例专用的稳定标识（重启后 durable 名不变的前提）。
const IDENTITY: &str = "e2e-live";

fn jetstream_url() -> Option<Vec<String>> {
    let value = std::env::var(ENV_URL).ok()?.trim().to_string();
    if value.is_empty() {
        return None;
    }
    Some(value.split(',').map(|u| u.trim().to_string()).filter(|u| !u.is_empty()).collect())
}

fn log_source() -> LogSource {
    let now = Timestamp::now();
    LogSource {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        name: "jetstream-live".to_string(),
        protocol: IngestProtocol::Nats,
        vendor: "generic".to_string(),
        product: "json".to_string(),
        enabled: true,
        parser_id: None,
        connection: SourceConnection::default(),
        mode: CollectionMode::Pull,
        poll_interval_secs: None,
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
        IngestConfig { emit_to_bus: false, dedup_window_secs: 0, ..IngestConfig::default() },
    );
    (Arc::new(pipeline), sink)
}

/// 装配好的接收器 + 底层实现（ack_wait 压到 2s，让"超时重投"能在测试内被观察到）。
fn receiver(source_impl: Arc<AsyncNatsJetStream>) -> (JetStreamReceiver, Arc<InMemorySink>) {
    let (pipeline, sink) = pipeline_and_sink();
    let subject = format!("agf.ingest.{IDENTITY}");
    let stream = StreamPlan::for_identity(IDENTITY, &subject);
    let mut consumer = ConsumerPlan::for_identity(IDENTITY, JetMode::Pull, &subject, 32);
    consumer.ack_wait_secs = 2;
    consumer.max_deliver = 5;
    (JetStreamReceiver::new(pipeline, log_source(), stream, consumer, source_impl), sink)
}

/// 往 `subject` 发布消息并**等待 JetStream 服务端 ack**（与 `tools/simulators/nats_jetstream.py`
/// 的 `pub` 子命令等价：拿不到 ack 就失败，绝不假装投递成功）。
async fn publish(client: &AsyncNatsJetStream, subject: &str, payloads: &[Vec<u8>]) {
    for payload in payloads {
        let ack =
            client.context().publish(subject.to_string(), payload.clone().into()).await.expect("发布到 JetStream");
        ack.await.expect("等待 JetStream 服务端 ack");
    }
}

#[tokio::test]
#[ignore = "需要真实 NATS + JetStream（AGF_E2E_JETSTREAM_URL）"]
async fn durable_provision_pull_ack_term_and_restart_resume() {
    let Some(urls) = jetstream_url() else {
        println!("[live] {ENV_URL} 未设置，跳过");
        return;
    };
    let identity_stream = StreamPlan::for_identity(IDENTITY, &format!("agf.ingest.{IDENTITY}")).name.clone();

    // ---- ① provision 幂等：重复声明不新增 consumer ----
    let source_impl = Arc::new(AsyncNatsJetStream::connect(urls.clone()).await.expect("连接真实 NATS"));
    // 清掉上一轮残留（只动本用例自己的 stream）
    let _ = source_impl.delete_stream(&identity_stream).await;
    let (recv, sink) = receiver(Arc::clone(&source_impl));
    let first = recv.provision().await.expect("首次 provision");
    let second = recv.provision().await.expect("第二次 provision");
    println!("[live] provision #1 = {first:?}");
    println!("[live] provision #2 = {second:?}（consumer_count 必须不增）");
    assert_eq!(second.consumer_count, 1, "durable consumer 幂等：重复声明不新增");
    let stats = source_impl.consumer_stats(&recv.consumer_plan().durable_name).await.expect("consumer 统计");
    println!("[live] provision 后 consumer 统计 = {stats:?}");

    // ---- ② N 条投递 → pull 接入 → sink 计数 = N；ack 后 pending/ack_pending/redelivered 归零 ----
    let payloads: Vec<Vec<u8>> =
        (0..5).map(|i| format!("{{\"message\":\"jetstream-live {i}\",\"index\":{i}}}").into_bytes()).collect();
    publish(&source_impl, &format!("agf.ingest.{IDENTITY}"), &payloads).await;
    let pulled = recv.poll_batch(32).await.expect("pull 一批");
    assert_eq!(pulled, 5, "5 条全部拉取");
    assert_eq!(sink.events().expect("事件快照").len(), 5, "5 条全部落库");
    let after_ack = source_impl.consumer_stats(&recv.consumer_plan().durable_name).await.expect("consumer 统计");
    println!("[live] ack 后 consumer 统计 = {after_ack:?}");
    assert_eq!(after_ack.num_pending, 0, "全部投递完 ⇒ pending 归零");
    assert_eq!(after_ack.num_ack_pending, 0, "**应答必须真的发到服务端**（空实现时这里恒 > 0）");
    assert_eq!(after_ack.num_redelivered, 0, "ack 之后不该发生重投");
    // 等过 ack_wait（2s）：若 ack 没发出去，服务端会重投 ⇒ num_redelivered 增长
    tokio::time::sleep(Duration::from_secs(5)).await;
    let settled = source_impl.consumer_stats(&recv.consumer_plan().durable_name).await.expect("consumer 统计");
    println!("[live] 等待 {}s（> ack_wait=2s）后 = {settled:?}", 5);
    assert_eq!(settled.num_redelivered, 0, "等过一个 ack_wait 后仍不得出现重投（这正是修复前缺的证据）");
    assert_eq!(settled.num_ack_pending, 0);
    assert_eq!(settled.ack_floor_stream_seq, 5, "应答水位必须推进到第 5 条");

    // ---- ③ 毒消息 term 后重投次数停止增长 ----
    publish(&source_impl, &format!("agf.ingest.{IDENTITY}"), &[Vec::new()]).await;
    let before_poison = source_impl.consumer_stats(&recv.consumer_plan().durable_name).await.expect("consumer 统计");
    let poison_batch = recv.poll_batch(8).await.expect("拉取毒消息");
    assert_eq!(poison_batch, 1, "毒消息被拉取");
    let after_poison = source_impl.consumer_stats(&recv.consumer_plan().durable_name).await.expect("consumer 统计");
    println!("[live] 毒消息前 = {before_poison:?}");
    println!("[live] 毒消息后 = {after_poison:?}（num_redelivered 必须停止增长）");
    assert_eq!(
        after_poison.num_redelivered, before_poison.num_redelivered,
        "term 之后服务端不得再重投（先 nak/不 ack 会让它随 ack_wait 增长）"
    );
    assert_eq!(after_poison.num_ack_pending, 0, "term 后不存在未应答消息");
    assert_eq!(after_poison.num_pending, 0);
    tokio::time::sleep(Duration::from_secs(4)).await;
    let poison_settled = source_impl.consumer_stats(&recv.consumer_plan().durable_name).await.expect("consumer 统计");
    assert_eq!(
        poison_settled.num_redelivered, before_poison.num_redelivered,
        "等过一个 ack_wait 后毒消息仍不得被重投: {poison_settled:?}"
    );

    // ---- ④ 新连接（等价于进程重启）：durable 从 ack 水位续投，已 ack 的不重投 ----
    drop(recv);
    drop(source_impl);
    let reopened = Arc::new(AsyncNatsJetStream::connect(urls.clone()).await.expect("重新连接真实 NATS"));
    let (recv2, sink2) = receiver(Arc::clone(&reopened));
    let resumed = recv2.provision().await.expect("重启后 provision（必须复用同一 durable）");
    println!("[live] 重启后 provision = {resumed:?}");
    assert_eq!(resumed.consumer_count, 1, "重启后仍然只有一个 durable consumer");
    // 停服期间投递 2 条
    publish(
        &reopened,
        &format!("agf.ingest.{IDENTITY}"),
        &[b"{\"message\":\"after restart 0\"}".to_vec(), b"{\"message\":\"after restart 1\"}".to_vec()],
    )
    .await;
    let pulled2 = recv2.poll_batch(32).await.expect("重启后 pull");
    let persisted2 = sink2.events().expect("事件快照").len();
    println!("[live] 重启后续投拉取 {pulled2} 条，新 sink 落库 {persisted2} 条（新 sink 是空的，所以必须是 2）");
    assert_eq!(pulled2, 2, "已 ack 的 6 条不得重投，只有停服期间的 2 条（+0 毒消息已被 term）");
    assert_eq!(persisted2, 2);
    let final_stats = reopened.consumer_stats(&recv2.consumer_plan().durable_name).await.expect("consumer 统计");
    println!("[live] 重启后最终 consumer 统计 = {final_stats:?}");
    assert_eq!(final_stats.num_ack_pending, 0);
    assert_eq!(final_stats.num_pending, 0);

    // 收尾：删掉本用例自己的 stream（不动其它 stream）
    reopened.delete_stream(&identity_stream).await.expect("清理测试 stream");
    println!("[live] 已删除测试 stream {identity_stream}");
}

/// ack/nak/term 三个动作在**真机**上的语义差异：`nak` 会重投并累加 `num_redelivered`。
///
/// 这条用例是上面"归零"断言的**正向对照**——否则"num_redelivered 一直是 0"也可能只是
/// 统计口径没生效。
#[tokio::test]
#[ignore = "需要真实 NATS + JetStream（AGF_E2E_JETSTREAM_URL）"]
async fn nak_is_observable_as_redelivery_on_the_server() {
    let Some(urls) = jetstream_url() else {
        println!("[live] {ENV_URL} 未设置，跳过");
        return;
    };
    let identity = "e2e-nak";
    let subject = format!("agf.ingest.{identity}");
    let stream_name = StreamPlan::for_identity(identity, &subject).name.clone();
    let source_impl = Arc::new(AsyncNatsJetStream::connect(urls).await.expect("连接真实 NATS"));
    let _ = source_impl.delete_stream(&stream_name).await;
    let (pipeline, _sink) = pipeline_and_sink();
    let mut consumer = ConsumerPlan::for_identity(identity, JetMode::Pull, &subject, 8);
    consumer.ack_wait_secs = 30;
    let recv = JetStreamReceiver::new(
        pipeline,
        log_source(),
        StreamPlan::for_identity(identity, &subject),
        consumer,
        Arc::clone(&source_impl) as Arc<dyn agf_ingest::jetstream::JetStreamSource>,
    );
    recv.provision().await.expect("provision");
    publish(&source_impl, &subject, &[b"{\"message\":\"nak me\"}".to_vec()]).await;

    // 手动取一条并 nak（走的是 `JetStreamSource::ack` 的真实实现）
    use agf_ingest::jetstream::JetStreamSource as _;
    let messages = source_impl.fetch_batch(&recv.consumer_plan().durable_name, 1, Duration::from_millis(500)).await;
    let messages = messages.expect("fetch_batch");
    assert_eq!(messages.len(), 1);
    source_impl
        .ack(&recv.consumer_plan().durable_name, &messages[0], JetAckAction::Nak)
        .await
        .expect("nak 必须真的发到服务端");
    let after_nak = source_impl.consumer_stats(&recv.consumer_plan().durable_name).await.expect("consumer 统计");
    println!("[live] nak 后统计 = {after_nak:?}");
    assert_eq!(after_nak.num_ack_pending, 0, "nak 立即解除 ack pending（消息回到 pending 等待重投）");
    assert_eq!(after_nak.num_pending, 1, "nak 后消息重新可投");

    // 再次取回：delivered 递增 ⇒ 服务端确实重投了
    let again = source_impl
        .fetch_batch(&recv.consumer_plan().durable_name, 1, Duration::from_millis(500))
        .await
        .expect("fetch_batch #2");
    assert_eq!(again.len(), 1, "nak 之后必须能重新拉到同一条");
    println!("[live] nak 重投的 delivered = {}", again[0].delivered);
    assert!(again[0].delivered >= 2, "重投次数必须递增（delivered={}）", again[0].delivered);
    source_impl
        .ack(&recv.consumer_plan().durable_name, &again[0], JetAckAction::Term)
        .await
        .expect("term 必须真的发到服务端");
    let after_term = source_impl.consumer_stats(&recv.consumer_plan().durable_name).await.expect("consumer 统计");
    println!("[live] term 后统计 = {after_term:?}");
    assert_eq!(after_term.num_pending, 0);
    assert_eq!(after_term.num_ack_pending, 0);
    source_impl.delete_stream(&stream_name).await.expect("清理测试 stream");
}
