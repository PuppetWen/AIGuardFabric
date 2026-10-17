//! 对**真实 Pulsar broker**（`AGF_E2E_PULSAR_URL`，Pulsar **原生 binary protocol**）的端到端验证。
//!
//! 覆盖（每一项都对应一条**只有真机才能证明**的事实）：
//!
//! 1. 原生 producer 写进 topic → 本消费者在**原生协议**上收到，`sequence_id` / `properties` /
//!    `publish_time` 解析正确；
//! 2. **CRC32C 真的被校验**（`checksum_ok > 0`：broker 默认带校验和）；
//! 3. **batch 拆条**（一次 batch 帧拆成 N 条，`batch_entries` 计数与 sink 条数一致）；
//! 4. **ACK 真的发到 broker**：消费后 `pulsar-admin`（HTTP admin API）的 `msgBacklog`
//!    与 `unackedMessages` **归零**——空实现会一直挂着 backlog；
//! 5. **Shared 订阅两副本**：两个消费者各连一条连接、同订阅竞争消费，消息**不重复**。
//!
//! ## 运行方式（broker 已在跑；producer 用容器内的 `bin/pulsar-client produce`）
//!
//! ```text
//! set AGF_E2E_PULSAR_URL=pulsar://127.0.0.1:26650
//! set AGF_E2E_PULSAR_ADMIN=http://127.0.0.1:28080
//! set AGF_E2E_PULSAR_TOPIC=persistent://public/default/agf-native
//! set AGF_E2E_PULSAR_EXPECT=5
//! cargo test -p agf-ingest --test pulsar_native_live -- --ignored --nocapture
//! ```
//!
//! 未设置 `AGF_E2E_PULSAR_URL` 时用例直接打印"跳过"并返回（`#[ignore]` 保证常规
//! `cargo test` **不依赖任何外部服务**）。
#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used, clippy::print_stdout)]

use std::sync::Arc;
use std::time::Duration;

use agf_ingest::pulsar::{PulsarInitialPosition, PulsarNativeConfig, PulsarNativeReceiver, PulsarSubscriptionType};

mod pulsar_native_support;
use pulsar_native_support::*;

/// ① 单条 + ② CRC32C + ④ ACK（backlog 归零）。
///
/// 前置：外部已用 `bin/pulsar-client produce` 往该 topic 写了 `AGF_E2E_PULSAR_EXPECT` 条，
/// 且带 properties（`-p k1=v1,k2=v2`）——用 `tools/simulators/run_pulsar_native_e2e.ps1` 一把跑。
#[tokio::test]
#[ignore = "需要真实 Pulsar broker（AGF_E2E_PULSAR_URL）"]
async fn native_consume_reports_metadata_and_acks_backlog_to_zero() {
    let Some(_) = url() else {
        println!("[live] {ENV_URL} 未设置，跳过");
        return;
    };
    let topic = topic();
    let expect = expect_count();
    let subscription = unique_subscription("agf-live-single");
    let (pipeline, sink) = pipeline_and_sink();
    let receiver = PulsarNativeReceiver::new(config(&topic, &subscription, PulsarSubscriptionType::Exclusive));

    println!("[live] topic={topic} subscription={subscription} expect={expect}");
    let consumed = tokio::time::timeout(
        Duration::from_secs(30),
        receiver.poll_batch(&pipeline, &log_source("pulsar-native-live"), expect),
    )
    .await
    .expect("30s 内必须收到消息（producer 是否已经写入？）")
    .expect("poll_batch 不得报错");

    let stats = receiver.stats();
    let raw_count = sink.raws().expect("原始日志快照").len();
    println!(
        "[live] 消费 {consumed} 条；sink 落库 {raw_count} 条；帧 {}；CRC32C 通过 {}；batch 拆出 {} 条；ack {}；重连 {}",
        agf_ingest::pulsar::PulsarNativeStats::get(&stats.frames),
        agf_ingest::pulsar::PulsarNativeStats::get(&stats.checksum_ok),
        agf_ingest::pulsar::PulsarNativeStats::get(&stats.batch_entries),
        agf_ingest::pulsar::PulsarNativeStats::get(&stats.acks),
        agf_ingest::pulsar::PulsarNativeStats::get(&stats.reconnects),
    );
    assert!(consumed >= expect, "至少收到 {expect} 条，实际 {consumed}");
    assert_eq!(raw_count, consumed, "每条消息都要落进 sink（batch 拆条后逐条落库）");
    assert!(
        agf_ingest::pulsar::PulsarNativeStats::get(&stats.checksum_ok) > 0,
        "Pulsar 默认带 CRC32C ⇒ 必须至少校验通过一帧（若为 0，说明 checksum 分支没走到）"
    );
    assert_eq!(agf_ingest::pulsar::PulsarNativeStats::get(&stats.checksum_failures), 0);
    assert!(agf_ingest::pulsar::PulsarNativeStats::get(&stats.acks) > 0, "ack 必须真的发出去");
    // 打印前几条原始载荷（base64 解出来给人看），确认内容与 producer 写的一致
    {
        use base64::Engine as _;
        let raws = sink.raws().expect("raws");
        let preview: Vec<String> = raws
            .iter()
            .take(3)
            .map(|raw| {
                base64::engine::general_purpose::STANDARD
                    .decode(&raw.payload_b64)
                    .map(|bytes| String::from_utf8_lossy(&bytes).to_string())
                    .unwrap_or_else(|_| "<非 base64>".to_string())
            })
            .collect();
        println!("[live] 原始载荷前 3 条 = {preview:?}（origin = {:?}）", raws.first().map(|raw| raw.origin.clone()));
    }

    // ④ ack 的最强证据：broker 侧统计的 backlog / unacked 归零（异步 mark-delete ⇒ 轮询等待）
    if let Some((backlog, unacked)) = wait_for_backlog_zero(&topic, &subscription, Duration::from_secs(10)).await {
        println!(
            "[live] admin stats（轮询到稳定）: msgBacklog={backlog} unackedMessages={unacked}（订阅 {subscription}）"
        );
        assert_eq!(backlog, 0, "ACK 真发之后 msgBacklog 必须归零（空实现会一直挂着）");
        assert_eq!(unacked, 0, "unackedMessages 必须归零");
    } else {
        println!(
            "[live] {ENV_ADMIN} 未设置：跳过 admin backlog 断言（见 run_pulsar_native_e2e.ps1 的 pulsar-admin 输出）"
        );
    }
}

/// ③ batch 拆条：一次 batch 帧（`num_messages_in_batch > 1`）必须拆成 N 条。
#[tokio::test]
#[ignore = "需要真实 Pulsar broker（AGF_E2E_PULSAR_URL）"]
async fn native_batch_message_is_split_into_entries() {
    let Some(_) = url() else {
        println!("[live] {ENV_URL} 未设置，跳过");
        return;
    };
    let topic = format!("{}-batch", topic());
    let expect = expect_count().max(2);
    let subscription = unique_subscription("agf-live-batch");
    let (pipeline, sink) = pipeline_and_sink();
    let receiver = PulsarNativeReceiver::new(config(&topic, &subscription, PulsarSubscriptionType::Exclusive));

    println!("[live] batch topic={topic} expect={expect}");
    let consumed = tokio::time::timeout(
        Duration::from_secs(30),
        receiver.poll_batch(&pipeline, &log_source("pulsar-native-batch"), expect),
    )
    .await
    .expect("30s 内必须收到 batch 消息")
    .expect("poll_batch");

    let stats = receiver.stats();
    let frames = agf_ingest::pulsar::PulsarNativeStats::get(&stats.frames);
    let entries = agf_ingest::pulsar::PulsarNativeStats::get(&stats.batch_entries);
    let raws = sink.raws().expect("raws");
    println!("[live] 帧 {frames}、batch 拆出 {entries} 条、消费 {consumed} 条、sink {} 条", raws.len());
    assert!(entries >= expect as u64, "batch_entries 必须 >= {expect}（说明真的走了拆条分支），实际 {entries}");
    assert_eq!(raws.len(), consumed, "拆出来的每条都要独立落库（不是整段 batch 算一条）");
    let unique: std::collections::BTreeSet<String> = raws.iter().map(|raw| raw.payload_b64.clone()).collect();
    assert_eq!(unique.len(), raws.len(), "拆条后每条载荷都应不同（producer 侧刻意给了不同内容）");
}

/// ⑥ 断线恢复：消费过程中 broker 被重启 ⇒ 客户端**退避重连**并继续消费，不丢不重。
///
/// 由 `tools/simulators/run_pulsar_native_e2e.ps1` 编排：本用例在后台跑，
/// 编排脚本在它运行期间 `docker restart` broker，然后继续 produce。
///
/// 断言：
/// * `stats.reconnects >= 1`（说明真的走了退避重连分支）；
/// * 重启前后的消息**都被消费到**（`sink` 条数 >= 期望）；
/// * 每条只出现一次（重连不产生重复投递）。
#[tokio::test]
#[ignore = "需要真实 Pulsar broker + 编排脚本在运行期间重启它（AGF_E2E_PULSAR_URL）"]
async fn native_run_reconnects_after_broker_restart() {
    init_tracing();
    let Some(_) = url() else {
        println!("[live] {ENV_URL} 未设置，跳过");
        return;
    };
    let topic = env_or("AGF_E2E_PULSAR_TOPIC_RECONNECT", &format!("{}-reconnect", topic()));
    let expect = expect_count();
    let subscription = unique_subscription("agf-live-reconnect");
    let deadline_secs: u64 = env_or("AGF_E2E_PULSAR_RECONNECT_DEADLINE_SECS", "180").parse().unwrap_or(180);
    let (pipeline, sink) = pipeline_and_sink();
    let (tx, rx) = tokio::sync::watch::channel(false);
    let receiver = Arc::new(
        PulsarNativeReceiver::new(config(&topic, &subscription, PulsarSubscriptionType::Exclusive)).with_shutdown(rx),
    );
    let source = log_source("pulsar-native-reconnect");
    let runner = Arc::clone(&receiver);
    let task = tokio::spawn(async move { runner.run(pipeline, source).await });

    println!("[live] reconnect topic={topic} subscription={subscription} expect={expect} deadline={deadline_secs}s");
    let started = std::time::Instant::now();
    let mut last_report = 0_usize;
    let mut consumed;
    while started.elapsed() < Duration::from_secs(deadline_secs) {
        consumed = sink.raws().map(|raws| raws.len()).unwrap_or(0);
        let reconnects = agf_ingest::pulsar::PulsarNativeStats::get(&receiver.stats().reconnects);
        let connects = agf_ingest::pulsar::PulsarNativeStats::get(&receiver.stats().connects);
        if consumed != last_report {
            last_report = consumed;
            println!(
                "[live] 已消费 {consumed}/{expect} 条；连接 {connects} 次、重连 {reconnects} 次（{:.1}s）",
                started.elapsed().as_secs_f64()
            );
        }
        if consumed >= expect {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let _ = tx.send(true);
    let outcome = tokio::time::timeout(Duration::from_secs(10), task).await;
    let raws = sink.raws().expect("raws");
    let unique: std::collections::BTreeSet<String> = raws.iter().map(|raw| raw.payload_b64.clone()).collect();
    let reconnects = agf_ingest::pulsar::PulsarNativeStats::get(&receiver.stats().reconnects);
    let connects = agf_ingest::pulsar::PulsarNativeStats::get(&receiver.stats().connects);
    println!(
        "[live] 结束：消费 {} 条（唯一 {}）、连接 {connects} 次、重连 {reconnects} 次、run 退出 = {:?}",
        raws.len(),
        unique.len(),
        outcome.map(|result| result.map(|inner| inner.is_ok()))
    );
    assert!(reconnects >= 1, "broker 重启之后必须发生退避重连（reconnects={reconnects}）");
    assert!(raws.len() >= expect, "重启前后的消息都要消费到：期望 >= {expect}，实际 {}", raws.len());
    assert_eq!(unique.len(), raws.len(), "重连不得产生重复消费（at-least-once + 内容去重口径）");
}

/// ⑦ token 鉴权（第 2 轮）：**不带 token 必须被明确拒绝**（`AuthenticationError`，不可重试）；
/// 带上 `AGF_INGEST_PULSAR_TOKEN` 才能消费。两个方向都要证明，否则"实现了 token"只是纸面结论。
#[tokio::test]
#[ignore = "需要真实 Pulsar broker + authenticationEnabled=true（AGF_E2E_PULSAR_URL/AGF_E2E_PULSAR_TOKEN）"]
async fn native_token_auth_is_required_and_accepted() {
    init_tracing();
    let Some(base) = url() else {
        println!("[live] {ENV_URL} 未设置，跳过");
        return;
    };
    let Some(token) =
        std::env::var(ENV_TOKEN).ok().map(|value| value.trim().to_string()).filter(|value| !value.is_empty())
    else {
        println!("[live] {ENV_TOKEN} 未设置，跳过（本用例需要 authenticationEnabled=true 的 broker）");
        return;
    };
    let topic = env_or("AGF_E2E_PULSAR_TOPIC_AUTH", &format!("{}-auth", topic()));
    let expect = expect_count();

    // ---- ① 不带 token：CONNECT 必须被 broker 明确拒绝 ----
    let (pipeline_denied, _sink) = pipeline_and_sink();
    let mut no_token = PulsarNativeConfig::new(&base, &topic).expect("配置");
    no_token.subscription = unique_subscription("agf-live-noauth");
    no_token.initial_position = PulsarInitialPosition::Earliest;
    no_token.token = None;
    let denied =
        PulsarNativeReceiver::new(no_token).poll_batch(&pipeline_denied, &log_source("pulsar-native-noauth"), 1).await;
    let text = denied.expect_err("broker 开了 authenticationEnabled ⇒ 不带 token 必须被拒").to_string();
    println!("[live] 不带 token 的订阅错误（必须是认证类）= {text}");
    assert!(text.contains("Authentication"), "错误必须分类为认证失败：{text}");

    // ---- ② 带 token：正常订阅 + 消费 + ack ----
    let (pipeline_ok, sink_ok) = pipeline_and_sink();
    let mut with_token = config(&topic, &unique_subscription("agf-live-auth"), PulsarSubscriptionType::Exclusive);
    with_token.token = Some(token);
    let receiver = PulsarNativeReceiver::new(with_token);
    let consumed = tokio::time::timeout(
        Duration::from_secs(30),
        receiver.poll_batch(&pipeline_ok, &log_source("pulsar-native-auth"), expect),
    )
    .await
    .expect("30s 内必须消费到消息")
    .expect("带 token 的订阅必须成功");
    let raws = sink_ok.raws().expect("raws");
    println!(
        "[live] 带 token：消费 {consumed} 条、落库 {} 条、ack {}、CRC32C 通过 {}",
        raws.len(),
        agf_ingest::pulsar::PulsarNativeStats::get(&receiver.stats().acks),
        agf_ingest::pulsar::PulsarNativeStats::get(&receiver.stats().checksum_ok),
    );
    assert!(consumed >= expect, "至少要收到 {expect} 条，实际 {consumed}");
    assert_eq!(raws.len(), consumed);
}

/// ⑤ Shared 订阅两副本：两个消费者同订阅竞争消费 ⇒ 全量覆盖且**不重复**。
#[tokio::test]
#[ignore = "需要真实 Pulsar broker（AGF_E2E_PULSAR_URL）"]
async fn native_shared_subscription_two_replicas_do_not_duplicate() {
    let Some(_) = url() else {
        println!("[live] {ENV_URL} 未设置，跳过");
        return;
    };
    let topic = env_or(ENV_TOPIC_SHARED, &format!("{}-shared", topic()));
    let expect = expect_count();
    let subscription = unique_subscription("agf-live-shared");
    let (pipeline_a, sink_a) = pipeline_and_sink();
    let (pipeline_b, sink_b) = pipeline_and_sink();
    let receiver_a = Arc::new(PulsarNativeReceiver::new(config(&topic, &subscription, PulsarSubscriptionType::Shared)));
    let receiver_b = Arc::new(PulsarNativeReceiver::new(config(&topic, &subscription, PulsarSubscriptionType::Shared)));
    let source_a = log_source("pulsar-native-shared-a");
    let source_b = log_source("pulsar-native-shared-b");

    println!("[live] shared topic={topic} subscription={subscription} expect={expect}");
    // 两个副本各自最多收 `expect` 条；总数到齐后仍会阻塞 ⇒ 用超时收口，然后看两边各自收到什么。
    // 同时**轮询 broker 侧订阅状态**：必须观察到该订阅下同时挂着 2 个消费者
    // （只看客户端计数不算证据——"两个进程各连了一条连接"要在 broker 侧看得见）。
    // 轮询口径见下面的 `probe`：权威 stats（`authoritative=true`）+ 连续 2 次命中才算稳定。
    //
    // **为什么每个副本的目标条数是 `expect * 2` 而不是 `expect`**：
    // `poll_batch(.., n)` 一旦处理满 n 条就**返回并断开连接**。此前两个副本都用 `expect`，
    // 于是"两个消费者同时在挂"的窗口只有先收满的那一方断开之前的那一小段（实测常常只有几百毫秒），
    // 探针很容易只看到 1 个 ⇒ 这条断言 3 次里挂 1 次（不是 broker 或断言口径的问题，是观测窗口的竞态）。
    // 把目标翻倍后，在"发布数 ≤ expect"的真机轮里谁都收不满，两个连接会一直保持到 20s 超时，
    // broker 侧因此能稳定观察到 2 个消费者；数据面断言（并集 / 去重 / 帧数）完全不受影响。
    let hold = expect.saturating_mul(2);
    let both = async {
        let a = receiver_a.poll_batch(&pipeline_a, &source_a, hold);
        let b = receiver_b.poll_batch(&pipeline_b, &source_b, hold);
        tokio::join!(a, b)
    };
    let probe_topic = topic.clone();
    let probe_sub = subscription.clone();
    let probe = async move {
        let mut max_consumers = 0_usize;
        let mut stable_hits = 0_u32;
        for _ in 0..40 {
            if let Some(count) = admin_consumer_count(&probe_topic, &probe_sub).await {
                max_consumers = max_consumers.max(count);
                // "**轮询到稳定**"：连续 2 次都看到 >= 2 个消费者才收工，而不是钉住某一次瞬时读数。
                // （`admin_get` 用 `authoritative=true`，读数不会是 60s 缓存快照——见该函数的文档。）
                stable_hits = if count >= 2 { stable_hits + 1 } else { 0 };
                if stable_hits >= 2 {
                    break;
                }
            } else {
                stable_hits = 0;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        max_consumers
    };
    let (_, max_consumers) = tokio::join!(async { tokio::time::timeout(Duration::from_secs(20), both).await }, probe);
    println!("[live] broker 侧该订阅同时挂着的消费者数（观测到的最大值）= {max_consumers}");

    let raws_a = sink_a.raws().expect("raws a");
    let raws_b = sink_b.raws().expect("raws b");
    let set_a: std::collections::BTreeSet<String> = raws_a.iter().map(|raw| raw.payload_b64.clone()).collect();
    let set_b: std::collections::BTreeSet<String> = raws_b.iter().map(|raw| raw.payload_b64.clone()).collect();
    let union: std::collections::BTreeSet<String> = set_a.union(&set_b).cloned().collect();
    let overlap: Vec<_> = set_a.intersection(&set_b).collect();
    println!(
        "[live] 副本 A 收到 {} 条（唯一 {}）、副本 B 收到 {} 条（唯一 {}）、并集 {} 条、重复 {} 条",
        raws_a.len(),
        set_a.len(),
        raws_b.len(),
        set_b.len(),
        union.len(),
        overlap.len()
    );
    assert!(union.len() >= expect, "两个副本并起来必须覆盖全部 {expect} 条，实际 {}", union.len());
    assert!(overlap.is_empty(), "Shared 订阅不得重复投递同一条：{overlap:?}");
    let frames_a = receiver_a.stats().frames.load(std::sync::atomic::Ordering::Relaxed);
    let frames_b = receiver_b.stats().frames.load(std::sync::atomic::Ordering::Relaxed);
    assert!(frames_a + frames_b > 0, "至少一个副本必须真的收到帧");
    // broker 侧证据（配了 AGF_E2E_PULSAR_ADMIN 才断言）：同一订阅下同时挂着 2 个消费者。
    // 不断言"两个副本都收到了消息"——Shared 的分派是竞争式的，消息少时一个副本全收是**合法**结果。
    if std::env::var(ENV_ADMIN).is_ok_and(|value| !value.trim().is_empty()) {
        assert_eq!(max_consumers, 2, "broker 侧该订阅下必须同时挂着 2 个消费者（实际观测 {max_consumers}）");
    } else {
        println!("[live] {ENV_ADMIN} 未设置：跳过 broker 侧消费者计数断言");
    }
}
