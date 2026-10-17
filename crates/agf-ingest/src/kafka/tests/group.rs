//! 消费者组协议的单测：分配器（range/roundrobin）、分配不变量、rebalance 判据、
//! 消费者协议编解码、起始 offset 决策、组配置开关（**全部离线，不需要 broker**）。

use super::*;

/// `[(topic, partition)]` 的便捷构造。
fn parts(topic: &str, partitions: &[i32]) -> Vec<(String, i32)> {
    partitions.iter().map(|partition| (topic.to_string(), *partition)).collect()
}

/// topic → 分区表的便捷构造。
fn topic_map(entries: &[(&str, &[i32])]) -> BTreeMap<String, Vec<i32>> {
    entries.iter().map(|(topic, partitions)| ((*topic).to_string(), partitions.to_vec())).collect()
}

/// 分配不变量：**无重叠**（同一分区只给一个成员）。
fn assert_no_overlap(plan: &AssignmentPlan) {
    let mut seen = BTreeMap::new();
    for (member, assigned) in plan {
        for key in assigned {
            assert!(seen.insert(key.clone(), member.clone()).is_none(), "分区 {key:?} 被重复分配");
        }
    }
}

/// 分配不变量：**无遗漏**（成员订阅的 topic 的每个分区都有人负责）。
fn assert_full_coverage(plan: &AssignmentPlan, members: &[GroupMember], topics: &BTreeMap<String, Vec<i32>>) {
    verify_plan(plan, members, topics).unwrap_or_else(|e| panic!("分配计划违反不变量: {e}"));
}

#[test]
fn range_single_member_takes_all_partitions() {
    let members = vec![GroupMember::new("m1", vec!["logs".to_string()])];
    let topics = topic_map(&[("logs", &[0, 1, 2, 3])]);
    let plan = assign_partitions(GroupAssignor::Range, &members, &topics);
    assert_eq!(plan["m1"], parts("logs", &[0, 1, 2, 3]));
    assert_full_coverage(&plan, &members, &topics);
}

#[test]
fn range_two_members_split_evenly_without_overlap() {
    let members =
        vec![GroupMember::new("m1", vec!["logs".to_string()]), GroupMember::new("m2", vec!["logs".to_string()])];
    let topics = topic_map(&[("logs", &[0, 1, 2, 3])]);
    let plan = assign_partitions(GroupAssignor::Range, &members, &topics);
    assert_eq!(plan["m1"], parts("logs", &[0, 1]));
    assert_eq!(plan["m2"], parts("logs", &[2, 3]));
    assert_no_overlap(&plan);
    assert_full_coverage(&plan, &members, &topics);
}

#[test]
fn range_assigns_remainder_to_earliest_members() {
    // 3 个成员分 5 个分区：范围分配语义 = 前 2 个各拿 2 个、最后一个拿 1 个
    let members = vec![
        GroupMember::new("m1", vec!["logs".to_string()]),
        GroupMember::new("m2", vec!["logs".to_string()]),
        GroupMember::new("m3", vec!["logs".to_string()]),
    ];
    let topics = topic_map(&[("logs", &[0, 1, 2, 3, 4])]);
    let plan = assign_partitions(GroupAssignor::Range, &members, &topics);
    assert_eq!(plan["m1"], parts("logs", &[0, 1]));
    assert_eq!(plan["m2"], parts("logs", &[2, 3]));
    assert_eq!(plan["m3"], parts("logs", &[4]));
    assert_full_coverage(&plan, &members, &topics);
}

#[test]
fn more_members_than_partitions_leaves_idle_members() {
    // 5 个成员只有 2 个分区：2 个成员各拿 1 个，其余成员**空手**（不是报错）
    let members: Vec<GroupMember> =
        (0..5).map(|index| GroupMember::new(format!("m{index}"), vec!["logs".to_string()])).collect();
    let topics = topic_map(&[("logs", &[0, 1])]);
    let plan = assign_partitions(GroupAssignor::Range, &members, &topics);
    assert_eq!(plan["m0"], parts("logs", &[0]));
    assert_eq!(plan["m1"], parts("logs", &[1]));
    for index in 2..5 {
        assert!(plan[&format!("m{index}")].is_empty(), "多余的成员不应分到分区");
    }
    assert_no_overlap(&plan);
    assert_full_coverage(&plan, &members, &topics);
}

#[test]
fn round_robin_covers_all_partitions_across_topics() {
    let members = vec![
        GroupMember::new("m1", vec!["a".to_string(), "b".to_string()]),
        GroupMember::new("m2", vec!["b".to_string()]),
        GroupMember::new("m3", vec!["a".to_string()]),
    ];
    let topics = topic_map(&[("a", &[0, 1]), ("b", &[0, 1])]);
    let plan = assign_partitions(GroupAssignor::RoundRobin, &members, &topics);
    assert_no_overlap(&plan);
    assert_full_coverage(&plan, &members, &topics);
    // m2 只订阅 b ⇒ 不会拿到 a 的任何分区
    assert!(plan["m2"].iter().all(|(topic, _)| topic == "b"));
}

#[test]
fn partition_count_growth_is_fully_absorbed() {
    // 分区数变化：4 → 6，重新分配后仍然无重叠无遗漏（新增分区被吸收）
    let members =
        vec![GroupMember::new("m1", vec!["logs".to_string()]), GroupMember::new("m2", vec!["logs".to_string()])];
    let before = assign_partitions(GroupAssignor::Range, &members, &topic_map(&[("logs", &[0, 1, 2, 3])]));
    assert_eq!(before.values().map(Vec::len).sum::<usize>(), 4);
    let after = assign_partitions(GroupAssignor::Range, &members, &topic_map(&[("logs", &[0, 1, 2, 3, 4, 5])]));
    assert_eq!(after["m1"], parts("logs", &[0, 1, 2]));
    assert_eq!(after["m2"], parts("logs", &[3, 4, 5]));
    assert_full_coverage(&after, &members, &topic_map(&[("logs", &[0, 1, 2, 3, 4, 5])]));
}

#[test]
fn verify_plan_rejects_overlap_and_gap() {
    let members =
        vec![GroupMember::new("m1", vec!["logs".to_string()]), GroupMember::new("m2", vec!["logs".to_string()])];
    let topics = topic_map(&[("logs", &[0, 1])]);
    // 重叠：两个成员都拿到 0
    let mut overlap: AssignmentPlan = BTreeMap::new();
    overlap.insert("m1".to_string(), parts("logs", &[0, 1]));
    overlap.insert("m2".to_string(), parts("logs", &[0]));
    assert!(verify_plan(&overlap, &members, &topics).is_err(), "重叠必须被拒绝");
    // 遗漏：分区 1 没人拿
    let mut gap: AssignmentPlan = BTreeMap::new();
    gap.insert("m1".to_string(), parts("logs", &[0]));
    gap.insert("m2".to_string(), Vec::new());
    assert!(verify_plan(&gap, &members, &topics).is_err(), "遗漏必须被拒绝");
    // 正常计划通过
    let good = assign_partitions(GroupAssignor::Range, &members, &topics);
    assert!(verify_plan(&good, &members, &topics).is_ok());
}

#[test]
fn rebalance_triggers_cover_the_three_heartbeat_error_codes() {
    assert_eq!(rebalance_trigger(error_code::REBALANCE_IN_PROGRESS), Some(RebalanceTrigger::RebalanceInProgress));
    assert_eq!(rebalance_trigger(error_code::ILLEGAL_GENERATION), Some(RebalanceTrigger::IllegalGeneration));
    assert_eq!(rebalance_trigger(error_code::UNKNOWN_MEMBER_ID), Some(RebalanceTrigger::UnknownMemberId));
    assert_eq!(rebalance_trigger(0), None, "错误码 0（成功）不触发 rebalance");
    assert_eq!(rebalance_trigger(3), None, "未知错误码不误判成 rebalance");
    // 只有"成员 id 失效"才必须换新 id，其余保留 member_id 重新入组
    assert!(RebalanceTrigger::UnknownMemberId.requires_new_member_id());
    assert!(RebalanceTrigger::FencedInstanceId.requires_new_member_id());
    assert!(!RebalanceTrigger::RebalanceInProgress.requires_new_member_id());
    assert!(!RebalanceTrigger::IllegalGeneration.requires_new_member_id());
}

#[test]
fn heartbeat_and_poll_deadlines_follow_the_configured_intervals() {
    assert!(!heartbeat_due(2_999, 3_000));
    assert!(heartbeat_due(3_000, 3_000));
    assert!(heartbeat_due(9_999, 3_000));
    assert!(!poll_interval_exceeded(299_999, 300_000));
    assert!(poll_interval_exceeded(300_001, 300_000));
    assert!(!poll_interval_exceeded(u64::MAX, 0), "max.poll.interval.ms = 0 表示不检查");
}

#[test]
fn group_timing_validation_rejects_dangerous_combinations() {
    assert!(validate_group_timing(45_000, 3_000, 300_000).is_ok());
    // 心跳过于频繁（>= session/3）⇒ 网络抖动会被误判成成员死亡
    assert!(validate_group_timing(45_000, 15_000, 300_000).is_err());
    assert!(validate_group_timing(45_000, 0, 300_000).is_err());
    assert!(validate_group_timing(0, 3_000, 300_000).is_err());
    // max.poll.interval.ms 小于 session.timeout.ms ⇒ 每轮都在退组重入
    assert!(validate_group_timing(45_000, 3_000, 30_000).is_err());
    // 0 = 关闭该检查
    assert!(validate_group_timing(45_000, 3_000, 0).is_ok());
}

#[test]
fn consumer_protocol_subscription_round_trips() {
    let topics = vec!["logs".to_string(), "audit".to_string()];
    let encoded = encode_subscription_metadata(&topics);
    assert!(!encoded.is_empty(), "订阅元数据编码不能为空");
    assert_eq!(decode_subscription_metadata(&encoded).unwrap_or_default(), topics);
    // 空主题列表也能往返（不 panic、不吞异常）
    let empty = encode_subscription_metadata(&[]);
    assert_eq!(decode_subscription_metadata(&empty).unwrap_or_default(), Vec::<String>::new());
    // 垃圾字节 ⇒ 显式报错，而不是静默返回空订阅（否则会退化成"订阅不到任何 topic"）
    assert!(decode_subscription_metadata(&[0xff, 0xff, 0xff, 0xff]).is_err());
}

#[test]
fn consumer_protocol_assignment_round_trips() {
    let assigned = parts("logs", &[0, 2, 3]);
    let encoded = encode_assignment_metadata(&assigned);
    assert!(!encoded.is_empty(), "分配编码不能为空");
    let mut decoded = decode_assignment_metadata(&encoded).unwrap_or_default();
    decoded.sort();
    let mut expected = assigned;
    expected.sort();
    assert_eq!(decoded, expected);
    assert!(decode_assignment_metadata(&[0xff, 0xff]).is_err());
}

/// 十六进制字面量 → 字节（与官方实现的 golden vector 对照用；奇数长度/非法字符按 0 处理即可，
/// 只服务于下面的常量，不参与生产路径）。
fn unhex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digits = std::str::from_utf8(pair).unwrap_or("00");
            u8::from_str_radix(digits, 16).unwrap_or(0)
        })
        .collect()
}

/// 字节 → 小写十六进制。
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

#[test]
fn consumer_protocol_bytes_match_the_official_java_encoder() {
    // golden vector：`kafka-clients 3.9.0` 的
    // `ConsumerProtocol.serializeSubscription(new Subscription(List.of("agf-e2e-group")), (short) 0)`
    // 与 `serializeAssignment(new Assignment(List.of(new TopicPartition("agf-e2e-group", 0))), (short) 0)`
    // 的输出（由 tools/simulators/out/kafkalibs/AgfConsumerProtocolProbe.java 打印，
    // 也就是 `MessageUtil.toVersionPrefixedByteBuffer(0, message)` 的字节）。
    //
    // 这条断言是**真机 bug 的回归闸**：曾经少写头 2 字节的版本前缀 ⇒ 协调器解析成员元数据时抛
    // `RuntimeException`，JoinGroup 响应被永久扣住（详见 `codec` 模块文档）。
    let expected_subscription = concat!(
        "0000",                       // 版本前缀（int16 BE = 0）
        "00000001",                   // topics 数组长度 = 1
        "000d",                       // topic 名长度 = 13
        "6167662d6532652d67726f7570", // "agf-e2e-group"
        "ffffffff",                   // user_data = null
    );
    let encoded = encode_subscription_metadata(&["agf-e2e-group".to_string()]);
    assert_eq!(hex(&encoded), expected_subscription, "订阅元数据必须与官方 v0 编码逐字节一致");
    assert_eq!(encoded.len(), 25);

    let expected_assignment = concat!(
        "0000",                       // 版本前缀
        "00000001",                   // assigned_partitions 数组长度 = 1
        "000d",                       // topic 名长度 = 13
        "6167662d6532652d67726f7570", // "agf-e2e-group"
        "00000001",                   // partitions 数组长度 = 1
        "00000000",                   // 分区 0
        "ffffffff",                   // user_data = null
    );
    let encoded = encode_assignment_metadata(&[("agf-e2e-group".to_string(), 0)]);
    assert_eq!(hex(&encoded), expected_assignment, "分配元数据必须与官方 v0 编码逐字节一致");
    assert_eq!(encoded.len(), 33);
}

#[test]
fn consumer_protocol_metadata_needs_the_version_prefix() {
    // 旧实现的字节形态（= kafka-protocol 的裸正文，**没有**版本前缀）：必须显式报错。
    let legacy_subscription = unhex(concat!("00000001", "000d", "6167662d6532652d67726f7570", "ffffffff",));
    assert_eq!(legacy_subscription.len(), 23, "这正是历史上发上线的 23 字节形态");
    assert!(
        decode_subscription_metadata(&legacy_subscription).is_err(),
        "缺版本前缀的元数据必须被拒绝（接受它就等于把响应卡死的 bug 放回来）"
    );
    let legacy_assignment =
        unhex(concat!("00000001", "000d", "6167662d6532652d67726f7570", "00000001", "00000000", "ffffffff"));
    assert!(decode_assignment_metadata(&legacy_assignment).is_err(), "分配侧同样必须拒绝");

    // 前缀本身太短 / 版本号超出支持范围 ⇒ 各自的显式错误（不是"静默返回空订阅"）
    let short = decode_subscription_metadata(&[0x00]).err().map(|e| e.to_string()).unwrap_or_default();
    assert!(short.contains("版本前缀"), "长度不足必须指向版本前缀: {short}");
    let unsupported = unhex(concat!("0007", "00000001", "000d", "6167662d6532652d67726f7570", "ffffffff"));
    let unsupported = decode_subscription_metadata(&unsupported).err().map(|e| e.to_string()).unwrap_or_default();
    assert!(unsupported.contains("不受支持"), "版本号超范围必须显式报错: {unsupported}");
}

#[test]
fn consumer_protocol_reads_a_java_members_v3_metadata() {
    // Java 客户端默认写 **v3**（多出 owned_partitions / generation_id / rack_id）。
    // 本接收器不实现粘性分配，但作为组长**必须**能读出它订阅的 topic —— 与协调器同一口径：
    // 前缀给版本，正文一律按 v0（所有后续版本的公共前缀）解析。
    let java_v3 = unhex(concat!(
        "0003", // 版本前缀 = 3
        "00000001",
        "000d",
        "6167662d6532652d67726f7570",
        "ffffffff", // topics + user_data
        "00000000", // owned_partitions = []
        "ffffffff", // generation_id = -1
        "ffff",     // rack_id = null
    ));
    assert_eq!(java_v3.len(), 35);
    assert_eq!(
        decode_subscription_metadata(&java_v3).unwrap_or_default(),
        vec!["agf-e2e-group".to_string()],
        "Java 成员的 v3 订阅元数据必须能读出 topic"
    );
    // 官方实现写出的 v3 分配体（含 user_data=null）同样要能读
    let java_assignment_v3 =
        unhex(concat!("0003", "00000001", "000d", "6167662d6532652d67726f7570", "00000001", "00000000", "ffffffff"));
    assert_eq!(decode_assignment_metadata(&java_assignment_v3).unwrap_or_default(), parts("agf-e2e-group", &[0]));
}

#[test]
fn committed_offset_wins_over_start_from() {
    // 组内已提交 ⇒ 用它（"重启进程从已提交 offset 续消费"的口径）
    assert_eq!(choose_start_offset(Some(42), 0).0, 42);
    assert_eq!(choose_start_offset(Some(0), 7).0, 0, "offset 0 是合法已提交位置");
    // 未提交（-1 / None）⇒ 回落到 start_from 定位结果
    assert_eq!(choose_start_offset(Some(-1), 7).0, 7);
    assert_eq!(choose_start_offset(None, 7).0, 7);
    assert!(choose_start_offset(None, 7).1.contains("start_from"));
    assert!(choose_start_offset(Some(42), 0).1.contains("已提交"));
}

#[test]
fn group_id_absent_means_legacy_local_cursor_path() {
    // **降级判定的核心断言**：没配 `_GROUP_ID` ⇒ 不启用组协议（走 rskafka 本地游标，行为不变）。
    // 用一个绝不会出现的 env 前缀，避免污染真实进程环境（env 只读，不写）。
    assert!(KafkaGroupConfig::from_env("AGF_INGEST_UNSET_PREFIX_FOR_GROUP_TEST", "agf-ingest").is_none());
    let default = KafkaGroupConfig::default();
    assert!(!default.enabled(), "默认配置必须**关闭**组协议");
    assert_eq!(default.assignor, GroupAssignor::Range);
    assert_eq!(default.session_timeout_ms, 45_000);
    assert_eq!(default.heartbeat_interval_ms, 3_000);
    assert_eq!(default.max_poll_interval_ms, 300_000);
    // 显式给了 group.id 才算启用
    let enabled = KafkaGroupConfig { group_id: "agf-live".to_string(), ..KafkaGroupConfig::default() };
    assert!(enabled.enabled());
    assert!(enabled.describe().contains("agf-live"));
    // 分配器文本解析（大小写/连字符都不敏感）
    assert_eq!(GroupAssignor::parse("ROUND-ROBIN"), Some(GroupAssignor::RoundRobin));
    assert_eq!(GroupAssignor::parse("roundrobin"), Some(GroupAssignor::RoundRobin));
    assert_eq!(GroupAssignor::parse("range"), Some(GroupAssignor::Range));
    assert_eq!(GroupAssignor::parse("sticky"), None);
}
