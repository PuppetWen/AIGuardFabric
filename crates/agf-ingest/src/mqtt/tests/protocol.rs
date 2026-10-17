//! MQTT 协议版本与 **MQTT 5 专有特性**用例：版本映射、会话过期/Clean Start、Topic Alias、
//! Receive Maximum、订阅选项、用户属性、以及"3.1.1 上配 v5 项必须报错"的降级口径。

use super::*;

use rumqttc::v5::mqttbytes::v5::RetainForwardRule;

/// 测试用环境变量表（拥有所有权，避免与临时集合的生命周期纠缠）。
struct EnvMap(BTreeMap<String, String>);

impl EnvMap {
    fn new(pairs: &[(&str, &str)]) -> Self {
        Self(pairs.iter().map(|(key, value)| ((*key).to_string(), (*value).to_string())).collect())
    }

    fn get(&self, key: &str) -> Option<String> {
        self.0.get(key).cloned()
    }
}

impl EnvMap {
    fn config(&self) -> MqttProtocolConfig {
        MqttProtocolConfig::from_lookup(|key| self.get(key))
    }
}

#[test]
fn protocol_version_parsing_and_defaults() {
    // 默认 3.1.1（既有行为不变）
    let empty = EnvMap::new(&[]);
    let default = empty.config();
    assert_eq!(default.version, MqttProtocolVersion::V3_1_1);
    assert!(!default.version_configured);
    assert!(!default.version.is_v5());
    assert_eq!(default.version.as_str(), "3.1.1");
    assert!(default.v5.clean_start, "默认 clean session/start = true（与既有 set_clean_session(true) 一致）");
    assert!(default.v5.session_expiry_secs.is_none());
    assert_eq!(default.v5.topic_alias_max, 0);
    assert!(default.v5.receive_maximum.is_none());
    assert!(default.v5.subscribe.is_default());
    assert!(default.v5.user_properties.is_empty());
    assert!(default.validate().is_ok(), "默认配置必须自洽");
    assert!(default.describe().contains("clean_session=true"), "{}", default.describe());

    // 版本写法宽松：3.1.1 / 3 / 311 / v3.1.1 / 4 与 5 / 5.0 / v5
    for text in ["3.1.1", "3.1", "311", "3", "v3.1.1", "4"] {
        assert_eq!(MqttProtocolVersion::parse(text), Some(MqttProtocolVersion::V3_1_1), "{text}");
    }
    for text in ["5", "5.0", "v5", "50", "5.0.0"] {
        assert_eq!(MqttProtocolVersion::parse(text), Some(MqttProtocolVersion::V5), "{text}");
    }
    assert_eq!(MqttProtocolVersion::parse("6"), None);
    assert_eq!(MqttProtocolVersion::parse(""), None);

    // 显式 v5
    let v5 = EnvMap::new(&[(ENV_PROTOCOL_VERSION, "5")]).config();
    assert_eq!(v5.version, MqttProtocolVersion::V5);
    assert!(v5.version_configured);
    assert!(v5.version.is_v5());
    assert!(v5.validate().is_ok());
    assert!(v5.describe().contains("MQTT 5"), "{}", v5.describe());

    // 无法识别的版本：只 warn + 回退 3.1.1，但**记住"配过"**（描述里如实写出）
    let broken = EnvMap::new(&[(ENV_PROTOCOL_VERSION, "9.9")]).config();
    assert_eq!(broken.version, MqttProtocolVersion::V3_1_1);
    assert!(broken.version_configured, "配过就必须记为已配置（不静默）");
    assert!(broken.describe().contains("回退"), "{}", broken.describe());
}

#[test]
fn v5_features_map_from_env() {
    let env = EnvMap::new(&[
        (ENV_PROTOCOL_VERSION, "5"),
        (ENV_SESSION_EXPIRY_SECS, "3600"),
        (ENV_CLEAN_START, "0"),
        (ENV_TOPIC_ALIAS_MAX, "10"),
        (ENV_RECEIVE_MAXIMUM, "20"),
        (ENV_SUBSCRIBE_NOLOCAL, "1"),
        (ENV_SUBSCRIBE_RETAIN_AS_PUBLISHED, "yes"),
        (ENV_SUBSCRIBE_RETAIN_HANDLING, "1"),
        (ENV_USER_PROPERTIES, "site=shanghai,collector=agf-ingest"),
    ]);
    let config = env.config();
    assert!(config.version.is_v5());
    assert!(config.validate().is_ok(), "{:?}", config.validate());
    assert_eq!(config.v5.session_expiry_secs, Some(3600));
    assert!(!config.v5.clean_start);
    assert_eq!(config.v5.topic_alias_max, 10);
    assert_eq!(config.v5.receive_maximum, Some(20));
    assert!(config.v5.subscribe.no_local);
    assert!(config.v5.subscribe.retain_as_published);
    assert_eq!(config.v5.subscribe.retain_handling, RetainHandling::OnNewSubscribe);
    assert_eq!(config.v5.subscribe.retain_handling.as_u8(), 1);
    assert_eq!(
        config.v5.user_properties,
        vec![("site".to_string(), "shanghai".to_string()), ("collector".to_string(), "agf-ingest".to_string()),]
    );
    let described = config.describe();
    assert!(described.contains("会话过期=3600s"), "{described}");
    assert!(described.contains("CleanStart=false"), "{described}");
    assert!(described.contains("TopicAlias≤10"), "{described}");
    assert!(described.contains("ReceiveMaximum=20"), "{described}");
    assert!(described.contains("NoLocal=true"), "{described}");
    assert!(described.contains("RetainAsPublished=true"), "{described}");
    assert!(described.contains("CONNECT 用户属性=2 条"), "{described}");

    // 每项都必须被记为"显式配置"（版本兼容性校验依赖它）
    for key in [
        ENV_SESSION_EXPIRY_SECS,
        ENV_TOPIC_ALIAS_MAX,
        ENV_RECEIVE_MAXIMUM,
        ENV_SUBSCRIBE_NOLOCAL,
        ENV_SUBSCRIBE_RETAIN_AS_PUBLISHED,
        ENV_SUBSCRIBE_RETAIN_HANDLING,
        ENV_USER_PROPERTIES,
    ] {
        assert!(config.v5.configured.contains(&key), "缺少 {key}: {:?}", config.v5.configured);
    }
}

#[test]
fn v5_only_features_on_v311_are_rejected_loudly() {
    // 3.1.1 上配 v5 专有项：**明确报错**（而不是静默忽略），调用方写进 /readyz notes
    for key in [
        (ENV_SESSION_EXPIRY_SECS, "300"),
        (ENV_TOPIC_ALIAS_MAX, "5"),
        (ENV_RECEIVE_MAXIMUM, "10"),
        (ENV_SUBSCRIBE_NOLOCAL, "1"),
        (ENV_SUBSCRIBE_RETAIN_AS_PUBLISHED, "1"),
        (ENV_SUBSCRIBE_RETAIN_HANDLING, "2"),
        (ENV_USER_PROPERTIES, "k=v"),
    ] {
        let env = EnvMap::new(&[key]);
        let config = env.config();
        let result = config.validate();
        assert!(matches!(result, Err(DomainError::Config(_))), "{key:?} 在 3.1.1 上必须报错: {result:?}");
        let message = result.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(message.contains(key.0), "错误里必须点名配置项: {message}");
        assert!(message.contains("绝不静默忽略"), "{message}");
    }
    // 同一些项在 v5 上就是合法的
    let env = EnvMap::new(&[(ENV_PROTOCOL_VERSION, "5"), (ENV_SUBSCRIBE_NOLOCAL, "1"), (ENV_TOPIC_ALIAS_MAX, "5")]);
    assert!(env.config().validate().is_ok());

    // Clean Start **不算** v5 专有：3.1.1 上映射为 clean_session=false，合法
    let env = EnvMap::new(&[(ENV_CLEAN_START, "0")]);
    let config = env.config();
    assert!(config.validate().is_ok(), "{:?}", config.validate());
    assert!(!config.v5.clean_start);
    assert!(config.describe().contains("clean_session=false"), "{}", config.describe());
    assert!(config.v5.v5_only_configured().is_empty(), "clean start 不是 v5 专有项");
}

#[test]
fn illegal_v5_values_fall_back_without_silence() {
    let env = EnvMap::new(&[
        (ENV_PROTOCOL_VERSION, "5"),
        (ENV_SESSION_EXPIRY_SECS, "abc"),
        (ENV_TOPIC_ALIAS_MAX, "70000"),
        (ENV_RECEIVE_MAXIMUM, "0"),
        (ENV_SUBSCRIBE_RETAIN_HANDLING, "7"),
        (ENV_USER_PROPERTIES, "good=1,broken,=novalue"),
    ]);
    let config = env.config();
    assert!(config.version.is_v5());
    assert_eq!(config.v5.session_expiry_secs, None, "非法数字按未配置处理");
    assert_eq!(config.v5.topic_alias_max, 0, "u16 越界按未配置处理");
    assert_eq!(config.v5.receive_maximum, None, "Receive Maximum=0 非法（MQTT 5 要求 ≥1）");
    assert_eq!(config.v5.subscribe.retain_handling, RetainHandling::OnEverySubscribe, "非法 RetainHandling 回退 0");
    assert_eq!(config.v5.user_properties, vec![("good".to_string(), "1".to_string())], "坏项跳过、好项保留");
    // 配了（哪怕值非法）仍要能通过"v3.1.1 兼容性"检查时点出问题：这里 version=5，天然自洽
    assert!(config.validate().is_ok());
}

#[test]
fn subscribe_options_and_retain_handling_mapping() {
    assert_eq!(RetainHandling::default(), RetainHandling::OnEverySubscribe);
    assert_eq!(RetainHandling::parse("0"), Some(RetainHandling::OnEverySubscribe));
    assert_eq!(RetainHandling::parse("1"), Some(RetainHandling::OnNewSubscribe));
    assert_eq!(RetainHandling::parse("2"), Some(RetainHandling::Never));
    assert_eq!(RetainHandling::parse("3"), None);
    assert_eq!(RetainHandling::Never.as_u8(), 2);
    assert!(SubscribeOptions::default().is_default());
    assert!(!SubscribeOptions { no_local: true, ..SubscribeOptions::default() }.is_default());
    let described = SubscribeOptions { no_local: true, retain_as_published: true, ..Default::default() }.describe();
    assert!(described.contains("NoLocal=true"), "{described}");
    assert!(described.contains("RetainHandling=每次订阅都下发保留消息(0)"), "{described}");

    // Retain Handling → rumqttc::v5 的 RetainForwardRule（下发到 SUBSCRIBE 报文的位）
    assert_eq!(retain_forward_rule(RetainHandling::OnEverySubscribe), RetainForwardRule::OnEverySubscribe);
    assert_eq!(retain_forward_rule(RetainHandling::OnNewSubscribe), RetainForwardRule::OnNewSubscribe);
    assert_eq!(retain_forward_rule(RetainHandling::Never), RetainForwardRule::Never);
}
