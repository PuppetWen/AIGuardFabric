//! MQTT 装配段（由 `spawn_extra_receivers.rs` 按块拆分，纯搬移、逻辑不变）。
//!
//! 覆盖订阅接线（`MqttReceiver::from_source`）与加固项运行态标注（TLS / 共享订阅 / 遗嘱）。
use super::*;

impl ExtraReceiverCtx<'_> {
    /// ---- MQTT ----
    ///
    /// 返回 `(broker, topic)`：加固标注段要用它们判断"本进程到底有没有启用 MQTT"
    /// （原实现靠同一函数体里的局部变量，抽成 `async fn` 后只能显式返回）。
    pub(super) async fn mqtt(&mut self) -> (String, String) {
        let source_identity = self.identity.clone();
        let pipeline = self.pipeline;
        let metrics = self.metrics;
        let listeners = &mut *self.listeners;
        let broker = env_or("AGF_INGEST_MQTT_BROKER", "");
        let topic = env_or("AGF_INGEST_MQTT_TOPIC", "");
        if broker.is_empty() || topic.is_empty() {
            listeners.note("MQTT 未启用：需同时配置 AGF_INGEST_MQTT_BROKER 与 AGF_INGEST_MQTT_TOPIC".to_string());
        } else {
            let source = source_with(&source_identity, IngestProtocol::Mqtt, "mqtt", |connection| {
                connection.endpoint = Some(broker.clone());
                connection.topic = Some(topic.clone());
                connection.headers.insert("qos".to_string(), env_or("AGF_INGEST_MQTT_QOS", "1"));
                if let Ok(client_id) = std::env::var("AGF_INGEST_MQTT_CLIENT_ID") {
                    if !client_id.trim().is_empty() {
                        connection.headers.insert("client.id".to_string(), client_id.trim().to_string());
                    }
                }
                if let (Ok(user), Ok(pass)) =
                    (std::env::var("AGF_INGEST_MQTT_USERNAME"), std::env::var("AGF_INGEST_MQTT_PASSWORD"))
                {
                    if !user.trim().is_empty() {
                        connection.headers.insert("username".to_string(), user.trim().to_string());
                        connection.headers.insert("password".to_string(), pass);
                    }
                }
            });
            match MqttReceiver::from_source(Arc::clone(pipeline), &source) {
                Ok(receiver) => {
                    let receiver = Arc::new(receiver.with_counters(metrics.counters("mqtt")));
                    tracing::info!(broker = %broker, topic = %topic, "MQTT 订阅接收器已启用（断线退避重连）");
                    let mqtt_pipeline = Arc::clone(pipeline);
                    tokio::spawn(async move {
                        if let Err(e) = receiver.start(mqtt_pipeline, source).await {
                            tracing::warn!(error = %e, "MQTT 订阅任务退出");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "MQTT 未启用（配置非法，其余能力不受影响）");
                    listeners.note(format!("MQTT 未启用：{e}"));
                }
            }
        }
        (broker, topic)
    }

    /// === MQTT 加固（TLS / 共享订阅 / 遗嘱）：独立块，只补运行态说明 ===
    ///
    /// 加固项的**生效**位置在 `agf_ingest::mqtt`（`MqttReceiver::from_source` 直接读
    /// `AGF_INGEST_MQTT_TLS*` / `..._WILL_*` / `..._RECONNECT_*`，并按 `mqtts://` scheme 自动开 TLS）；
    /// 这里只把"本进程实际会用的形态"如实写进 `/readyz` 的 notes，不改变上面的接线逻辑。
    pub(super) fn annotate_mqtt_hardening(&mut self, broker: &str, topic: &str) {
        let listeners = &mut *self.listeners;
        if !broker.is_empty() && !topic.is_empty() {
            let qos = env_or("AGF_INGEST_MQTT_QOS", "1").trim().parse::<u8>().unwrap_or(1);
            let endpoint = agf_ingest::mqtt::parse_endpoint(broker).ok();
            let tls_config = match &endpoint {
                Some(endpoint) => agf_ingest::mqtt::MqttTlsConfig::from_env().for_scheme(endpoint),
                None => agf_ingest::mqtt::MqttTlsConfig::from_env(),
            };
            let tls_text = match tls_config.validate() {
                Ok(()) if tls_config.enabled => tls_config.describe(),
                Ok(()) => "明文 TCP（未启用 TLS）".to_string(),
                Err(e) => format!("配置非法：{e}"),
            };
            let shared_text = match agf_ingest::mqtt::plan_subscribe(topic, qos) {
                Ok(plan) => match &plan.shared {
                    Some(shared) => format!(
                        "共享订阅 topic={} group={} filter={}（同组竞争消费）",
                        plan.topic, shared.group, shared.filter
                    ),
                    None => "独占订阅（非共享）".to_string(),
                },
                Err(e) => format!("订阅主题非法：{e}"),
            };
            let will_text = agf_ingest::mqtt::MqttWill::from_env()
                .map_or_else(|| "未配置（客户端异常断开不会发出告警消息）".to_string(), |will| will.describe());
            let (initial, max) = agf_ingest::mqtt::BackoffPolicy::from_env().bounds_secs();
            listeners.note(format!(
                "MQTT 加固：TLS={tls_text}；{shared_text}；遗嘱={will_text}；退避重连={initial}s→{max}s"
            ));
        }
    }
}
