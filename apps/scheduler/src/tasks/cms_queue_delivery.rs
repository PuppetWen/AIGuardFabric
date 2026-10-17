use super::{Id, TaskOutcome};
use super::{
    cms_queue_client::{BASE, Client},
    cms_queue_outbox::{Run, fingerprint},
    cms_queue_task::{CmsQueueConfig, number},
};
use agf_core::ids::deterministic_id;
use serde_json::{Value, json};

// 平台 CMS 回执对对象字段递归排序后计算哈希；本地 outbox 仍校验原始持久字节。
fn platform_fingerprint(value: &Value) -> anyhow::Result<String> {
    fn canonical(value: &Value) -> Value {
        match value {
            Value::Object(map) => Value::Object(
                map.iter()
                    .map(|(key, value)| (key.clone(), canonical(value)))
                    .collect::<std::collections::BTreeMap<_, _>>()
                    .into_iter()
                    .collect(),
            ),
            Value::Array(items) => Value::Array(items.iter().map(canonical).collect()),
            other => other.clone(),
        }
    }
    fingerprint(&canonical(value))
}

pub(super) fn check(receipt: &Value, wire: &Value, purpose: &str, intent: &Value) -> anyhow::Result<()> {
    anyhow::ensure!(
        receipt["id"] == wire["request_id"]
            && receipt["purpose"] == purpose
            && receipt["inputHash"] == platform_fingerprint(wire)?
            && receipt["immutableIntent"] == true
            && receipt["automaticRetry"] == false,
        "CMS 平台原回执与不可变 wire 不匹配"
    );
    let items = receipt["items"].as_array().ok_or_else(|| anyhow::anyhow!("CMS 逐指标回执缺失"))?;
    let payloads = intent["items"].as_array().ok_or_else(|| anyhow::anyhow!("CMS 原指标缺失"))?;
    let enqueue: Id = serde_json::from_value(intent["enqueueId"].clone())?;
    let tenant: super::TenantId = serde_json::from_value(intent["tenant"].clone())?;
    anyhow::ensure!(
        items.len() == payloads.len() && receipt["itemIds"].as_array().is_some_and(|ids| ids.len() == items.len()),
        "CMS 指标数量不匹配"
    );
    for (index, (item, payload)) in items.iter().zip(payloads).enumerate() {
        let id = deterministic_id("agf.cms.queue.item.v1", &format!("{tenant}:{enqueue}:{index}"));
        anyhow::ensure!(
            item["id"] == id.to_string()
                && receipt["itemIds"][index] == id.to_string()
                && item["enqueueRequestId"] == enqueue.to_string()
                && item["name"] == payload["name"]
                && item["payloadHash"] == platform_fingerprint(payload)?,
            "CMS 指标身份/原 payload 哈希不匹配"
        );
    }
    Ok(())
}
pub(super) async fn deliver(
    client: &Client,
    config: &CmsQueueConfig,
    run: &Run,
    intent: &Value,
    queued: Value,
) -> anyhow::Result<TaskOutcome> {
    let items = queued["items"].as_array().ok_or_else(|| anyhow::anyhow!("CMS 逐指标队列缺失"))?;
    let source = items.first().ok_or_else(|| anyhow::anyhow!("CMS 指标队列为空"))?["originalSource"].clone();
    anyhow::ensure!(items.iter().all(|item| item["originalSource"] == source), "CMS 原指标源不同");
    let mocked = source["transportMode"] == "mock" && source["mocked"] == true;
    if !mocked && !config.confirm_live {
        return Ok(TaskOutcome::degraded(format!(
            "CMS {} 条原指标已入持久队列；Live 送云未确认，未发送，providerWriteAttempted=false",
            items.len()
        )));
    }
    anyhow::ensure!(mocked || source["transportMode"] == "live", "CMS 非正式传输模式不能由生产调度发送");
    let send_id: Id = serde_json::from_value(intent["sendId"].clone())?;
    let existing = client.original(send_id).await?;
    let wire = if let Some(wire) = run.read("send")? {
        wire
    } else {
        anyhow::ensure!(existing.is_none(), "CMS 原 send 存在但 wire 缺失");
        let wire = json!({"request_id":send_id,"expected_generation":number(&client.get(BASE).await?,"generation")?,
            "item_ids":queued["itemIds"],"confirm_live":!mocked && config.confirm_live});
        run.save("send", &wire)?;
        wire
    };
    anyhow::ensure!(
        wire["request_id"] == send_id.to_string() && wire["item_ids"] == queued["itemIds"],
        "CMS 原 send wire 不匹配"
    );
    let receipt = if let Some(value) = existing {
        value
    } else {
        anyhow::ensure!(
            run.read("send-started")?.is_none(),
            "CMS send 曾开始但原回执缺失：状态未知，仅允许查原编号，禁止重送云"
        );
        run.save("send-started", &json!({"wireHash":fingerprint(&wire)?}))?;
        client.post(&format!("{BASE}/send"), &wire).await?
    };
    check(&receipt, &wire, "send", intent)?;
    // Only local settlement is recoverable; this endpoint cannot contact the provider.
    for item in receipt["items"].as_array().ok_or_else(|| anyhow::anyhow!("CMS 逐指标回执缺失"))? {
        if item["canRecoverLocal"] == true {
            let id: Id = serde_json::from_value(item["id"].clone())?;
            client.post(&format!("{BASE}/items/{id}/recover-local"), &json!({})).await?;
        }
    }
    let settled = client.original(send_id).await?.ok_or_else(|| anyhow::anyhow!("CMS 原 send 回执消失，禁止重送"))?;
    check(&settled, &wire, "send", intent)?;
    outcome(run, &settled, mocked)
}
fn outcome(run: &Run, receipt: &Value, mocked: bool) -> anyhow::Result<TaskOutcome> {
    let attempts = receipt["originalAttempts"].as_array().ok_or_else(|| anyhow::anyhow!("CMS 原尝试回执缺失"))?;
    let total = receipt["itemIds"].as_array().ok_or_else(|| anyhow::anyhow!("CMS 原指标编号缺失"))?.len();
    anyhow::ensure!(attempts.len() == total, "CMS 尝试数量不完整");
    let accepted = attempts
        .iter()
        .filter(|attempt| attempt["completionState"] == "complete" && attempt["outcome"]["delivery"] == "accepted")
        .count();
    anyhow::ensure!(
        attempts.iter().all(|attempt| attempt["requestId"] == receipt["id"]
            && attempt["mocked"] == mocked
            && (!mocked || attempt["providerWriteAttempted"] == false)),
        "CMS Mock/尝试来源不匹配"
    );
    let states = attempts
        .iter()
        .map(|attempt| {
            format!(
                "{}:{}",
                attempt["completionState"].as_str().unwrap_or("unknown"),
                attempt["outcome"]["delivery"].as_str().unwrap_or("unknown")
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let note = format!(
        "CMS 持久队列接受 {accepted}/{total}；{}；原请求 {}；逐项 {states}；实际审计由平台结算，consumerApplied=unknown，不自动重试",
        if mocked {
            "Mock，未真实触达云监控，providerWriteAttempted=false"
        } else {
            "云接受以原逐项回执为准"
        },
        receipt["id"]
    );
    let mut result = if accepted == total {
        run.save(
            "accepted",
            &json!({"requestId":receipt["id"],"inputHash":receipt["inputHash"],"accepted":accepted,"mocked":mocked}),
        )?;
        TaskOutcome::ok(note)
    } else {
        TaskOutcome::failed(note)
    };
    result.degraded = mocked;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tasks::cms_queue_outbox::hash;

    #[test]
    fn platform_hash_matches_canonical_nested_objects_without_changing_original_bytes() -> anyhow::Result<()> {
        let value = json!({"z":{"b":2,"a":{"y":true,"x":false}},"a":[{"z":2,"a":1},3]});
        let original = serde_json::to_vec(&value)?;
        let expected = hash(br#"{"a":[{"a":1,"z":2},3],"z":{"a":{"x":false,"y":true},"b":2}}"#);
        assert_eq!(platform_fingerprint(&value)?, expected);
        assert_ne!(fingerprint(&value)?, expected, "回归输入必须覆盖 preserve_order 下的非规范字段顺序");
        assert_eq!(serde_json::to_vec(&value)?, original, "不得重写原 wire 或 outbox payload");
        Ok(())
    }

    #[test]
    fn platform_hash_preserves_array_order_and_rejects_changed_values() -> anyhow::Result<()> {
        let original = json!({"items":[{"z":2,"a":1},{"z":4,"a":3}]});
        let reordered_keys = json!({"items":[{"a":1,"z":2},{"a":3,"z":4}]});
        let reordered_items = json!({"items":[{"a":3,"z":4},{"a":1,"z":2}]});
        let changed_value = json!({"items":[{"a":1,"z":99},{"a":3,"z":4}]});
        assert_eq!(platform_fingerprint(&original)?, platform_fingerprint(&reordered_keys)?);
        assert_ne!(platform_fingerprint(&original)?, platform_fingerprint(&reordered_items)?);
        assert_ne!(platform_fingerprint(&original)?, platform_fingerprint(&changed_value)?);
        Ok(())
    }

    #[test]
    fn receipt_check_accepts_platform_hash_and_rejects_wire_or_payload_tampering() -> anyhow::Result<()> {
        let tenant = super::super::TenantId::default_tenant();
        let enqueue = Id::new();
        let payload = json!({"kind":"metric","name":"owned-metric","value":7.0,
            "dimensions":{"zone":"owned","service":"agf-scheduler"},"at":"2026-10-10T00:00:00Z"});
        let wire = json!({"request_id":enqueue,"configuration_version":1,"expected_generation":0,
            "items":[payload],"initialize_mock_fixture":true});
        let intent = json!({"enqueueId":enqueue,"tenant":tenant,"items":[payload]});
        let item = deterministic_id("agf.cms.queue.item.v1", &format!("{tenant}:{enqueue}:0"));
        let mut receipt = json!({"id":enqueue,"purpose":"enqueue","inputHash":platform_fingerprint(&wire)?,
            "immutableIntent":true,"automaticRetry":false,"itemIds":[item],
            "items":[{"id":item,"enqueueRequestId":enqueue,"name":"owned-metric",
                "payloadHash":platform_fingerprint(&payload)?}]});
        check(&receipt, &wire, "enqueue", &intent)?;
        let mut changed_wire = wire.clone();
        changed_wire["configuration_version"] = json!(2);
        assert!(check(&receipt, &changed_wire, "enqueue", &intent).is_err());
        let mut changed_intent = intent.clone();
        changed_intent["items"][0]["value"] = json!(8.0);
        assert!(check(&receipt, &wire, "enqueue", &changed_intent).is_err());
        receipt["items"][0]["payloadHash"] = json!("0".repeat(64));
        assert!(check(&receipt, &wire, "enqueue", &intent).is_err());
        Ok(())
    }
}
