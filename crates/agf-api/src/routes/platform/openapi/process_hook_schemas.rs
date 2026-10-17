//! 严格三类请求和脱敏回执；字节预算独立于 JSON 字符数量。
use serde_json::{Value, json};
fn uuid() -> Value {
    json!({"type":"string","format":"uuid","not":{"enum":["00000000-0000-0000-0000-000000000000"]}})
}
fn fixed(value: Value) -> Value {
    json!({"enum":[value]})
}
fn nullable(value: Value) -> Value {
    json!({"anyOf":[value,{"type":"null"}]})
}
fn hash() -> Value {
    json!({"type":"string","pattern":"^[0-9a-fA-F]{64}$"})
}
fn request(mode: &str) -> Value {
    let mut properties = json!({"request_id":uuid(),"agent_id":uuid(),"mode":fixed(json!(mode)),
        "source":{"enum":["linux_sched_exec","windows_wmi_start"]},
        "executable_b64":{"type":"string","contentEncoding":"base64","maxLength":5464,"x-max-decoded-bytes":4096,"x-no-nul":true},
        "arguments":{"type":"array","maxItems":0,"items":{"type":"string"}},
        "executable_sha256":fixed(Value::Null),"pid":nullable(json!({"type":"integer","minimum":1,"maximum":u32::MAX})),
        "uid":nullable(json!({"type":"integer","minimum":0,"maximum":u32::MAX})),
        "monotonic_ns":nullable(json!({"type":"integer","minimum":0,"maximum":u64::MAX})),
        "truncated":{"type":"boolean"},"lost":fixed(json!(0))});
    let mut required =
        vec!["request_id", "agent_id", "mode", "source", "executable_b64", "arguments", "truncated", "lost"];
    match mode {
        "launch" => {
            properties["source"] = fixed(json!("managed_launcher"));
            properties["executable_b64"]["minLength"] = json!(4);
            properties["executable_b64"]["x-decoded-utf8"] = json!(true);
            properties["arguments"] = json!({"type":"array","maxItems":64,"x-max-total-utf8-bytes":16384,
                "items":{"type":"string","maxLength":4096,"x-max-utf8-bytes":4096,"x-no-nul":true}});
            properties["executable_sha256"] = hash();
            required.push("executable_sha256");
            for key in ["pid", "uid", "monotonic_ns"] {
                properties[key] = fixed(Value::Null);
            }
            properties["truncated"] = fixed(json!(false));
        }
        "observe" => {
            properties["executable_b64"]["minLength"] = json!(4);
            properties["pid"] = json!({"type":"integer","minimum":1,"maximum":u32::MAX});
            required.push("pid");
        }
        _ => {
            properties["executable_b64"] = fixed(json!(""));
            for key in ["pid", "uid", "monotonic_ns"] {
                properties[key] = fixed(Value::Null);
            }
            properties["truncated"] = fixed(json!(false));
            properties["lost"] = json!({"type":"integer","minimum":1,"maximum":u64::MAX});
        }
    }
    json!({"type":"object","additionalProperties":false,"required":required,"properties":properties})
}
pub(super) fn register(schemas: &mut Value) {
    schemas["ProcessRequest"] = json!({"oneOf":[request("launch"),request("observe"),request("loss")],
        "discriminator":{"propertyName":"mode"}});
    let properties = json!({"request_id":uuid(),"agent_id":uuid(),"request_sha256":hash(),
        "mode":{"enum":["launch","observe","loss"]},"launch_allowed":{"type":"boolean"},
        "action":{"enum":["allow","deny","audit","quota","redact","throttle","degrade","circuitbreak","isolate","approval"]},
        "dry_run":{"type":"boolean"},"audit_committed":fixed(json!(true)),"audit_id":uuid(),
        "expires_at_ms":{"type":"integer","description":"原提交时间加3000ms；过期不启动"},"enforced":fixed(json!(false))});
    let required = properties.as_object().map(|fields| fields.keys().cloned().collect::<Vec<_>>()).unwrap_or_default();
    schemas["ProcessReceipt"] = json!({"type":"object","additionalProperties":false,"required":required,"properties":properties,
        "description":"原请求绑定的已审计准入；服务端不宣称 OS 已执行或阻断。观察/loss 永不允许启动。"});
}
