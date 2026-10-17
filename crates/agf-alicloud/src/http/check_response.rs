//! 由 `http.rs` 拆分：`check_response` 等 5 个函数（纯搬移，逻辑不变）。
use super::*;

/// 校验响应：非 2xx 或带业务错误码时映射为领域错误。
///
/// # Errors
/// 见 [`map_error_code`]。
pub fn check_response(response: &RpcResponse) -> DomainResult<()> {
    if response.is_business_success() {
        return Ok(());
    }
    if let Some(code) = response.code() {
        let message = response.message().unwrap_or("远端未提供 Message");
        let request_id = response.body.get("RequestId").and_then(serde_json::Value::as_str);
        return Err(map_error_code(code, message, request_id));
    }
    if !(200..300).contains(&response.status) {
        return Err(DomainError::DependencyUnavailable {
            dependency: "alicloud.rpc".to_string(),
            cause: format!("HTTP {} 且响应体无有效错误码", response.status),
        });
    }
    Err(DomainError::Validation("云 API 返回失败状态但未提供有效错误码".into()))
}

/// 复数键别名（阿里云同一份数据在不同接口里用不同复数形式）。
///
/// 例如报警历史的单数键是 `AlarmHistory`，但阿里云返回的复数键是 `AlarmHistories`
/// （不是朴素加 `s` 得到的 `AlarmHistorys`）。这里把不规则复数显式列出来，
/// 避免"只支持规则复数"的解析器在老接口上静默返回空数组。
#[must_use]
pub fn plural_alias(key: &str) -> &'static str {
    match key {
        "AlarmHistory" => "AlarmHistories",
        "VpcEndpoint" => "VpcEndpoints",
        "SecurityGroupRule" => "SecurityGroupRules",
        "JobExecution" => "JobExecutions",
        _ => "",
    }
}

/// 从响应里取数组字段（兼容阿里云三种返回形态）：
///
/// 1. `{ "Xxx": [ ... ] }`（单数键直接是数组）；
/// 2. `{ "Xxxs": { "Xxx": [ ... ] } }`（复数键包单数键）；
/// 3. `{ "Alias": { "Alias": [ ... ] } }`（不规则复数，见 [`plural_alias`]）。
#[must_use]
pub fn json_array<'a>(body: &'a serde_json::Value, keys: &[&str]) -> Vec<&'a serde_json::Value> {
    for key in keys {
        if let Some(array) = body.get(*key).and_then(serde_json::Value::as_array) {
            return array.iter().collect();
        }
        let plural = format!("{key}s");
        if let Some(inner) = body.get(&plural).and_then(|v| v.get(*key)).and_then(serde_json::Value::as_array) {
            return inner.iter().collect();
        }
        if let Some(inner) = body.get(&plural).and_then(|v| v.get(&plural)).and_then(serde_json::Value::as_array) {
            return inner.iter().collect();
        }
        let alias = plural_alias(key);
        if !alias.is_empty() {
            if let Some(inner) = body.get(alias).and_then(|v| v.get(alias)).and_then(serde_json::Value::as_array) {
                return inner.iter().collect();
            }
            if let Some(inner) = body.get(alias).and_then(|v| v.get(*key)).and_then(serde_json::Value::as_array) {
                return inner.iter().collect();
            }
            if let Some(array) = body.get(alias).and_then(serde_json::Value::as_array) {
                return array.iter().collect();
            }
        }
    }
    Vec::new()
}

/// 取整数（兼容字符串数字，阿里云 `TotalCount` 有时是 `"3"`）。
#[must_use]
pub fn json_i64(body: &serde_json::Value, key: &str) -> Option<i64> {
    match body.get(key) {
        Some(serde_json::Value::Number(n)) => n.as_i64(),
        Some(serde_json::Value::String(s)) => s.parse::<i64>().ok(),
        _ => None,
    }
}

/// 取字符串。
#[must_use]
pub fn json_str(body: &serde_json::Value, key: &str) -> Option<String> {
    body.get(key).and_then(serde_json::Value::as_str).map(ToString::to_string)
}
