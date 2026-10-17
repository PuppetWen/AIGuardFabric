//! 由 `provider.rs` 拆分：`parse_bedrock_event` 等 10 个函数（纯搬移，逻辑不变）。
use super::*;

/// Bedrock `converse-stream` 载荷 → canonical 分片。
pub(crate) fn parse_bedrock_event(value: &Value) -> Option<StreamChunk> {
    if let Some(delta) = value.get("contentBlockDelta") {
        if let Some(t) = delta.get("delta").and_then(|d| d.get("text")).and_then(Value::as_str) {
            return Some(StreamChunk::text(t));
        }
        if let Some(fragment) = delta.get("delta").and_then(|d| d.get("toolUse")).and_then(|t| t.get("input")) {
            let mut chunk = StreamChunk::default();
            chunk.delta.tool_calls.push(crate::wire::ToolCallDelta {
                index: u32::try_from(delta.get("contentBlockIndex").and_then(Value::as_u64).unwrap_or(0)).unwrap_or(0),
                id: None,
                name: None,
                arguments_fragment: fragment.as_str().unwrap_or_default().to_string(),
            });
            return Some(chunk);
        }
        return None;
    }
    if let Some(start) = value.get("contentBlockStart") {
        if let Some(tu) = start.get("start").and_then(|s| s.get("toolUse")) {
            let mut chunk = StreamChunk::default();
            chunk.delta.tool_calls.push(crate::wire::ToolCallDelta {
                index: u32::try_from(start.get("contentBlockIndex").and_then(Value::as_u64).unwrap_or(0)).unwrap_or(0),
                id: tu.get("toolUseId").and_then(Value::as_str).map(ToString::to_string),
                name: tu.get("name").and_then(Value::as_str).map(ToString::to_string),
                arguments_fragment: String::new(),
            });
            return Some(chunk);
        }
        return None;
    }
    if let Some(stop) = value.get("messageStop") {
        let reason = match stop.get("stopReason").and_then(Value::as_str) {
            Some("max_tokens") => FinishReason::Length,
            Some("tool_use") => FinishReason::ToolCalls,
            Some("content_filtered") => FinishReason::ContentFilter,
            _ => FinishReason::Stop,
        };
        return Some(StreamChunk::finished(reason, None));
    }
    if let Some(meta) = value.get("metadata") {
        if let Some(u) = meta.get("usage") {
            return Some(StreamChunk {
                delta: crate::wire::ChatDelta::default(),
                finish_reason: None,
                usage: Some(Usage {
                    prompt_tokens: u.get("inputTokens").and_then(Value::as_u64).unwrap_or(0),
                    completion_tokens: u.get("outputTokens").and_then(Value::as_u64).unwrap_or(0),
                    cached_tokens: u.get("cacheReadInputTokens").and_then(Value::as_u64).unwrap_or(0),
                    ..Usage::default()
                }),
                anthropic_event: None,
            });
        }
    }
    None
}

/// 生成 SigV4 签名头（`authorization` / `x-amz-date` / `x-amz-content-sha256` / 可选的 `x-amz-security-token`）。
///
/// # Errors
/// URL 不含主机名时返回 `DomainError::Validation`。
pub fn sign_sigv4(input: &SigV4Input<'_>) -> DomainResult<BTreeMap<String, String>> {
    let host = host_of(input.url).ok_or_else(|| DomainError::Validation(format!("非法 URL: {}", input.url)))?;
    let uri_path = path_of(input.url);
    let amz_date = input.now.as_datetime().format("%Y%m%dT%H%M%SZ").to_string();
    let date_stamp = input.now.as_datetime().format("%Y%m%d").to_string();
    let payload_hash = hex::encode(Sha256::digest(input.body));

    // 1) 规范头（必须按字典序、小写）
    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    headers.insert("host".to_string(), host);
    headers.insert("x-amz-content-sha256".to_string(), payload_hash.clone());
    headers.insert("x-amz-date".to_string(), amz_date.clone());
    if let Some(token) = &input.credentials.session_token {
        headers.insert("x-amz-security-token".to_string(), token.clone());
    }
    // 规范头：`k:v\n` 按字典序拼接（fold 避免为每个头单独分配 String）
    let canonical_headers: String = headers.iter().fold(String::new(), |mut acc, (k, v)| {
        acc.push_str(k);
        acc.push(':');
        acc.push_str(v);
        acc.push('\n');
        acc
    });
    let signed_headers: String = headers.keys().cloned().collect::<Vec<_>>().join(";");

    // 2) 规范请求
    let canonical_request =
        format!("{}\n{}\n{}\n{}\n{}\n{}", input.method, uri_path, "", canonical_headers, signed_headers, payload_hash);

    // 3) 待签串
    let scope = format!("{date_stamp}/{}/{}/aws4_request", input.region, input.service);
    let string_to_sign =
        format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}", hex::encode(Sha256::digest(canonical_request.as_bytes())));

    // 4) 派生密钥 + 签名
    let secret = format!("AWS4{}", input.credentials.secret_access_key);
    let k_date = hmac_sha256(secret.as_bytes(), date_stamp.as_bytes());
    let k_region = hmac_sha256(&k_date, input.region.as_bytes());
    let k_service = hmac_sha256(&k_region, input.service.as_bytes());
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
        input.credentials.access_key_id
    );
    let mut out = headers;
    out.insert("authorization".to_string(), authorization);
    Ok(out)
}

pub(crate) fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    // HMAC 接受任意长度密钥；构造失败（不可达）时返回空签名而不是 panic
    let Ok(mut mac) = <Hmac<Sha256> as Mac>::new_from_slice(key) else {
        return Vec::new();
    };
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// 从 URL 取主机名（含端口）。
#[must_use]
pub fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let host = rest.split(['/', '?']).next()?;
    if host.is_empty() { None } else { Some(host.to_string()) }
}

/// 从 URL 取路径（默认 `/`）。
#[must_use]
pub fn path_of(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    match rest.find('/') {
        Some(idx) => {
            let path = &rest[idx..];
            let path = path.split('?').next().unwrap_or(path);
            if path.is_empty() { "/".to_string() } else { path.to_string() }
        }
        None => "/".to_string(),
    }
}

/// 凭据掩码（日志/控制台安全展示）。
#[must_use]
pub fn masked_credential(credential: Option<&str>) -> String {
    match credential {
        None => "<未配置>".to_string(),
        Some(c) => mask_default(c),
    }
}

/// 图片 data URI → `(mime, base64)`（Bedrock 需要分开传）。
#[must_use]
pub fn split_data_uri(uri: &str) -> Option<(String, String)> {
    let rest = uri.trim().strip_prefix("data:")?;
    let (meta, data) = rest.split_once(',')?;
    let mime = meta.split(';').next().unwrap_or("image/png").to_string();
    if data.is_empty() { None } else { Some((mime, data.to_string())) }
}

/// 把 data URI 里的 base64 解码回字节（**不做网络下载**，避免 SSRF 面）。
///
/// # Errors
/// 非 data URI 或 base64 非法。
pub fn decode_data_uri(uri: &str) -> DomainResult<Vec<u8>> {
    let (_, data) = split_data_uri(uri).ok_or_else(|| DomainError::Validation("不是合法的 data URI".to_string()))?;
    B64.decode(data.as_bytes()).map_err(|e| DomainError::Parse(format!("base64 解码失败: {e}")))
}

/// 未配置凭据时统一的可降级错误（供 `mock` 与 `gateway` 复用）。
#[must_use]
pub fn unconfigured_error(provider: &str) -> DomainError {
    DomainError::NotImplemented(format!("{provider} 未配置凭据：应降级到 MockProvider"))
}

/// 数据分级门禁（网关路由前的最后一道自检，避免误把受限数据送云端）。
#[must_use]
pub fn endpoint_allows(endpoint: &ModelEndpoint, class: DataClass) -> bool {
    endpoint.enabled && endpoint.accepts_data_class(class)
}
