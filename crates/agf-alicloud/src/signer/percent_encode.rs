//! 由 `signer.rs` 拆分：`percent_encode` 等 11 个函数（纯搬移，逻辑不变）。
use super::*;

/// 阿里云**参数**百分号编码（用于 key 与 value）。
///
/// 严格 RFC3986：空格 → `%20`，字面加号 → `%2B`，未保留字符 `~` 保持原样。
#[must_use]
pub fn percent_encode(value: &str) -> String {
    percent_encode_signature(value)
}

/// 签名值的百分号编码：严格 RFC3986（`+` → `%2B`，`/` → `%2F`，`=` → `%3D`）。
///
/// 参数与 Base64 签名使用相同编码，避免把字面加号错误转换为空格。
#[must_use]
pub fn percent_encode_signature(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for &byte in value.as_bytes() {
        if is_unreserved_byte(byte) {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push_str(&format!("{byte:02X}"));
        }
    }
    out
}

/// 由 `(key, value)` 列表构造规范化查询串。
///
/// 排序规则：按**编码后**的 key 字节序升序（阿里云规范如此，且对 ASCII key 与按原 key
/// 排序结果一致）；同 key 多条时按 value 编码后顺序稳定排序。
#[must_use]
pub fn canonicalized_query(params: &[(String, String)]) -> String {
    let mut pairs: Vec<(String, String)> =
        params.iter().map(|(key, value)| (percent_encode(key), percent_encode(value))).collect();
    pairs.sort();
    pairs.into_iter().map(|(key, value)| format!("{key}={value}")).collect::<Vec<_>>().join("&")
}

/// 构造 RPC 风格 `StringToSign`。
#[must_use]
pub fn rpc_string_to_sign(method: &str, canonical_query: &str) -> String {
    format!("{}&{}&{}", method.to_uppercase(), percent_encode("/"), percent_encode(canonical_query))
}

/// 计算 RPC 风格签名：`Base64(HMAC-SHA1(AccessKeySecret + "&", StringToSign))`。
#[must_use]
pub fn rpc_signature(access_key_secret: &str, string_to_sign: &str) -> String {
    let key = format!("{access_key_secret}&");
    match HmacSha1::new_from_slice(key.as_bytes()) {
        Ok(mut mac) => {
            mac.update(string_to_sign.as_bytes());
            B64.encode(mac.finalize().into_bytes())
        }
        // HMAC-SHA1 接受任意长度密钥，这里不可达；不 panic，退化为空签名由服务端拒绝。
        Err(_) => String::new(),
    }
}

/// 执行 RPC 风格签名，返回带 `Signature` 的完整查询串。
///
/// 公共参数顺序无关（会被排序），但 `Signature` 必须在签名**之后**追加。
#[must_use]
pub fn sign_rpc(input: &RpcSignInput<'_>) -> RpcSigned {
    let mut params: Vec<(String, String)> = input.params.clone();
    params.push(("AccessKeyId".to_string(), input.access_key_id.to_string()));
    params.push(("Format".to_string(), "JSON".to_string()));
    params.push(("SignatureMethod".to_string(), "HMAC-SHA1".to_string()));
    params.push(("SignatureNonce".to_string(), input.signature_nonce.to_string()));
    params.push(("SignatureVersion".to_string(), "1.0".to_string()));
    params.push(("Timestamp".to_string(), input.timestamp.to_string()));

    let canonical_query = canonicalized_query(&params);
    let string_to_sign = rpc_string_to_sign(input.method, &canonical_query);
    let signature = rpc_signature(input.access_key_secret, &string_to_sign);
    let final_query = format!("{canonical_query}&Signature={}", percent_encode_signature(&signature));
    RpcSigned { canonical_query, string_to_sign, final_query, signature }
}

/// SHA-256 十六进制（`upper=true` 输出大写）。
#[must_use]
pub fn sha256_hex(value: &str, upper: bool) -> String {
    let hex = hex::encode(Sha256::digest(value.as_bytes()));
    if upper { hex.to_uppercase() } else { hex }
}

/// 构造 V3 规范化请求头区块（`name:value\n`，按小写名排序，以换行结束）。
#[must_use]
pub(crate) fn canonical_headers_block(headers: &BTreeMap<String, String>) -> String {
    let mut out = String::new();
    for (name, value) in headers {
        out.push_str(&name.to_ascii_lowercase());
        out.push(':');
        out.push_str(value.trim());
        out.push('\n');
    }
    out
}

/// V3 风格签名（`ACS3-HMAC-SHA256`）。
///
/// 算法：
/// ```text
/// CanonicalRequest =
///   HTTPMethod + "\n" + CanonicalURI + "\n" + CanonicalQueryString + "\n" +
///   CanonicalHeaders + "\n" + SignedHeaders + "\n" + HexEncode(Hash(RequestPayload))
/// StringToSign  = "ACS3-HMAC-SHA256" + "\n" + HexEncode(Hash(CanonicalRequest))
/// Signature     = Hex(HMAC-SHA256(AccessKeySecret, StringToSign))
/// Authorization = "ACS3-HMAC-SHA256 Credential=<AK>,SignedHeaders=<...>,Signature=<...>"
/// ```
///
/// 注：调用方必须自行在 `headers` 里放 `x-acs-action` / `x-acs-version` / `x-acs-date` /
/// `x-acs-signature-nonce`；本函数只负责补 `host` 与 `x-acs-content-sha256`。
///
/// `TODO(pending-verification):` V3 的 `x-acs-signature-nonce` 语义、
/// 以及是否允许省略 `x-acs-content-sha256` 走 `UNSIGNED-PAYLOAD`，尚未与线上签名对照，
/// 见 `docs/pending-verification.md`。RPC 风格是本 crate 的默认实现路径。
#[must_use]
pub fn sign_v3(input: &V3SignInput<'_>) -> V3Signed {
    let content_sha256 = sha256_hex(input.body, false);
    let mut headers: BTreeMap<String, String> =
        input.headers.iter().map(|(key, value)| (key.to_ascii_lowercase(), value.trim().to_string())).collect();
    headers.remove("authorization");
    headers.insert("host".to_string(), input.host.to_string());
    headers.insert("x-acs-content-sha256".to_string(), content_sha256.clone());

    let canonical_headers = canonical_headers_block(&headers);
    let signed_headers = headers.keys().map(|key| key.to_ascii_lowercase()).collect::<Vec<_>>().join(";");
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        input.method.to_uppercase(),
        input.canonical_uri,
        input.canonical_query,
        canonical_headers,
        signed_headers,
        content_sha256
    );
    let request_hash = sha256_hex(&canonical_request, false);
    let string_to_sign = format!("ACS3-HMAC-SHA256\n{request_hash}");
    let signature = match HmacSha256::new_from_slice(input.access_key_secret.as_bytes()) {
        Ok(mut mac) => {
            mac.update(string_to_sign.as_bytes());
            hex::encode(mac.finalize().into_bytes())
        }
        Err(_) => String::new(),
    };
    let authorization = format!(
        "ACS3-HMAC-SHA256 Credential={},SignedHeaders={},Signature={}",
        input.access_key_id, signed_headers, signature
    );
    V3Signed { signed_headers: headers, content_sha256, canonical_request, string_to_sign, signature, authorization }
}

/// 生成 HmacSHA1 的裸结果（十六进制），用于测试内部一致性。
#[must_use]
pub fn hmac_sha1_hex(key: &str, message: &str) -> String {
    match HmacSha1::new_from_slice(key.as_bytes()) {
        Ok(mut mac) => {
            mac.update(message.as_bytes());
            hex::encode(mac.finalize().into_bytes())
        }
        Err(_) => String::new(),
    }
}

/// 生成 HmacSHA256 的裸结果（十六进制），用于测试内部一致性。
#[must_use]
pub fn hmac_sha256_hex(key: &str, message: &str) -> String {
    match HmacSha256::new_from_slice(key.as_bytes()) {
        Ok(mut mac) => {
            mac.update(message.as_bytes());
            hex::encode(mac.finalize().into_bytes())
        }
        Err(_) => String::new(),
    }
}
