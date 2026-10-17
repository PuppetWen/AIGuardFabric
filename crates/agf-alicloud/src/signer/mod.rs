//! 阿里云 API 签名（RPC 风格 HMAC-SHA1 + V3 风格 ACS3-HMAC-SHA256）。
//!
//! ## 为什么签名要单独成模块
//!
//! 签名是"错了就什么都调不通、且错误信息只告诉你 SignatureDoesNotMatch"的那类代码，
//! 必须能脱离网络被逐字节验证。本模块**无 I/O、无异步**，全部是纯函数，
//! 测试里用手算向量逐段断言（规范化查询串 / StringToSign / 最终签名）。
//!
//! ## RPC 风格（绝大多数阿里云 OpenAPI 的 `?Action=Xxx` 形式）
//!
//! 1. **规范化查询串（CanonicalizedQueryString）**
//!    - 每个 key / value 先按阿里云规则百分号编码，再按 key 的**字节序**升序排序；
//!    - 以 `k=v` 形式用 `&` 连接。
//! 2. **StringToSign** = `HTTPMethod + "&" + percentEncode("/") + "&" + percentEncode(canonicalQuery)`
//!    （注意：canonicalQuery 会被**再编码一次**，所以其中的 `=`/`&` 变成 `%3D`/`%26`，
//!    已经编码出的 `%3A` 会变成 `%253A`）。
//! 3. **Signature** = `Base64(HMAC-SHA1(AccessKeySecret + "&", StringToSign))`。
//! 4. 最终请求 = canonicalQuery + `&Signature=` + percentEncode(signature)。
//!
//! ## 百分号编码规则（[`percent_encode`]）
//!
//! - 非保留字符 `A-Z a-z 0-9 - _ . ~` 原样输出；
//! - 字面 `+` 编码为 `%2B`，`*` 编码为 `%2A`，空格编码为 `%20`，`~` 保持原样；
//! - 其余字符按 UTF-8 逐字节输出大写十六进制，形如 `%E4%B8%AD`。
//!
//! ## V3 风格（`ACS3-HMAC-SHA256`）
//!
//! 见 [`sign_v3`]；`TODO(pending-verification)` 说明其未与线上签名做过对照。

pub(crate) use std::collections::BTreeMap;

pub(crate) use base64::Engine;

pub(crate) use base64::engine::general_purpose::STANDARD as B64;

pub(crate) use hmac::Hmac;
pub(crate) use hmac::Mac;

pub(crate) use sha1::Sha1;

pub(crate) use sha2::Digest;
pub(crate) use sha2::Sha256;

#[allow(unused_imports)]
pub use percent_encode::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

type HmacSha1 = Hmac<Sha1>;

type HmacSha256 = Hmac<Sha256>;

/// 未保留字符（RFC3986）中可直接输出的部分。
const fn is_unreserved_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.' || byte == b'~'
}

/// RPC 风格签名输入。
///
/// `params` 里**不要**包含 `Action` / `Version` 与公共参数（`AccessKeyId` / `Format` /
/// `SignatureMethod` / `SignatureNonce` / `SignatureVersion` / `Timestamp`）——它们由
/// [`sign_rpc`] 补齐；重复出现会导致规范化查询串里出现两个同名键。
#[derive(Clone)]
pub struct RpcSignInput<'a> {
    /// HTTP 方法（`GET` / `POST`）。
    pub method: &'a str,
    /// AccessKeyId。
    pub access_key_id: &'a str,
    /// AccessKeySecret。
    pub access_key_secret: &'a str,
    /// 业务参数（**不含**签名相关公共参数，由本函数补齐）。
    pub params: Vec<(String, String)>,
    /// 请求时间戳（RFC3339，秒精度，形如 `2016-02-23T12:46:24Z`）。
    pub timestamp: &'a str,
    /// 签名随机串（调用方提供，便于测试固定）。
    pub signature_nonce: &'a str,
}

/// RPC 风格签名结果（可审计，便于排障与控制台展示）。
#[derive(Clone)]
pub struct RpcSigned {
    /// 规范化查询串（不含 Signature）。
    pub canonical_query: String,
    /// 待签名串。
    pub string_to_sign: String,
    /// 最终查询串（含 `Signature`）。
    pub final_query: String,
    /// 签名值。
    pub signature: String,
}

/// V3 风格签名输入。
#[derive(Clone)]
pub struct V3SignInput<'a> {
    /// HTTP 方法（`POST` / `GET`）。
    pub method: &'a str,
    /// 规范化 URI（一般 `/`，或以 `/` 开头且已百分号编码的路径）。
    pub canonical_uri: &'a str,
    /// 规范化查询串（已排序已编码；可为空）。
    pub canonical_query: &'a str,
    /// 参与签名的头部（**不含 host**，由签名函数补齐并按小写名排序）。
    pub headers: BTreeMap<String, String>,
    /// Host（如 `cs.aliyuncs.com`）。
    pub host: &'a str,
    /// 请求体（用于计算 `x-acs-content-sha256`）。
    pub body: &'a str,
    /// AccessKeyId（V3 的 `Credential=` 值）。
    pub access_key_id: &'a str,
    /// AccessKeySecret。
    pub access_key_secret: &'a str,
}

/// V3 风格签名结果。
#[derive(Clone)]
pub struct V3Signed {
    /// 参与签名的头部（含 host / x-acs-content-sha256）。
    pub signed_headers: BTreeMap<String, String>,
    /// `x-acs-content-sha256`。
    pub content_sha256: String,
    /// 规范化请求（CanonicalRequest）。
    pub canonical_request: String,
    /// 待签名串。
    pub string_to_sign: String,
    /// 签名值（小写十六进制）。
    pub signature: String,
    /// `Authorization` 头的值。
    pub authorization: String,
}

mod debug;
mod percent_encode;
#[cfg(test)]
mod published_vector;
#[cfg(test)]
mod tests;
