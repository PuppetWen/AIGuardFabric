//! 由 `signer.rs` 拆分：`percent_encoding_edge_cases` 等 13 个函数（纯搬移，逻辑不变）。
use super::*;

#[test]
pub(crate) fn percent_encoding_edge_cases() {
    assert_eq!(percent_encode("abcXYZ019"), "abcXYZ019");
    assert_eq!(percent_encode("-_.~"), "-_.~", "未保留字符保持原样");
    assert_eq!(percent_encode("a b"), "a%20b", "空格编码为 %20，不是 +");
    assert_eq!(percent_encode("a+b"), "a%2Bb", "加号保持字面含义");
    assert_eq!(percent_encode("a*b"), "a%2Ab", "星号编码为 %2A");
    assert_eq!(percent_encode("a/b"), "a%2Fb", "斜杠必须编码");
    assert_eq!(percent_encode("k=v&x"), "k%3Dv%26x");
    assert_eq!(percent_encode("%7E"), "%257E", "已编码形态会被再次编码");
    assert_eq!(percent_encode(":"), "%3A");
    assert_eq!(percent_encode("中"), "%E4%B8%AD", "非 ASCII 按 UTF-8 逐字节编码");
    assert_eq!(percent_encode(""), "");
    assert_eq!(percent_encode("emoji😀"), "emoji%F0%9F%98%80");
}

#[test]
pub(crate) fn canonical_query_sorts_and_joins() {
    let params = vec![
        ("Version".to_string(), "2014-05-26".to_string()),
        ("Action".to_string(), "DescribeRegions".to_string()),
        ("Format".to_string(), "JSON".to_string()),
    ];
    assert_eq!(canonicalized_query(&params), "Action=DescribeRegions&Format=JSON&Version=2014-05-26");
}

#[test]
pub(crate) fn canonical_query_sorts_by_byte_order_uppercase_first() {
    let params = vec![
        ("a".to_string(), "1".to_string()),
        ("A".to_string(), "2".to_string()),
        ("B".to_string(), "3".to_string()),
        ("b".to_string(), "4".to_string()),
    ];
    assert_eq!(canonicalized_query(&params), "A=2&B=3&a=1&b=4", "字节序：大写字母在小写之前");
}

#[test]
pub(crate) fn canonical_query_keeps_empty_values() {
    let params = vec![("Action".to_string(), String::new()), ("Version".to_string(), "2022-05-09".to_string())];
    assert_eq!(canonicalized_query(&params), "Action=&Version=2022-05-09");
}

#[test]
pub(crate) fn canonical_query_encodes_values_with_unicode_and_symbols() {
    let params = vec![("Filter".to_string(), "name=gpu cluster".to_string()), ("Tag".to_string(), "键=值".to_string())];
    assert_eq!(canonicalized_query(&params), "Filter=name%3Dgpu%20cluster&Tag=%E9%94%AE%3D%E5%80%BC");
}

#[test]
pub(crate) fn string_to_sign_double_encodes_canonical_query() {
    let query = "Action=DescribeRegions&Version=2014-05-26";
    let to_sign = rpc_string_to_sign("GET", query);
    assert_eq!(to_sign, "GET&%2F&Action%3DDescribeRegions%26Version%3D2014-05-26");
    assert!(to_sign.starts_with("GET&%2F&"));
    assert_eq!(rpc_string_to_sign("post", query), rpc_string_to_sign("POST", query), "方法名大小写不敏感");
}

/// 手算签名向量（沿用阿里云 OpenAPI 规范附录示例的公共参数形态）。
///
/// 中间值（可复核）：
/// ```text
/// canonicalQuery =
///   AccessKeyId=testid&Action=DescribeRegions&Format=JSON
///   &SignatureMethod=HMAC-SHA1
///   &SignatureNonce=a1b2c3d4-e5f6-7890-abcd-ef1234567890
///   &SignatureVersion=1.0&Timestamp=2016-02-23T12%3A46%3A24Z&Version=2014-05-26
/// stringToSign =
///   GET&%2F&AccessKeyId%3Dtestid%26Action%3DDescribeRegions%26Format%3DJSON
///   %26SignatureMethod%3DHMAC-SHA1
///   %26SignatureNonce%3Da1b2c3d4-e5f6-7890-abcd-ef1234567890
///   %26SignatureVersion%3D1.0%26Timestamp%3D2016-02-23T12%253A46%253A24Z
///   %26Version%3D2014-05-26
/// signature = Base64(HMAC-SHA1("testsecret&", stringToSign))
///           = cA+UKSvbG9XoP0nlqwBhKTOW4ss=
/// ```
///
/// 复核方式（任一）：
/// - PowerShell：`[System.Security.Cryptography.HMACSHA1]::new([Text.Encoding]::UTF8.GetBytes('testsecret&'))`
///   后 `[Convert]::ToBase64String(...)`；
/// - `python -c "import hmac,hashlib,base64;print(base64.b64encode(hmac.new(b'testsecret&',STS.encode(),hashlib.sha1).digest()).decode())"`；
/// - 本模块 [`hmac_sha1_hex`] 的独立实现（见下一条测试）。
#[test]
pub(crate) fn rpc_signature_matches_hand_computed_vector() {
    let input = RpcSignInput {
        method: "GET",
        access_key_id: "testid",
        access_key_secret: "testsecret",
        params: vec![
            ("Action".to_string(), "DescribeRegions".to_string()),
            ("Version".to_string(), "2014-05-26".to_string()),
        ],
        timestamp: "2016-02-23T12:46:24Z",
        signature_nonce: "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    };
    let signed = sign_rpc(&input);
    assert_eq!(
        signed.canonical_query,
        "AccessKeyId=testid&Action=DescribeRegions&Format=JSON&SignatureMethod=HMAC-SHA1\
             &SignatureNonce=a1b2c3d4-e5f6-7890-abcd-ef1234567890&SignatureVersion=1.0\
             &Timestamp=2016-02-23T12%3A46%3A24Z&Version=2014-05-26"
    );
    assert_eq!(
        signed.string_to_sign,
        "GET&%2F&AccessKeyId%3Dtestid%26Action%3DDescribeRegions%26Format%3DJSON\
             %26SignatureMethod%3DHMAC-SHA1\
             %26SignatureNonce%3Da1b2c3d4-e5f6-7890-abcd-ef1234567890\
             %26SignatureVersion%3D1.0%26Timestamp%3D2016-02-23T12%253A46%253A24Z\
             %26Version%3D2014-05-26"
    );
    assert_eq!(signed.signature, "cA+UKSvbG9XoP0nlqwBhKTOW4ss=");
    assert_eq!(
        signed.final_query,
        format!("{}&Signature={}", signed.canonical_query, percent_encode_signature("cA+UKSvbG9XoP0nlqwBhKTOW4ss="))
    );
    assert!(
        signed.final_query.ends_with("Signature=cA%2BUKSvbG9XoP0nlqwBhKTOW4ss%3D"),
        "签名里的 + 必须编码为 %2B（不是表示空格的 %20）: {}",
        signed.final_query
    );
}

#[test]
pub(crate) fn parameter_and_signature_encoding_preserve_plus() {
    assert_eq!(percent_encode("a+b"), "a%2Bb", "参数编码保留字面加号");
    assert_eq!(percent_encode_signature("a+b"), "a%2Bb", "签名编码保留 + 的字面语义");
    assert_eq!(percent_encode("a~b"), "a~b");
    assert_eq!(percent_encode_signature("a~b"), "a~b", "签名编码 ~ 属未保留字符");
    assert_eq!(percent_encode_signature("a/b=c"), "a%2Fb%3Dc");
    assert_eq!(percent_encode_signature(""), "");
}

/// 用第二套独立实现（[`hmac_sha1_hex`]）交叉验证同一条向量，避免"实现和期望值同源"。
#[test]
pub(crate) fn rpc_signature_cross_checked_by_second_primitive() {
    let to_sign = "GET&%2F&Action%3DDescribeRegions";
    let base64_signature = rpc_signature("testsecret", to_sign);
    let raw = hmac_sha1_hex("testsecret&", to_sign);
    let expected = B64.encode(hex::decode(&raw).unwrap_or_default());
    assert_eq!(base64_signature, expected);
    assert_eq!(raw.len(), 40, "HMAC-SHA1 输出 20 字节 = 40 hex");
}

#[test]
pub(crate) fn rpc_signature_is_secret_dependent() {
    let to_sign = "GET&%2F&Action%3DDescribeRegions";
    assert_ne!(rpc_signature("secret-a", to_sign), rpc_signature("secret-b", to_sign));
    assert_eq!(rpc_signature("secret-a", to_sign), rpc_signature("secret-a", to_sign));
}

#[test]
pub(crate) fn v3_signature_matches_hand_computed_vector() {
    let mut headers = BTreeMap::new();
    headers.insert("x-acs-action".to_string(), "ListClusters".to_string());
    headers.insert("x-acs-version".to_string(), "2022-05-09".to_string());
    headers.insert("x-acs-date".to_string(), "2026-03-01T00:00:00Z".to_string());
    headers.insert("x-acs-signature-nonce".to_string(), "fixed-nonce-for-test".to_string());
    let input = V3SignInput {
        method: "POST",
        canonical_uri: "/",
        canonical_query: "",
        headers,
        host: "cs.aliyuncs.com",
        body: "",
        access_key_id: "testid",
        access_key_secret: "testsecret",
    };
    let signed = sign_v3(&input);
    assert_eq!(signed.content_sha256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_eq!(
        signed.canonical_request,
        "POST\n/\n\n\
             host:cs.aliyuncs.com\n\
             x-acs-action:ListClusters\n\
             x-acs-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\
             x-acs-date:2026-03-01T00:00:00Z\n\
             x-acs-signature-nonce:fixed-nonce-for-test\n\
             x-acs-version:2022-05-09\n\n\
             host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-signature-nonce;x-acs-version\n\
             e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        signed.string_to_sign,
        "ACS3-HMAC-SHA256\n024ead82a1ccc10598bb8ac571148dc7710ec47b931cf529079b369a4d7afc87"
    );
    assert_eq!(signed.signature, "862673fd46b7f0d457a4feaaf996d8b511c93d8c2498a9dcf45dd693e394c8e0");
    assert!(signed.authorization.starts_with("ACS3-HMAC-SHA256 Credential=testid"));
    assert!(
        signed.authorization.contains("Signature=862673fd46b7f0d457a4feaaf996d8b511c93d8c2498a9dcf45dd693e394c8e0")
    );
}

#[test]
pub(crate) fn v3_signature_changes_with_payload() {
    let headers = BTreeMap::new();
    let base = V3SignInput {
        method: "POST",
        canonical_uri: "/",
        canonical_query: "a=1",
        headers,
        host: "cs.aliyuncs.com",
        body: "",
        access_key_id: "testid",
        access_key_secret: "s",
    };
    let with_body = V3SignInput { body: "{\"x\":1}", ..base.clone() };
    assert_ne!(sign_v3(&base).signature, sign_v3(&with_body).signature);
    assert_ne!(sign_v3(&base).content_sha256, sign_v3(&with_body).content_sha256);
}

#[test]
pub(crate) fn sha256_helper_shapes() {
    let lower = sha256_hex("abc", false);
    assert_eq!(lower.len(), 64);
    assert_eq!(lower, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq!(sha256_hex("abc", true), lower.to_uppercase());
}
