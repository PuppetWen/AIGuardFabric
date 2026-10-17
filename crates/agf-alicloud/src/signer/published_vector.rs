//! Published ACS3 vector: https://help.aliyun.com/en/sdk/product-overview/v3-request-structure-and-signature
use super::*;
#[test]
fn matches_alibaba_published_acs3_vector_with_query_parameters() {
    let headers = BTreeMap::from([
        ("x-acs-action".into(), "RunInstances".into()),
        ("x-acs-version".into(), "2014-05-26".into()),
        ("x-acs-date".into(), "2023-10-26T10:22:32Z".into()),
        ("x-acs-signature-nonce".into(), "3156853299f313e23d1673dc12e1703d".into()),
    ]);
    let signed = sign_v3(&V3SignInput {
        method: "POST",
        canonical_uri: "/",
        canonical_query: "ImageId=win2019_1809_x64_dtc_zh-cn_40G_alibase_20230811.vhd&RegionId=cn-shanghai",
        headers,
        host: "ecs.cn-shanghai.aliyuncs.com",
        body: "",
        access_key_id: "YourAccessKeyId",
        access_key_secret: "YourAccessKeySecret",
    });
    assert_eq!(
        signed.string_to_sign,
        "ACS3-HMAC-SHA256\n7ea06492da5221eba5297e897ce16e55f964061054b7695beedaac1145b1e259"
    );
    assert_eq!(signed.signature, "06563a9e1b43f5dfe96b81484da74bceab24a1d853912eee15083a6f0f3283c0");
}
#[test]
fn query_roundtrip_preserves_security_tokens_and_literals() {
    let params = vec![("SecurityToken".into(), "token+a/b=~".into()), ("Filter".into(), "A B".into())];
    let encoded = canonicalized_query(&params);
    let decoded = url::form_urlencoded::parse(encoded.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(decoded["SecurityToken"], "token+a/b=~");
    assert_eq!(decoded["Filter"], "A B");
}
