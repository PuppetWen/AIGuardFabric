use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};

fn carrier() -> Value {
    let config = json!({"accessKey":"INDEPENDENT-PLUGIN-ID", "secretKey":"INDEPENDENT-PLUGIN-SECRET",
        "checkRequest":true, "checkResponse":true})
    .to_string();
    json!({"response":{"RequestId":"owned-apig-provider", "Code":"OK", "Success":true,
        "data":{"totalCount":1,"items":[{"pluginAttachmentId":"pa-owned", "pluginClassName":"ai-security-guard",
            "pluginVersion":"1.0.0", "enabled":true, "pluginConfig":STANDARD.encode(config),
            "config":"INDEPENDENT-POLICY-SECRET", "authConfig":{"authType":"JWT","unknown":"INDEPENDENT-AUTH-SECRET"},
            "unknownCarrier":{"secret":"INDEPENDENT-UNKNOWN-SECRET"}}]}}, "error":"INDEPENDENT-DIAGNOSTIC-SECRET"})
}
#[test]
fn encoded_plugin_and_arbitrary_configuration_never_enter_public_receipts() -> DomainResult<()> {
    let mut original = carrier();
    original["INDEPENDENT-FIELD-SECRET"] = json!("INDEPENDENT-FIELD-VALUE");
    let encoded = original["response"]["data"]["items"][0]["pluginConfig"].clone();
    let mut safe = original.clone();
    project("alicloud-apig", &mut safe)?;
    let row = &safe["response"]["data"]["items"][0];
    for field in ["pluginConfig", "config", "authConfig"] {
        assert!(marker(&row[field]));
        assert_eq!(row[field]["present"], true);
    }
    assert!(row.get("unknownCarrier").is_none());
    assert_eq!(safe["response"]["data"]["totalCount"], 1);
    assert_eq!(row["pluginAttachmentId"], "pa-owned");
    assert_eq!(row["enabled"], true);
    assert_eq!(safe["response"]["Code"], "OK");
    assert_eq!(safe["response"]["Success"], true);
    assert!(!safe.to_string().contains("INDEPENDENT-"));
    assert!(!safe.to_string().contains(encoded.as_str().unwrap_or_default()));
    assert_eq!(original["response"]["data"]["items"][0]["pluginConfig"], encoded);
    let first = safe.clone();
    project("alicloud-apig", &mut safe)?;
    assert_eq!(safe, first);
    Ok(())
}
#[test]
fn malformed_marker_raw_arrays_and_metadata_containers_are_not_trusted() -> DomainResult<()> {
    let mut raw = json!({"response":{"data":{"config":{"opaque":true,"present":true,"sha256":"not-a-hash", "secret":"BAD-SECRET"},
        "name":{"secret":"BAD-SECRET"},"items":["BAD-SECRET"],"message":"BAD-SECRET"}}});
    project("alicloud-apig", &mut raw)?;
    assert!(!raw.to_string().contains("BAD-SECRET"));
    assert!(marker(&raw["response"]["data"]["config"]));
    assert!(marker(&raw["response"]["data"]["name"]));
    assert!(marker(&raw["response"]["data"]["items"][0]));
    Ok(())
}
#[test]
fn unrelated_adapters_are_unchanged_and_large_arrays_never_silently_truncate() -> DomainResult<()> {
    let original = carrier();
    let mut other = original.clone();
    project("alicloud-cms", &mut other)?;
    assert_eq!(other, original);
    let mut large = json!({"response":{"data":{"totalCount":1025,"items":vec![json!({"id":"owned"});1025]}}});
    project("alicloud-apig", &mut large)?;
    assert_eq!(large["response"]["data"]["totalCount"], 1025);
    assert!(marker(&large["response"]["data"]["items"]));
    Ok(())
}

#[test]
fn unknown_error_code_never_carries_provider_diagnostics_or_changes_success_metadata() -> DomainResult<()> {
    for code in [json!("INDEPENDENT-CODE-SECRET"), json!({"secret":"INDEPENDENT-CODE-SECRET"}), json!(999)] {
        let mut value = json!({"response":{"Code":code,"Success":false,"data":{"code":"INDEPENDENT-CODE-SECRET"}}});
        project("alicloud-apig", &mut value)?;
        assert_eq!(value["response"]["Code"], "omitted");
        assert_eq!(value["response"]["Success"], false);
        assert!(!value.to_string().contains("INDEPENDENT-CODE-SECRET"));
        let first = value.clone();
        project("alicloud-apig", &mut value)?;
        assert_eq!(value, first);
    }
    for code in [Value::Null, json!(0), json!(1), json!(200), json!("Ok"), json!("SUCCESS")] {
        let mut value = json!({"response":{"Code":code}});
        let first = value.clone();
        project("alicloud-apig", &mut value)?;
        assert_eq!(value, first);
    }
    Ok(())
}
