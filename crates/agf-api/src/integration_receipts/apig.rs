//! APIG public receipts expose resource metadata, never encoded or arbitrary configuration.
//! Projection runs before encryption and again on old receipts and pending recovery.
use agf_core::error::DomainResult;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const OMITTED: &str = "APIG configuration and provider diagnostics were omitted";
pub(super) fn project(adapter: &str, value: &mut Value) -> DomainResult<()> {
    if adapter == "alicloud-apig" {
        filter(value)?;
    }
    Ok(())
}
fn normalized(key: &str) -> String {
    key.chars().filter(char::is_ascii_alphanumeric).flat_map(char::to_lowercase).collect()
}
fn container(key: &str) -> bool {
    matches!(
        key,
        "response"
            | "data"
            | "items"
            | "records"
            | "routes"
            | "attachments"
            | "resources"
            | "pluginattachments"
            | "resourceidentifiers"
            | "environments"
    )
}
fn metadata(key: &str) -> bool {
    matches!(
        key,
        "code"
            | "success"
            | "requestid"
            | "id"
            | "gatewayid"
            | "environmentid"
            | "environmentname"
            | "httpapiid"
            | "routeid"
            | "attachmentid"
            | "pluginattachmentid"
            | "pluginid"
            | "pluginclassid"
            | "pluginclassname"
            | "pluginversion"
            | "policyid"
            | "policyattachmentid"
            | "policyclassid"
            | "policyclassname"
            | "policyversion"
            | "resourceid"
            | "resourcetype"
            | "name"
            | "status"
            | "type"
            | "enabled"
            | "version"
            | "pagenumber"
            | "pagenum"
            | "pagesize"
            | "total"
            | "totalcount"
            | "totalpages"
            | "nexttoken"
            | "createtime"
            | "updatetime"
            | "mocked"
            | "source"
            | "accepted"
            | "failed"
    )
}
fn carrier(key: &str) -> bool {
    matches!(
        key,
        "pluginconfig"
            | "config"
            | "authconfig"
            | "deployconfigs"
            | "policyconfigs"
            | "httpapiconfig"
            | "serviceconfigs"
            | "headers"
            | "cookies"
            | "authorization"
            | "accesskey"
            | "accesskeyid"
            | "accesskeysecret"
            | "secretkey"
            | "securitytoken"
            | "token"
            | "raw"
            | "payload"
            | "parameters"
            | "request"
            | "result"
    )
}
fn scalar(value: &Value) -> bool {
    value.is_null()
        || value.is_boolean()
        || value.is_number()
        || value.as_str().is_some_and(|text| text.len() <= 256 && !text.chars().any(char::is_control))
}
fn marker(value: &Value) -> bool {
    let Some(fields) = value.as_object() else { return false };
    fields.len() == 3
        && fields.get("opaque") == Some(&Value::Bool(true))
        && fields.get("present").is_some_and(Value::is_boolean)
        && fields.get("sha256").is_some_and(|digest| {
            (fields.get("present") == Some(&Value::Bool(false)) && digest.is_null())
                || (fields.get("present") == Some(&Value::Bool(true))
                    && digest.as_str().is_some_and(|text| {
                        text.len() == 64
                            && text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    }))
        })
}
fn opaque(value: &mut Value) -> DomainResult<()> {
    if marker(value) {
        return Ok(());
    }
    let present = !value.is_null() && value.as_str().is_none_or(|text| !text.is_empty());
    let digest =
        present.then(|| serde_json::to_vec(value)).transpose()?.map(|bytes| hex::encode(Sha256::digest(bytes)));
    *value = json!({"opaque":true,"present":present,"sha256":digest});
    Ok(())
}
fn filter(value: &mut Value) -> DomainResult<()> {
    if marker(value) {
        return Ok(());
    }
    match value {
        Value::Object(fields) => {
            let names: Vec<String> = fields.keys().cloned().collect();
            for original in names {
                if original.len() > 64
                    || !original.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
                {
                    fields.remove(&original);
                    continue;
                }
                let name = normalized(&original);
                let Some(field) = fields.get_mut(&original) else { continue };
                if name == "code"
                    && !field.is_null()
                    && !matches!(field.as_u64(), Some(0 | 1 | 200))
                    && !field.as_str().is_some_and(|code| {
                        matches!(code.to_ascii_lowercase().as_str(), "0" | "1" | "200" | "ok" | "success")
                    })
                {
                    *field = Value::String("omitted".into());
                } else if matches!(name.as_str(), "error" | "message" | "cause") {
                    *field = Value::String(OMITTED.into());
                } else if container(&name) && (field.is_array() || field.is_object()) {
                    filter(field)?;
                } else if metadata(&name) && scalar(field) {
                    // Keep pagination and outcome metadata, never a nested configuration under it.
                } else if carrier(&name) || metadata(&name) || container(&name) {
                    opaque(field)?;
                } else {
                    // Unknown field names can themselves contain opaque configuration or secrets.
                    fields.remove(&original);
                }
            }
        }
        Value::Array(items) if items.len() <= 1024 => {
            for item in items {
                if item.is_object() {
                    filter(item)?;
                } else {
                    opaque(item)?;
                }
            }
        }
        _ => opaque(value)?,
    }
    Ok(())
}
#[cfg(test)]
mod tests;
