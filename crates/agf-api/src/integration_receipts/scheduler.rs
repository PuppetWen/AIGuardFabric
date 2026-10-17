//! Scheduler receipts expose metadata, never executable carriers or provider diagnostics.
//! The same projection protects old encrypted receipts without mutating them on GET.
use agf_core::error::DomainResult;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const DETAILS_OMITTED: &str = "Scheduler response details were omitted; inspect safe status and request identifiers";

pub(super) fn project(adapter: &str, operation: &str, value: &mut Value) -> DomainResult<()> {
    if adapter != "alicloud-schedulerx3" {
        return Ok(());
    }
    if operation == "GetApp" {
        *value = json!({"error":"Use the dedicated Scheduler native observation endpoint"});
        return Ok(());
    }
    filter(value)?;
    Ok(())
}

fn key(value: &str) -> String {
    value.chars().filter(char::is_ascii_alphanumeric).flat_map(char::to_lowercase).collect()
}

fn carrier(name: &str) -> bool {
    matches!(
        name,
        "parameters"
            | "jobhandler"
            | "script"
            | "xattrs"
            | "instanceparameters"
            | "result"
            | "workaddr"
            | "executor"
            | "serverip"
            | "noticeconfig"
            | "noticecontacts"
            | "label"
            | "cleanmode"
            | "description"
            | "accesstoken"
            | "securitytoken"
            | "authorization"
            | "headers"
            | "raw"
            | "payload"
    )
}

fn container(name: &str) -> bool {
    matches!(name, "response" | "data" | "records" | "jobs" | "job" | "jobexecutions" | "jobexecution")
}

fn metadata(name: &str) -> bool {
    matches!(
        name,
        "code"
            | "success"
            | "requestid"
            | "id"
            | "jobid"
            | "jobids"
            | "appgroupid"
            | "appname"
            | "name"
            | "jobname"
            | "jobtype"
            | "status"
            | "currentexecutestatus"
            | "lastexecutestatus"
            | "page"
            | "pagenum"
            | "pagenumber"
            | "pagesize"
            | "total"
            | "totalcount"
            | "totalpages"
            | "jobexecutionid"
            | "workflowid"
            | "workflowexecutionid"
            | "workflowname"
            | "timetype"
            | "timeexpression"
            | "timezone"
            | "calendar"
            | "createtime"
            | "updatetime"
            | "scheduletime"
            | "datatime"
            | "starttime"
            | "endtime"
            | "lastexecuteendtime"
            | "duration"
            | "attempt"
            | "attemptinterval"
            | "maxattempt"
            | "maxconcurrency"
            | "routestrategy"
            | "triggertype"
            | "priority"
            | "weight"
            | "nodetype"
            | "dataoffset"
            | "dependentstrategy"
            | "starttimetype"
            | "executeblockstrategy"
            | "executorblockstrategy"
            | "childjobid"
            | "totaltokens"
            | "mocked"
            | "source"
            | "accepted"
            | "failed"
    )
}

fn safe_marker(value: &Value) -> bool {
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
    if safe_marker(value) {
        return Ok(());
    }
    let present = !value.is_null() && value.as_str().is_none_or(|text| !text.is_empty());
    let digest =
        present.then(|| serde_json::to_vec(value)).transpose()?.map(|bytes| format!("{:x}", Sha256::digest(bytes)));
    *value = json!({"opaque":true,"present":present,"sha256":digest});
    Ok(())
}

fn scalar(value: &Value) -> bool {
    value.is_null()
        || value.is_boolean()
        || value.is_number()
        || value.as_str().is_some_and(|text| text.len() <= 256 && !text.contains('\0'))
}

fn filter(value: &mut Value) -> DomainResult<()> {
    if safe_marker(value) {
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
                let name = key(&original);
                if carrier(&name) {
                    if let Some(field) = fields.get_mut(&original) {
                        opaque(field)?;
                    }
                } else if matches!(name.as_str(), "message" | "error" | "cause") {
                    fields.insert(original, Value::String(DETAILS_OMITTED.into()));
                } else if container(&name) {
                    if let Some(field) = fields.get_mut(&original) {
                        if field.is_object() || field.is_array() {
                            filter(field)?;
                        } else if !field.is_null() && !field.is_number() {
                            opaque(field)?;
                        }
                    }
                } else if metadata(&name) {
                    if let Some(field) = fields.get_mut(&original) {
                        if name == "code"
                            && !field.is_null()
                            && !matches!(field.as_u64(), Some(0 | 1 | 200))
                            && !field.as_str().is_some_and(|code| {
                                matches!(code.to_ascii_lowercase().as_str(), "0" | "1" | "200" | "ok" | "success")
                            })
                        {
                            *field = Value::String("omitted".into());
                        } else if name == "jobids"
                            && field.as_array().is_some_and(|items| items.len() <= 2000 && items.iter().all(scalar))
                        {
                            // Keep the documented ID list; it is never used as execution authority.
                        } else if !scalar(field) {
                            opaque(field)?;
                        }
                    }
                } else {
                    // Never expose arbitrary provider field names or contents as diagnostics.
                    fields.remove(&original);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                filter(item)?;
            }
        }
        Value::String(_) => opaque(value)?,
        _ => {}
    }
    Ok(())
}
