//! Safe hashes and phase evidence exclude raw provider config, policy bodies and credentials.
use serde_json::{Value, json};

fn object(properties: Value) -> Value {
    let required = properties.as_object().map(|fields| fields.keys().cloned().collect::<Vec<_>>()).unwrap_or_default();
    json!({"type":"object","additionalProperties":false,"required":required,"properties":properties})
}
fn reference(name: &str) -> Value {
    json!({"$ref":format!("#/components/schemas/{name}")})
}
fn nullable(name: &str) -> Value {
    json!({"oneOf":[reference(name),{"type":"null"}]})
}
fn array(name: &str, maximum: usize) -> Value {
    json!({"type":"array","maxItems":maximum,"items":reference(name)})
}

pub(super) fn describe(document: &mut Value) {
    let uuid = json!({"type":"string","format":"uuid"});
    let optional_uuid = json!({"type":["string","null"],"format":"uuid"});
    let time = json!({"type":"string","format":"date-time"});
    let optional_time = json!({"type":["string","null"],"format":"date-time"});
    let text = json!({"type":"string"});
    let optional_text = json!({"type":["string","null"]});
    let count = json!({"type":"integer","minimum":0});
    let positive = json!({"type":"integer","minimum":1});
    let policy_version = json!({"type":"integer","minimum":1,"maximum":4_294_967_295_u64});
    let limit = json!({"type":"integer","minimum":1,"maximum":2_147_483_647});
    let boolean = json!({"type":"boolean"});
    let sha256 = json!({"type":"string","pattern":"^[a-f0-9]{64}$"});
    let mode = json!({"enum":["RequestPerMinute","TokenPerMinute"]});
    let schemas = &mut document["components"]["schemas"];
    schemas["ApigPolicyRevisionInput"] = object(json!({"policy_id":uuid,"version":policy_version}));
    schemas["ApigPolicyRevision"] = object(json!({"policyId":uuid,"version":policy_version}));
    schemas["ApigPolicyBinding"] = object(json!({
        "httpApiId":{"type":"string","minLength":1,"maxLength":256},
        "gatewayId":{"type":"string","minLength":1,"maxLength":256},
        "environmentId":{"type":"string","minLength":1,"maxLength":256},
        "policyId":{"type":"string","minLength":1,"maxLength":256},
        "attachmentId":{"type":"string","minLength":1,"maxLength":256}
    }));
    schemas["ApigPolicyTarget"] = object(json!({
        "targetScopeId":uuid,"writeResourceId":uuid,"configurationId":uuid,"configurationVersion":positive,
        "sourceLabel":text,"region":text,"endpoint":{"type":"string","format":"uri"},
        "binding":reference("ApigPolicyBinding"),"mocked":boolean,
        "transportMode":{"enum":["mock","live","loopback-test"]}
    }));
    schemas["ApigPolicyTarget"]["description"] = json!(
        "原配置五ID及来源范围不可被恢复改写；writeResourceId由tenant+policyId确定，未知风险不因其它绑定字段变化消失。endpoint为已解析安全来源，未提供云账号归属/授权验证证据。"
    );
    schemas["ApigPolicySlot"] = object(json!({
        "managedLimit":mode,"currentLimit":{"type":["integer","null"],"minimum":1,"maximum":2_147_483_647},
        "supported":boolean,"reason":optional_text
    }));
    schemas["ApigPolicyObservation"] = object(json!({
        "id":uuid,"requestId":uuid,"target":reference("ApigPolicyTarget"),"startedAt":time,"observedAt":time,
        "fingerprint":sha256,"configHash":sha256,"slots":array("ApigPolicySlot",2),
        "contentHash":sha256,"contentBytes":{"type":"integer","minimum":0,"maximum":655_360},
        "usable":boolean,"reason":optional_text
    }));
    schemas["ApigPolicyObservation"]["description"] = json!(
        "fingerprint仅为完整证据的本地比较值，configHash为规范配置hash；二者均不是云ETag/版本/CAS令牌。unsupported slot的currentLimit=null，不能当作0。contentHash/contentBytes覆盖加密证据封装，不是公开正文。"
    );
    schemas["ApigPolicySourceLimit"] = object(json!({
        "policyId":uuid,"policyVersion":policy_version,"quotaId":uuid,"quotaVersion":positive,
        "quotaFingerprint":sha256,"managedLimit":mode,"limit":limit
    }));
    schemas["ApigPolicySourceChoice"] = object(json!({
        "policyId":uuid,"version":policy_version,"name":text,"eligible":boolean,
        "source":nullable("ApigPolicySourceLimit"),"reason":optional_text
    }));
    schemas["ApigPolicySources"] = object(json!({
        "items":array("ApigPolicySourceChoice",100),"page":positive,
        "pageSize":{"type":"integer","minimum":1,"maximum":100},
        "total":count,"policyCount":count,"eligibleCount":count,"totalPages":count,
        "truncated":boolean,"reason":optional_text
    }));
    schemas["ApigPolicySources"]["description"] = json!(
        "来源验证完整签名注册表与当前quota；total是当前筛选的完整总数，policyCount和eligibleCount不依分页。truncated表示仍有后页。eligible=false不补造可发布蓝本。"
    );
    schemas["ApigPolicyPreview"] = object(json!({
        "id":uuid,"requestId":uuid,"target":reference("ApigPolicyTarget"),"stateVersion":count,
        "action":{"enum":["publish","rollback"]},"sourcePublicationId":optional_uuid,
        "observationId":uuid,"baselineObservedAt":time,"baselineFingerprint":sha256,"baselineConfigHash":sha256,
        "managedLimit":mode,"previousLimit":limit,"desiredLimit":limit,"desiredHash":sha256,
        "desiredBytes":{"type":"integer","minimum":0,"maximum":65_536},
        "sourcePolicyVersions":array("ApigPolicyRevision",1),"currentPolicyVersions":array("ApigPolicyRevision",1),
        "expiresAt":time,"previewUsable":boolean,"reason":optional_text,"consumedBy":optional_uuid,
        "casSemantics":{"const":"none"},"noCloudCas":{"const":true},
        "sharedPolicyImpact":{"type":"null"},"consumerApplied":{"type":"null"},
        "acknowledgeUnknownOperationId":optional_uuid,"unknownOverlapWarning":boolean,
        "allowedActions":{"type":"array","uniqueItems":true,"items":{"enum":["apply","read_receipt"]}}
    }));
    schemas["ApigPolicyOperation"] = object(json!({
        "requestId":uuid,"previewId":uuid,"target":reference("ApigPolicyTarget"),
        "action":{"enum":["publish","rollback"]},"sourcePublicationId":optional_uuid,
        "startedAt":time,"submittedAt":time,"finishedAt":optional_time,"leaseExpiresAt":time,
        "status":{"enum":["started","verified","conflict","failed","uncertain","superseded","archived"]},
        "originalStatus":{"type":["string","null"]},"archived":boolean,"archivedAt":optional_time,"archivable":boolean,
        "cloudWrite":object(json!({"status":{"enum":["not_attempted","attempting","accepted","unknown"]},
            "providerRequestId":{"type":["string","null"],"maxLength":256}})),
        "readback":object(json!({"status":{"enum":["not_attempted","matched","different","unavailable"]},
            "observedAt":optional_time,"currentHash":optional_text})),
        "localPublication":object(json!({"status":{"enum":["not_staged","pending_audit","published"]}})),
        "completionState":{"enum":["running","pending_audit","complete"]},"safeReason":optional_text,
        "consumerApplied":{"type":"null"},"supersededBy":optional_uuid,"sourceCurrent":{"type":["boolean","null"]},
        "sourcePolicyVersions":array("ApigPolicyRevision",1),
        "currentPolicyVersions":{"oneOf":[array("ApigPolicyRevision",1),{"type":"null"}]},
        "recoveryScopeId":optional_uuid,"recoveryConfigurationVersion":{"type":["integer","null"],"minimum":1},
        "allowedActions":{"type":"array","uniqueItems":true,"items":{"enum":["read_receipt","observe","recover_local","archive"]}}
    }));
    schemas["ApigPolicyOperation"]["description"] = json!(
        "verified要求原请求Accepted ACK、独立Matched回读及本地Published。Unknown始终是原请求的未知因果；后续当前匹配不能将其升级。sourceCurrent未知为null，原sourcePolicyVersions永久保留，恢复字段及allowedActions是当前资格。"
    );
    schemas["ApigPolicyPublicationHistory"] = object(json!({
        "publicationId":uuid,"target":reference("ApigPolicyTarget"),"verifiedAt":time,
        "contentHash":sha256,"contentBytes":{"type":"integer","minimum":0,"maximum":65_536},
        "sourcePolicyVersions":array("ApigPolicyRevision",1),"rollbackAvailable":boolean,"reason":optional_text
    }));
    schemas["ApigPolicyPublicationHistory"]["description"] = json!(
        "仅同目标已verified且正文未归档的历史；rollback仍须新的当前观察、同计量维度及可信当前版本围栏。只恢复历史previousLimit，不能覆盖外部新增规则或回退平台注册表。"
    );
    schemas["ApigPolicyLimits"] = object(json!({
        "maxPolicies":{"const":1},"maxContentBytes":{"const":655_360},"maxProviderConfigBytes":{"const":65_536},
        "maxRecordBytes":{"const":1_048_576},"maxMainBytes":{"const":4_194_304},"maxAggregateAgentIds":{"const":500},
        "maxStoredContentBytes":{"const":67_108_864},"maxDetailedRuns":{"const":128},
        "maxPreviews":{"const":32},"maxObservations":{"const":8},"maxArchive":{"const":100},
        "maxDriverSeconds":{"const":30},"maxOperationSeconds":{"const":110},"leaseSeconds":{"const":120},
        "previewSeconds":{"const":120},"observationSeconds":{"const":300}
    }));
    schemas["ApigPolicyPublicationState"] = object(json!({
        "sources":reference("ApigPolicySources"),"canInitializeMockFixture":boolean,
        "configured":boolean,"enabled":{"type":["boolean","null"]},"binding":nullable("ApigPolicyTarget"),
        "stateVersion":count,"generation":count,"canObserve":boolean,"canPrepare":boolean,"canApply":boolean,
        "bindingReason":optional_text,"busy":boolean,"leaseExpiresAt":optional_time,"unresolvedOperationId":optional_uuid,
        "observation":nullable("ApigPolicyObservation"),"operations":array("ApigPolicyOperation",50),
        "history":array("ApigPolicyPublicationHistory",50),"detailedRunCount":count,"archivedCount":count,
        "storedContentBytes":count,"limits":reference("ApigPolicyLimits"),
        "consumerApplied":{"type":"null"},"sharedPolicyImpact":{"type":"null"},"noCloudCas":{"const":true}
    }));
    schemas["ApigPolicyArchiveResult"] = object(json!({
        "generation":count,"archivedCount":count,"unchanged":boolean,
        "archivedRequestIds":{"type":"array","maxItems":100,"uniqueItems":true,"items":uuid}
    }));
}
