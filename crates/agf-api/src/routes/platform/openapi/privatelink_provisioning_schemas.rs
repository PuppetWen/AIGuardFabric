use serde_json::{Value, json};
fn object(properties: Value) -> Value {
    let keys = properties.as_object().map(|m| m.keys().cloned().collect::<Vec<_>>()).unwrap_or_default();
    json!({"type":"object","additionalProperties":false,"required":keys,"properties":properties})
}
fn uuid() -> Value {
    json!({"type":"string","format":"uuid"})
}
fn nullable() -> Value {
    json!({"type":["string","null"]})
}
fn n() -> Value {
    json!({"type":"integer","minimum":0})
}
fn b() -> Value {
    json!({"type":"boolean"})
}
fn reference(name: &str) -> Value {
    json!({"$ref":format!("#/components/schemas/{name}")})
}
pub(super) fn register(s: &mut Value) {
    s["PrivateLinkCreateTarget"] = object(
        json!({"region_id":{"type":"string","minLength":1,"maxLength":64},"service_region_id":{"type":"string","minLength":1,"maxLength":64},"service_id":{"type":"string","pattern":"^epsrv-[A-Za-z0-9-]+$","maxLength":70},"vpc_id":{"type":"string","pattern":"^vpc-[A-Za-z0-9-]+$","maxLength":68},"name":{"type":"string","minLength":2,"maxLength":128},"zones":{"type":"array","minItems":1,"maxItems":10,"items":object(json!({"zone_id":{"type":"string","maxLength":64},"vswitch_id":{"type":"string","maxLength":68}}))},"security_group_ids":{"type":"array","minItems":1,"maxItems":10,"uniqueItems":true,"items":{"type":"string","maxLength":67}},"cross_region_bandwidth":{"type":["integer","null"],"minimum":100,"maximum":50_000}}),
    );
    if let Some(keys) = s["PrivateLinkCreateTarget"]["required"].as_array_mut() {
        keys.retain(|v| v != "cross_region_bandwidth");
    }
    s["PrivateLinkProvisioningSource"] = object(
        json!({"configurationId":uuid(),"configurationVersion":{"type":"integer","minimum":1},"configuredAccountLabel":{"type":"string","maxLength":256},"accountIdentityVerified":{"const":false},"region":{"type":"string","maxLength":64},"transportMode":{"enum":["mock","live","loopback_test"]},"mocked":b()}),
    );
    s["PrivateLinkProvisioningResult"] = json!({"oneOf":[object(json!({"kind":{"const":"preview"},"expiresAt":{"type":"string","format":"date-time"},"baseGeneration":n()})),object(json!({"kind":{"const":"write"},"delivery":{"enum":["not_sent","acknowledged","rejected","unknown"]},"providerRequestId":{"type":["string","null"],"format":"uuid"},"endpointId":nullable(),"finishedAt":{"type":"string","format":"date-time"}})),object(json!({"kind":{"const":"observation"},"endpointId":{"type":"string"},"endpointState":{"type":"string"},"connectionState":{"type":"string"},"requestedResourcesMatch":{"const":true},"connectivityVerified":{"const":false},"checkedAt":{"type":"string","format":"date-time"},"originalCreateRequestId":{"type":["string","null"],"format":"uuid"},"inventoryScopeId":{"type":["string","null"],"format":"uuid"},"serviceId":{"type":"string"},"vpcId":{"type":"string"},"region":{"type":"string"},"serviceRegion":{"type":"string"}})),object(json!({"kind":{"const":"failed_read"}})),object(json!({"kind":{"const":"archive"},"changedCount":n(),"generation":n()})),{"type":"null"}]});
    s["PrivateLinkProvisioningSummary"] = object(
        json!({"serviceId":{"type":"string"},"vpcId":{"type":"string"},"region":{"type":"string"},"serviceRegion":{"type":"string"},"name":{"type":"string"},"zones":{"type":"array","minItems":1,"maxItems":10,"items":object(json!({"zoneId":{"type":"string"},"vSwitchId":{"type":"string"}}))},"securityGroupIds":{"type":"array","minItems":1,"maxItems":10,"items":{"type":"string"}},"crossRegionBandwidth":{"type":["integer","null"],"minimum":100,"maximum":50_000},"endpointId":nullable()}),
    );
    s["PrivateLinkProvisioningReceipt"] = object(
        json!({"requestId":uuid(),"purpose":{"enum":["preview","apply","observe","archive"]},"inputHash":{"type":"string","pattern":"^[a-f0-9]{64}$"},"submittedAt":{"type":"string","format":"date-time"},"admittedAt":{"type":"string","format":"date-time"},"startedAt":{"type":["string","null"],"format":"date-time"},"leaseExpiresAt":{"type":"string","format":"date-time"},"phase":{"enum":["admitted","started","complete"]},"completionState":{"enum":["complete","pending_audit","uncertain","in_flight"]},"originalSource":{"oneOf":[reference("PrivateLinkProvisioningSource"),{"type":"null"}]},"sourceCurrent":b(),"action":{"enum":["CreateVpcEndpoint","EnableVpcEndpointConnection",null]},"resourceSummary":{"oneOf":[reference("PrivateLinkProvisioningSummary"),{"type":"null"}]},"referenceRequestId":{"type":["string","null"],"format":"uuid"},"result":reference("PrivateLinkProvisioningResult"),"archived":b(),"archivedAt":{"type":["string","null"],"format":"date-time"},"canRecoverLocal":b(),"canArchive":b(),"canRedispatch":{"const":false},"automaticRetry":{"const":false},"connectivityVerified":{"const":false},"ramAuthorizationVerified":{"const":false}}),
    );
    s["PrivateLinkProvisioningState"] = object(
        json!({"generation":n(),"storedContentBytes":n(),"permanentFactCount":n(),"page":{"type":"integer","minimum":1,"maximum":u32::MAX},"pageSize":{"type":"integer","minimum":1,"maximum":50},"total":n(),"requests":{"type":"array","maxItems":50,"items":reference("PrivateLinkProvisioningReceipt")},"source":{"oneOf":[reference("PrivateLinkProvisioningSource"),{"type":"null"}]},"inventorySelection":{"oneOf":[object(json!({"scopeId":uuid(),"endpointId":{"type":"string"},"serviceId":{"type":"string"},"vpcId":{"type":"string"},"checkedAt":{"type":"string","format":"date-time"}})),{"type":"null"}]},"unresolvedWriteCount":n(),"limits":object(json!({"detailedRequests":{"const":128},"permanentFacts":{"const":4096},"archiveBatch":{"const":32},"bodyBytes":{"const":2_097_152},"originalSeconds":{"const":110},"previewSeconds":{"const":300}})),"automaticRetry":{"const":false},"exactlyOnce":{"const":false},"connectivityVerified":{"const":false},"ramAuthorizationVerified":{"const":false}}),
    );
}
