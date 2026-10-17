#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
#[tokio::test]
async fn seven_typed_routes_have_strict_schema_and_no_connectivity_claim() {
    let h = setup().await;
    let d = h.get("/api/v1/openapi.json").await.json();
    let root = "/api/v1/alicloud/privatelink/provisioning";
    for (suffix, method, grants) in [
        ("", "get", json!(["alicloud:read"])),
        ("/requests/{id}", "get", json!(["alicloud:read"])),
        ("/preview", "post", json!(["alicloud:read", "alicloud:write"])),
        ("/apply", "post", json!(["alicloud:read", "alicloud:write"])),
        ("/observe", "post", json!(["alicloud:read", "alicloud:write"])),
        ("/requests/{id}/recover-local", "post", json!(["alicloud:read", "alicloud:write"])),
        ("/archive", "post", json!(["alicloud:read", "alicloud:write"])),
    ] {
        let op = &d["paths"][format!("{root}{suffix}")][method];
        assert!(op.is_object());
        assert_eq!(op["x-required-permissions"], grants);
    }
    let s = &d["components"]["schemas"];
    assert_eq!(s["PrivateLinkProvisioningReceipt"]["additionalProperties"], false);
    assert_eq!(s["PrivateLinkProvisioningReceipt"]["properties"]["canRedispatch"]["const"], false);
    assert_eq!(s["PrivateLinkProvisioningState"]["properties"]["limits"]["properties"]["archiveBatch"]["const"], 32);
    assert_eq!(s["PrivateLinkProvisioningSource"]["properties"]["accountIdentityVerified"]["const"], false);
    assert!(s["PrivateLinkProvisioningState"]["properties"]["inventorySelection"].is_object());
}
