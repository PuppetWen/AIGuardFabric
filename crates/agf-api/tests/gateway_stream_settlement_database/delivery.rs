//! A complete explicit fallback may end normally even when the earlier fee evidence is unknown.
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact-owned gateway stream SQL; only literal127 provider"]
async fn complete_streaming_fallback_preserves_failure_audit_and_committed_protocol_end() -> DomainResult<()> {
    let owned = Owned::open("gw-stream-fallback").await?;
    let left = Provider::start(Reply::HttpFailure).await?;
    let right = Provider::start(Reply::Known).await?;
    let fixture = Fixture::new(&owned, &[&left, &right]).await?;
    let response = fixture.call(stream(), "owned-intentional-fallback").await?;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.text.matches("[DONE]").count(), 1);
    assert!(!response.text.contains("api_error"));
    let id = attempt(&response)?;
    let receipt = invariant(&owned, &fixture, id, "sent-usage-unknown").await?;
    assert_eq!(receipt["components"][0]["evidence"], "sent-usage-known");
    assert_eq!(receipt["components"][0]["costMicro"], 100);
    let fact = owned.body(&fixture.h, id, FACT).await?;
    let estimated = fact["charge"]["chats"][0]["cost"].as_i64().ok_or_else(invalid)?;
    assert_eq!(fixture.used(&fixture.h, "cost").await?, estimated + 100);
    let pending = owned.body(&fixture.h, id, PENDING).await?;
    assert_eq!(pending["outcome"]["rejection"]["reason"], "provider");
    assert_eq!(serde_json::to_value(owned.audit(id).await?[0].outcome)?, json!("failure"));
    let usage = agf_api::gateway_quota::usage(&fixture.h.state, fixture.h.tenant).await?;
    assert_eq!(usage.len(), 1);
    assert_eq!(json!(usage[0].id), receipt["components"][0]["usageId"]);
    assert_eq!(usage[0].cost_micro, 100);
    pure_restart(&owned, &fixture, id, &receipt).await?;
    assert_eq!((left.calls(), right.calls()), (1, 1));
    owned.case.pool.close().await;
    Ok(())
}
