//! Native request identity, leases and the last guard after queue/STS waits.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
mod team_management_helpers;
mod team_management_loopback_helpers;
use agf_core::ids::Id;
use common::*;
use team_management_helpers::*;
use team_management_loopback_helpers::*;
use wiremock::{
    Mock, MockServer, Request as CloudRequest, Respond, ResponseTemplate,
    matchers::{method, query_param},
};

#[tokio::test]
async fn preview_request_identity_is_global_across_different_teams() {
    let f = Fixture::mock().await;
    let request = Id::new();
    let mut a = preview_body(create("preview-a", json!([])), 0, false);
    a["request_id"] = json!(request);
    let mut b = a.clone();
    b["change"]["team_name"] = json!("preview-b");
    let uri = format!("{BASE}/previews");
    let (left, right) = tokio::join!(f.h.post(&uri, a.clone()), f.h.post(&uri, b.clone()));
    assert_eq!(
        [left.status, right.status].iter().filter(|status| status.is_success()).count(),
        1,
        "{} / {}",
        left.text,
        right.text
    );
    assert_eq!([left.status, right.status].iter().filter(|status| **status == StatusCode::CONFLICT).count(), 1);
    let (saved, body) = if left.status.is_success() { (left.json(), a) } else { (right.json(), b) };
    assert_eq!(result(f.h.post(&format!("{BASE}/previews"), body).await), saved);
    assert_eq!(f.writes("CreateTeam").await, 0);
    assert_eq!(f.writes("ListUsers").await, 0, "explicit empty members do not need a user directory");
}

#[tokio::test]
async fn operation_request_identity_has_one_claim_even_across_distinct_team_records() {
    let f = Fixture::mock().await;
    let a = result(f.preview(create("operation-a", json!([]))).await);
    let b = result(f.preview(create("operation-b", json!([]))).await);
    let request = Id::new();
    let (left, right) = tokio::join!(f.apply(&a, request), f.apply(&b, request));
    assert_eq!(
        [left.status, right.status].iter().filter(|status| status.is_success()).count(),
        1,
        "{} / {}",
        left.text,
        right.text
    );
    assert_eq!([left.status, right.status].iter().filter(|status| **status == StatusCode::CONFLICT).count(), 1);
    let (saved, preview) = if left.status.is_success() { (left.json(), a) } else { (right.json(), b) };
    verified(&saved);
    assert_eq!(result(f.apply(&preview, request).await), saved);
    assert_eq!(f.writes("CreateTeam").await, 1);
    let found = result(f.h.get(&format!("{BASE}?request_id={request}")).await);
    assert_eq!(
        found["operations"].as_array().unwrap().len(),
        1,
        "global lookup must not be overwritten by a second resource"
    );
    assert_eq!(found["operations"][0]["id"], saved["id"]);
}

async fn wait_claim(f: &Fixture) -> Value {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let rows = f.h.state.configurations.list::<Value>(f.h.tenant, STATE_KIND).await.unwrap();
            if let Some(row) = rows.into_iter().find(|row| {
                row["team_name"] == TEAM
                    && row["active"]["run"]
                        .as_str()
                        .is_some_and(|run| row["operations"][run]["cloud_write"]["status"] == "attempting")
            }) {
                return row;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap()
}
async fn rotate(rpc: &FixtureRpc, enabled: bool) {
    let changed = rpc
        .f
        .h
        .request(
            "PUT",
            CLOUD,
            Some(&rpc.f.h.admin),
            Some(json!({"expected_version":1,
        "enabled":enabled,"mock":false,"settings":{"instance_id":INSTANCE,"account_id":"team-test-account",
        "endpoint":rpc.server.uri()},"secrets":{}})),
        )
        .await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.text);
}

#[tokio::test]
async fn a_configuration_change_during_the_runtime_queue_prevents_provider_dispatch() {
    let mut rpc = FixtureRpc::new().await;
    let preview = result(rpc.f.preview(update(TEAM, "Must not escape a stale queue")).await);
    while rpc.observed.try_recv().is_ok() {}
    rpc.cloud.lock().unwrap().read_delay = Some("GetUser".into());
    let h = rpc.f.h.clone();
    let blocker = tokio::spawn(async move {
        h.post(
            &format!("{CLOUD}/operations"),
            json!({"request_id":Id::new(),
        "configuration_version":1,"confirm_live":true,"action":"GetUser","parameters":{"Name":"member-user"}}),
        )
        .await
    });
    rpc.wait_action("GetUser").await;
    let h = rpc.f.h.clone();
    let body = apply_body(&preview, Id::new(), true);
    let pending = tokio::spawn(async move { h.post(&format!("{BASE}/operations"), body).await });
    let claim = wait_claim(&rpc.f).await;
    assert_eq!(rpc.write_count("UpdateTeam"), 0);
    rotate(&rpc, false).await;
    result(blocker.await.unwrap());
    let completed = pending.await.unwrap();
    if completed.status.is_success() {
        assert_eq!(completed.json()["status"], "superseded");
    }
    assert_eq!(
        rpc.write_count("UpdateTeam"),
        0,
        "the last guard must re-read configuration after acquiring the runtime mutex"
    );
    let row = rpc
        .f
        .h
        .state
        .configurations
        .get::<Value>(rpc.f.h.tenant, STATE_KIND, Id::parse(claim["id"].as_str().unwrap()).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_ne!(row["operations"][claim["active"]["run"].as_str().unwrap()]["status"], "verified");
}

#[tokio::test]
async fn an_expired_operation_lease_in_the_runtime_queue_cannot_send_after_the_wait() {
    let mut rpc = FixtureRpc::new().await;
    let preview = result(rpc.f.preview(update(TEAM, "Old expired writer cannot resume")).await);
    while rpc.observed.try_recv().is_ok() {}
    rpc.cloud.lock().unwrap().read_delay = Some("GetUser".into());
    let h = rpc.f.h.clone();
    let blocker = tokio::spawn(async move {
        h.post(
            &format!("{CLOUD}/operations"),
            json!({"request_id":Id::new(),
        "configuration_version":1,"confirm_live":true,"action":"GetUser","parameters":{"Name":"member-user"}}),
        )
        .await
    });
    rpc.wait_action("GetUser").await;
    let h = rpc.f.h.clone();
    let body = apply_body(&preview, Id::new(), true);
    let pending = tokio::spawn(async move { h.post(&format!("{BASE}/operations"), body).await });
    let mut row = wait_claim(&rpc.f).await;
    let record_id = Id::parse(row["id"].as_str().unwrap()).unwrap();
    let run = row["active"]["run"].as_str().unwrap().to_owned();
    row["active"]["expires_at"] = json!(Timestamp::now().offset_secs(-1));
    row["operations"][&run]["lease_expires_at"] = json!(Timestamp::now().offset_secs(-1));
    rpc.f.h.state.configurations.put(rpc.f.h.tenant, STATE_KIND, record_id, &row).await.unwrap();
    result(blocker.await.unwrap());
    let completed = pending.await.unwrap();
    assert!(completed.status.is_success(), "{}", completed.text);
    assert_ne!(completed.json()["status"], "verified");
    assert_eq!(completed.json()["busy"], false);
    assert_eq!(rpc.write_count("UpdateTeam"), 0);
    let consumed = result(rpc.f.h.get(&format!("{BASE}/previews/{}", preview["id"].as_str().unwrap())).await);
    assert_eq!(consumed["previewUsable"], false);
    assert_eq!(consumed["unusableReason"], "consumed");
    let fresh = result(rpc.f.preview(update(TEAM, "A new explicit preview is required")).await);
    assert_eq!(fresh["previewUsable"], true);
}

#[derive(Clone)]
struct Sts {
    started: tokio::sync::mpsc::UnboundedSender<()>,
    delayed: Arc<std::sync::atomic::AtomicBool>,
}
impl Respond for Sts {
    fn respond(&self, _request: &CloudRequest) -> ResponseTemplate {
        let _ = self.started.send(());
        let response = ResponseTemplate::new(200).set_body_json(json!({"Credentials":{
            "AccessKeyId":"LOCAL-STS-ID","AccessKeySecret":"LOCAL-STS-SECRET","SecurityToken":"LOCAL-STS-TOKEN",
            "Expiration":Timestamp::now().offset_secs(1800).to_rfc3339()}}));
        if self.delayed.load(std::sync::atomic::Ordering::SeqCst) {
            response.set_delay(std::time::Duration::from_millis(700))
        } else {
            response
        }
    }
}

#[tokio::test]
async fn a_configuration_change_during_sts_resolution_prevents_the_confirmed_cloud_write() {
    let sts = MockServer::start().await;
    let (started, mut observed) = tokio::sync::mpsc::unbounded_channel();
    let delayed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    Mock::given(method("POST"))
        .and(query_param("Action", "AssumeRole"))
        .respond_with(Sts { started, delayed: delayed.clone() })
        .mount(&sts)
        .await;
    let mut rpc = FixtureRpc::with_settings(json!({"credential_source":"assume-role","sts_endpoint":sts.uri(),
        "role_arn":"acs:ram::1234567890123456:role/team-test"}))
    .await;
    let preview = result(rpc.f.preview(update(TEAM, "Never write with newly stale credentials")).await);
    while observed.try_recv().is_ok() {}
    rpc.restart_runtime();
    delayed.store(true, std::sync::atomic::Ordering::SeqCst);
    let h = rpc.f.h.clone();
    let body = apply_body(&preview, Id::new(), true);
    let pending = tokio::spawn(async move { h.post(&format!("{BASE}/operations"), body).await });
    tokio::time::timeout(std::time::Duration::from_secs(3), observed.recv()).await.unwrap().unwrap();
    wait_claim(&rpc.f).await;
    rotate(&rpc, false).await;
    let completed = pending.await.unwrap();
    if completed.status.is_success() {
        assert_eq!(completed.json()["status"], "superseded");
    }
    assert_eq!(rpc.write_count("UpdateTeam"), 0, "STS resolution must be followed by current target/lease validation");
    assert!(!completed.text.contains("LOCAL-STS-SECRET") && !completed.text.contains("LOCAL-STS-TOKEN"));
}
