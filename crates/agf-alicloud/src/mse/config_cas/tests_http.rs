use super::{tests::key, tests_http_support::*, *};
use serde_json::json;
use std::sync::Mutex;

#[tokio::test]
async fn real_http_tuple_form_signing_and_persistent_readback_match() {
    let content = Arc::new(Mutex::new("old\r\n".to_string()));
    let stored = content.clone();
    let server = Server::start(move |request| {
        let mut content = stored.lock().unwrap();
        if request.method == "GET" {
            return Reply::json(
                200,
                json!({"code":0,"message":"success","data":*content}),
                &[("Content-MD5", query::content_md5(&content))],
            );
        }
        let form = parsed_pairs(&request.body);
        assert_eq!(request.headers["casmd5"], query::content_md5(&content));
        *content = form["content"].clone();
        Reply::json(200, json!({"code":0,"message":"success","data":true}), &[])
    })
    .await;
    let client = server.client(Limits::default());
    let before = client.query(&key(), &allow()).await.unwrap();
    let desired = "{\"说明\":\"空格 + & = %\"}\r\n";
    assert_eq!(client.publish(&key(), &before.md5, desired, &allow()).await.unwrap(), PublishOutcome::Accepted);
    assert_eq!(client.query(&key(), &allow()).await.unwrap().content, desired);
    let requests = server.requests.lock().unwrap();
    assert_eq!(requests.len(), 3);
    let (_, query) = requests[0].target.split_once('?').unwrap();
    let expected = key();
    assert_eq!(
        parsed_pairs(query),
        expected
            .pairs()
            .into_iter()
            .map(|(key, value)| (key.into(), value.into()))
            .collect::<std::collections::BTreeMap<_, _>>()
    );
    let form = parsed_pairs(&requests[1].body);
    assert_eq!(form.len(), 5);
    assert_eq!(form["namespaceId"], expected.namespace_id);
    assert_eq!(form["dataId"], expected.data_id);
    assert_eq!(form["group"], expected.group);
    assert_eq!(form["content"], desired);
    assert_eq!(form["type"], "json");
    assert_eq!(requests[1].target, "/nacos/v2/cs/config");
    for request in requests.iter() {
        let timestamp = request.headers["timestamp"].parse().unwrap();
        assert_eq!(
            request.headers["spas-signature"],
            signing::signature(&key(), "owned-sdk-vector-secret", timestamp).unwrap()
        );
        assert!(!request.target.contains("owned-vector-ak"));
        assert!(!request.body.contains("owned-sdk-vector-secret"));
    }
}

#[tokio::test]
async fn conflict_is_not_retried_and_ordinary_server_error_is_uncertain() {
    for (code, expected) in
        [(20005, PublishOutcome::Conflict), (30000, PublishOutcome::Uncertain(UncertainReason::Protocol))]
    {
        let server = Server::start(move |_| Reply::json(500, json!({"code":code,"message":"failure"}), &[])).await;
        assert_eq!(
            server
                .client(Limits::default())
                .publish(&key(), &query::content_md5("old"), "new", &allow())
                .await
                .unwrap(),
            expected
        );
        assert_eq!(server.count(), 1);
    }
}

#[tokio::test]
async fn redirect_does_not_send_credentials_to_another_origin() {
    let other = Server::start(|_| Reply::json(200, json!({"code":0,"message":"success","data":true}), &[])).await;
    let location = format!("{}/nacos/v2/cs/config", other.origin);
    let server = Server::start(move |_| {
        Reply::json(307, json!({"code":0,"message":"redirect","data":true}), &[("Location", location.clone())])
    })
    .await;
    let result =
        server.client(Limits::default()).publish(&key(), &query::content_md5("old"), "new", &allow()).await.unwrap();
    assert_eq!(result, PublishOutcome::Uncertain(UncertainReason::Protocol));
    assert_eq!(server.count(), 1);
    assert_eq!(other.count(), 0);
}

#[tokio::test]
async fn provider_and_guard_deadlines_are_inside_the_budget_without_transport() {
    let server = Server::start(|_| Reply::json(200, json!({"code":0,"message":"success","data":true}), &[])).await;
    let budget = Limits { timeout: Duration::from_millis(40), ..Limits::default() };
    let client = NacosConfigClient::new(
        EngineEndpoint::literal_loopback_for_test(&server.origin).unwrap(),
        Arc::new(Provider { delay: Duration::from_secs(1), credential: tests::credential() }),
        budget,
    )
    .unwrap();
    assert!(matches!(
        client.publish(&key(), &query::content_md5("old"), "new", &allow()).await,
        Err(DomainError::Timeout(_))
    ));
    let client = server.client(budget);
    let slow = Guard { delay: Duration::from_secs(1), reject: false };
    assert!(matches!(client.query(&key(), &slow).await, Err(DomainError::Timeout(_))));
    assert_eq!(server.count(), 0);
}

#[tokio::test]
async fn a_non_yielding_provider_cannot_dispatch_after_the_deadline() {
    let server = Server::start(|_| Reply::json(200, json!({"code":0,"message":"success","data":true}), &[])).await;
    let client = NacosConfigClient::new(
        EngineEndpoint::literal_loopback_for_test(&server.origin).unwrap(),
        Arc::new(BlockingProvider),
        Limits { timeout: Duration::from_millis(20), ..Limits::default() },
    )
    .unwrap();
    assert!(matches!(client.query(&key(), &allow()).await, Err(DomainError::Timeout(_))));
    assert!(matches!(
        client.publish(&key(), &query::content_md5("old"), "new", &allow()).await,
        Err(DomainError::Timeout(_))
    ));
    assert_eq!(server.count(), 0);
}

#[tokio::test]
async fn authority_rejection_and_credentials_expiring_during_guard_send_nothing() {
    let server = Server::start(|_| Reply::json(200, json!({"code":0,"message":"success","data":true}), &[])).await;
    let reject = Guard { delay: Duration::ZERO, reject: true };
    assert!(matches!(
        server.client(Limits::default()).publish(&key(), &query::content_md5("old"), "new", &reject).await,
        Err(DomainError::Forbidden(_))
    ));
    let client = NacosConfigClient::new(
        EngineEndpoint::literal_loopback_for_test(&server.origin).unwrap(),
        Arc::new(ExpiringProvider),
        Limits::default(),
    )
    .unwrap();
    let started = tokio::time::Instant::now();
    assert!(matches!(
        client
            .publish(
                &key(),
                &query::content_md5("old"),
                "new",
                &Guard { delay: Duration::from_millis(2100), reject: false }
            )
            .await,
        Err(DomainError::Unauthenticated(_))
    ));
    assert!(started.elapsed() >= Duration::from_millis(2100));
    assert_eq!(server.count(), 0);
}

#[tokio::test]
async fn lost_or_truncated_response_never_replays_a_delivered_write() {
    for raw in [Vec::new(), b"HTTP/1.1 200 Test\r\nContent-Type: application/json\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{\"code\":0}".to_vec(),
        b"HTTP/1.1 200 Test\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n20\r\n{\"code\":0}".to_vec()] {
        let server = Server::start(move |_| Reply { raw: raw.clone(), delay: Duration::ZERO }).await;
        assert_eq!(server.client(Limits::default()).publish(&key(), &query::content_md5("old"), "new", &allow()).await.unwrap(),
            PublishOutcome::Uncertain(UncertainReason::Transport));
        assert_eq!(server.count(), 1);
    }
}

#[tokio::test]
async fn slow_write_response_is_uncertain_and_does_not_auto_repeat() {
    let server = Server::start(|_| {
        let mut reply = Reply::json(200, json!({"code":0,"message":"success","data":true}), &[]);
        reply.delay = Duration::from_secs(1);
        reply
    })
    .await;
    let result = server
        .client(Limits { timeout: Duration::from_millis(60), ..Limits::default() })
        .publish(&key(), &query::content_md5("old"), "new", &allow())
        .await
        .unwrap();
    assert!(matches!(result, PublishOutcome::Uncertain(UncertainReason::Deadline | UncertainReason::Transport)));
    assert_eq!(server.count(), 1);
}

#[tokio::test]
async fn chunked_and_declared_large_responses_are_bounded_after_dispatch() {
    for chunked in [false, true] {
        let server = Server::start(move |_| {
            let body = "x".repeat(512);
            let raw = if chunked { format!("HTTP/1.1 200 Test\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n200\r\n{body}\r\n0\r\n\r\n") }
                else { format!("HTTP/1.1 200 Test\r\nContent-Type: application/json\r\nContent-Length: 512\r\nConnection: close\r\n\r\n{body}") };
            Reply { raw: raw.into_bytes(), delay: Duration::ZERO }
        }).await;
        assert_eq!(
            server
                .client(Limits { max_response_bytes: 128, ..Limits::default() })
                .publish(&key(), &query::content_md5("old"), "new", &allow())
                .await
                .unwrap(),
            PublishOutcome::Uncertain(UncertainReason::ResponseLimit)
        );
        assert_eq!(server.count(), 1);
    }
}

#[tokio::test]
async fn empty_publication_is_valid_but_invalid_baselines_send_nothing() {
    let server = Server::start(|request| {
        assert_eq!(parsed_pairs(&request.body)["content"], "");
        Reply::json(200, json!({"code":0,"message":"success","data":true}), &[])
    })
    .await;
    let client = server.client(Limits::default());
    assert!(client.publish(&key(), "not-md5", "new", &allow()).await.is_err());
    assert_eq!(server.count(), 0);
    assert_eq!(
        client.publish(&key(), &query::content_md5("old"), "", &allow()).await.unwrap(),
        PublishOutcome::Accepted
    );
    assert_eq!(server.count(), 1);
}
