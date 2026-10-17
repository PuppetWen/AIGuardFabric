use tokio::time::{Duration, Instant};

use super::test_server::{KEY, Reply, Server, configuration, reservation, valid_response};
use super::{
    EmbeddingCancellation, EmbeddingClient, EmbeddingDispatch, EmbeddingFailure, EmbeddingOutcome, EmbeddingProfile,
    MAX_INPUT_BYTES, MAX_RESPONSE_BYTES,
};

#[tokio::test]
async fn explicit_single_float_request_retains_pinned_generation_and_separate_paid_cost() {
    let server = Server::new(Reply::json(&valid_response(19))).await;
    let client = server.client();
    let attempt = client
        .embed(
            "owned synthetic input",
            30,
            reservation(30),
            Instant::now() + Duration::from_secs(2),
            &EmbeddingCancellation::default(),
        )
        .await;
    assert!(matches!(attempt.outcome, EmbeddingOutcome::Vector(_)));
    assert_eq!(attempt.configuration_version, 7);
    assert_eq!(attempt.model_revision, "owned-revision-20261001");
    assert_eq!(attempt.configured_cost_micro, Some(10));
    assert_eq!(attempt.usage.unwrap().total_tokens, 19);
    assert_eq!(attempt.dispatch, EmbeddingDispatch::ResponseReceived);
    assert_eq!(server.accepted(), 1);
    let request = &server.requests()[0];
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/v1/embeddings");
    assert!(request.authorization_matches && request.accepts_identity);
    assert_eq!(request.json["model"], "owned-embedding-model");
    assert_eq!(request.json["input"], "owned synthetic input");
    assert_eq!(request.json["encoding_format"], "float");
    assert_eq!(request.json["dimensions"], 3);
    assert!(!format!("{attempt:?}").contains("owned synthetic input"));
}

#[tokio::test]
async fn older_configured_model_omits_dimensions_but_validates_the_returned_dimension() {
    let server = Server::new(Reply::json(&valid_response(5))).await;
    let mut config = configuration(server.origin.clone());
    config.send_dimensions = false;
    let client =
        EmbeddingClient::from_service_profile(EmbeddingProfile::literal_loopback_for_test(config).unwrap(), KEY)
            .unwrap();
    let result = client
        .embed("owned", 5, reservation(5), Instant::now() + Duration::from_secs(2), &EmbeddingCancellation::default())
        .await;
    assert!(matches!(result.outcome, EmbeddingOutcome::Vector(_)));
    assert!(server.requests()[0].json.get("dimensions").is_none());
}

#[tokio::test]
async fn exact_input_byte_limit_remains_usable_with_a_trusted_conservative_token_reservation() {
    let server = Server::new(Reply::json(&valid_response(19))).await;
    let input = "a".repeat(MAX_INPUT_BYTES);
    let result = server
        .client()
        .embed(
            &input,
            8192,
            reservation(8192),
            Instant::now() + Duration::from_secs(2),
            &EmbeddingCancellation::default(),
        )
        .await;
    assert!(matches!(result.outcome, EmbeddingOutcome::Vector(_)));
    assert_eq!(server.requests()[0].json["input"].as_str().unwrap().len(), MAX_INPUT_BYTES);
    assert_eq!(result.configured_cost_micro, Some(10));
}

#[tokio::test]
async fn cancelled_expired_invalid_input_and_unreserved_budget_never_dispatch() {
    let server = Server::new(Reply::json(&valid_response(5))).await;
    let client = server.client();
    let cancelled = EmbeddingCancellation::default();
    cancelled.cancel();
    let result = client.embed("owned", 5, reservation(5), Instant::now() + Duration::from_secs(1), &cancelled).await;
    assert!(matches!(result.outcome, EmbeddingOutcome::Failed(EmbeddingFailure::Cancelled)));
    let result = client.embed("owned", 5, reservation(5), Instant::now(), &EmbeddingCancellation::default()).await;
    assert!(matches!(result.outcome, EmbeddingOutcome::Failed(EmbeddingFailure::Deadline)));
    for (input, bound, mut reserved, expected) in [
        (String::new(), 5, reservation(5), EmbeddingFailure::EmptyInput),
        ("é".repeat(MAX_INPUT_BYTES / 2 + 1), 5, reservation(5), EmbeddingFailure::InputLimit),
        ("\u{0001}".repeat(MAX_INPUT_BYTES), 5, reservation(5), EmbeddingFailure::InputLimit),
        ("owned".into(), 0, reservation(5), EmbeddingFailure::Budget),
        ("owned".into(), 6, reservation(5), EmbeddingFailure::Budget),
        ("owned".into(), 5, reservation(8193), EmbeddingFailure::Budget),
        ("low-cost".into(), 5, reservation(5), EmbeddingFailure::Budget),
    ] {
        if input == "low-cost" {
            reserved.reserved_cost_micro = 0;
        }
        let result = client
            .embed(&input, bound, reserved, Instant::now() + Duration::from_secs(1), &EmbeddingCancellation::default())
            .await;
        assert!(matches!(result.outcome, EmbeddingOutcome::Failed(failure) if failure == expected));
        assert_eq!(result.dispatch, EmbeddingDispatch::NotSent);
        assert_eq!(result.reservation, reserved);
    }
    assert_eq!(server.accepted(), 0);
}

#[tokio::test]
async fn redirect_does_not_forward_credentials_or_send_a_second_request() {
    let destination = Server::new(Reply::json(&valid_response(5))).await;
    let mut reply = Reply::json(&valid_response(5));
    reply.status = 307;
    reply.extra_headers.push(("Location".into(), format!("{}/v1/embeddings", destination.origin)));
    let source = Server::new(reply).await;
    let result = source
        .client()
        .embed("owned", 5, reservation(5), Instant::now() + Duration::from_secs(2), &EmbeddingCancellation::default())
        .await;
    assert!(matches!(result.outcome, EmbeddingOutcome::Failed(EmbeddingFailure::Redirect)));
    assert_eq!(source.accepted(), 1);
    assert_eq!(destination.accepted(), 0);
    assert!(result.usage.is_none());
}

#[tokio::test]
async fn provider_http_failures_and_disconnection_are_safe_single_attempts() {
    for status in [401, 429, 503] {
        let mut reply = Reply::json(&valid_response(5));
        reply.status = status;
        reply.body = format!("provider-private-input-and-{KEY}").into_bytes();
        let server = Server::new(reply).await;
        let result = server
            .client()
            .embed(
                "owned",
                5,
                reservation(5),
                Instant::now() + Duration::from_secs(2),
                &EmbeddingCancellation::default(),
            )
            .await;
        assert!(
            matches!(result.outcome, EmbeddingOutcome::Failed(EmbeddingFailure::HttpStatus(code)) if code == status)
        );
        assert_eq!(server.accepted(), 1);
        assert!(!format!("{result:?}").contains(KEY));
        assert!(result.configured_cost_micro.is_none());
        assert_eq!(result.reservation, reservation(5));
    }
    let mut reply = Reply::json(&valid_response(5));
    reply.close_without_response = true;
    let server = Server::new(reply).await;
    let result = server
        .client()
        .embed("owned", 5, reservation(5), Instant::now() + Duration::from_secs(1), &EmbeddingCancellation::default())
        .await;
    assert!(matches!(result.outcome, EmbeddingOutcome::Failed(EmbeddingFailure::Transport)));
    assert_eq!(result.dispatch, EmbeddingDispatch::PossiblySent);
    assert_eq!(server.accepted(), 1);
}

#[tokio::test]
async fn original_deadline_is_not_renewed_when_body_chunks_make_progress() {
    let mut reply = Reply::json(&valid_response(5));
    reply.chunk_bytes = 4;
    reply.chunk_delay = Duration::from_millis(50);
    let server = Server::new(reply).await;
    let client = server.client();
    let started = Instant::now();
    let result = client
        .embed("owned", 5, reservation(5), started + Duration::from_millis(500), &EmbeddingCancellation::default())
        .await;
    assert!(matches!(result.outcome, EmbeddingOutcome::Failed(EmbeddingFailure::Deadline)));
    assert_eq!(result.dispatch, EmbeddingDispatch::ResponseReceived);
    assert_eq!(result.reservation, reservation(5));
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(server.accepted(), 1);
}

#[tokio::test]
async fn cancellation_after_dispatch_never_claims_not_sent_or_retries() {
    let mut reply = Reply::json(&valid_response(5));
    reply.header_delay = Duration::from_secs(1);
    let server = Server::new(reply).await;
    let client = server.client();
    let cancelled = EmbeddingCancellation::default();
    let (result, ()) = tokio::join!(
        client.embed("owned", 5, reservation(5), Instant::now() + Duration::from_secs(2), &cancelled),
        async {
            server.wait_for_request().await;
            cancelled.cancel();
        }
    );
    assert!(matches!(result.outcome, EmbeddingOutcome::Failed(EmbeddingFailure::Cancelled)));
    assert_eq!(result.dispatch, EmbeddingDispatch::PossiblySent);
    assert!(result.configured_cost_micro.is_none());
    assert_eq!(result.reservation, reservation(5));
    assert_eq!(server.accepted(), 1);
}

#[tokio::test]
async fn dropping_issued_future_does_not_start_a_background_retry() {
    let mut reply = Reply::json(&valid_response(5));
    reply.header_delay = Duration::from_secs(1);
    let server = Server::new(reply).await;
    let client = server.client();
    let cancellation = EmbeddingCancellation::default();
    {
        let future = client.embed("owned", 5, reservation(5), Instant::now() + Duration::from_secs(2), &cancellation);
        tokio::pin!(future);
        tokio::select! {
            _ = &mut future => panic!("delayed response unexpectedly completed"),
            () = server.wait_for_request() => {},
        }
    }
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert_eq!(server.accepted(), 1);
    assert_eq!(server.requests().len(), 1);
    // The owner must still settle the reservation as possibly consumed; dropping cannot prove zero usage.
}

#[tokio::test]
async fn declared_and_chunked_response_sizes_are_bounded_without_echoing_body() {
    for chunked in [false, true] {
        let mut reply = Reply::json(&valid_response(5));
        reply.body = vec![b'x'; MAX_RESPONSE_BYTES + 1];
        reply.chunked = chunked;
        reply.chunk_bytes = 64 * 1024;
        let server = Server::new(reply).await;
        let result = server
            .client()
            .embed(
                "owned",
                5,
                reservation(5),
                Instant::now() + Duration::from_secs(2),
                &EmbeddingCancellation::default(),
            )
            .await;
        assert!(matches!(result.outcome, EmbeddingOutcome::Failed(EmbeddingFailure::ResponseLimit)));
        assert_eq!(result.dispatch, EmbeddingDispatch::ResponseReceived);
        assert_eq!(server.accepted(), 1);
        assert!(result.usage.is_none());
    }
}
