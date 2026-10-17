use serde_json::{Value, json};
use tokio::time::{Duration, Instant};

use super::test_server::{Reply, Server, reservation, valid_response};
use super::{EmbeddingCancellation, EmbeddingDispatch, EmbeddingFailure, EmbeddingOutcome, MAX_REPORTED_TOKENS};

async fn attempt(reply: Reply, reserved: u64) -> super::EmbeddingAttempt {
    let server = Server::new(reply).await;
    let result = server
        .client()
        .embed(
            "owned synthetic",
            reserved,
            reservation(reserved),
            Instant::now() + Duration::from_secs(2),
            &EmbeddingCancellation::default(),
        )
        .await;
    assert_eq!(server.accepted(), 1);
    result
}

#[tokio::test]
async fn wrong_model_keeps_trustworthy_usage_and_independent_cost() {
    let mut response = valid_response(19);
    response["model"] = json!("different-model");
    let result = attempt(Reply::json(&response), 30).await;
    assert!(matches!(result.outcome, EmbeddingOutcome::Failed(EmbeddingFailure::InvalidModel)));
    assert_eq!(result.usage.unwrap().total_tokens, 19);
    assert_eq!(result.configured_cost_micro, Some(10));
    assert_eq!(result.dispatch, EmbeddingDispatch::ResponseReceived);
}

#[tokio::test]
async fn wrong_index_or_multiple_vectors_are_unusable_but_not_free() {
    for data in [
        json!([{"object":"embedding","index":1,"embedding":[0.1,0.2,0.3]}]),
        json!([{"object":"embedding","index":0,"embedding":[0.1,0.2,0.3]},
               {"object":"embedding","index":1,"embedding":[0.4,0.5,0.6]}]),
        json!([]),
    ] {
        let mut response = valid_response(19);
        response["data"] = data;
        let result = attempt(Reply::json(&response), 30).await;
        assert!(matches!(result.outcome, EmbeddingOutcome::Failed(EmbeddingFailure::InvalidVector)));
        assert_eq!(result.configured_cost_micro, Some(10));
        assert_eq!(result.usage.unwrap().total_tokens, 19);
    }
}

#[tokio::test]
async fn wrong_dimension_base64_zero_overflow_and_underflow_keep_paid_usage() {
    for vector in [
        json!([0.1, 0.2]),
        json!("not-supported-base64"),
        json!([0, 0, 0]),
        json!([1e100, 0.2, 0.3]),
        json!([1e-100, 0, 0]),
        json!([null, 0.2, 0.3]),
        json!(["NaN", 0.2, 0.3]),
    ] {
        let mut response = valid_response(19);
        response["data"][0]["embedding"] = vector;
        let result = attempt(Reply::json(&response), 30).await;
        assert!(matches!(result.outcome, EmbeddingOutcome::Failed(EmbeddingFailure::InvalidVector)));
        assert_eq!(result.configured_cost_micro, Some(10));
        assert_eq!(result.reservation, reservation(30));
    }
}

#[tokio::test]
async fn reported_usage_over_reservation_retains_known_consumption_and_cost() {
    let result = attempt(Reply::json(&valid_response(300)), 30).await;
    assert!(matches!(result.outcome, EmbeddingOutcome::Failed(EmbeddingFailure::UsageOverReservation)));
    assert_eq!(result.usage.unwrap().total_tokens, 300);
    assert_eq!(result.configured_cost_micro, Some(150));
    assert_eq!(result.reservation, reservation(30));
    assert_eq!(result.dispatch, EmbeddingDispatch::ResponseReceived);
}

#[tokio::test]
async fn untrustworthy_usage_does_not_fabricate_zero_cost_or_release_reserved_budget() {
    for usage in [
        json!({"prompt_tokens":-1,"total_tokens":-1}),
        json!({"prompt_tokens":1.5,"total_tokens":1.5}),
        json!({"prompt_tokens":19,"total_tokens":20}),
        json!({"prompt_tokens":0,"total_tokens":0}),
        json!({"prompt_tokens":MAX_REPORTED_TOKENS+1,"total_tokens":MAX_REPORTED_TOKENS+1}),
        Value::Null,
    ] {
        let mut response = valid_response(19);
        response["usage"] = usage;
        let result = attempt(Reply::json(&response), 30).await;
        assert!(matches!(result.outcome, EmbeddingOutcome::Failed(EmbeddingFailure::InvalidUsage)));
        assert!(result.usage.is_none() && result.configured_cost_micro.is_none());
        assert_eq!(result.reservation, reservation(30));
        assert_eq!(result.dispatch, EmbeddingDispatch::ResponseReceived);
    }
}

#[tokio::test]
async fn malformed_json_and_incomplete_body_preserve_unknown_consumption() {
    let mut reply = Reply::json(&valid_response(19));
    reply.body = b"{ private response is invalid".to_vec();
    let result = attempt(reply, 30).await;
    assert!(matches!(result.outcome, EmbeddingOutcome::Failed(EmbeddingFailure::MalformedResponse)));
    assert!(result.configured_cost_micro.is_none());
    assert!(!format!("{result:?}").contains("private response"));
    let mut reply = Reply::json(&valid_response(19));
    reply.declared_length = Some(reply.body.len() + 100);
    let result = attempt(reply, 30).await;
    assert!(matches!(result.outcome, EmbeddingOutcome::Failed(EmbeddingFailure::Transport)));
    assert_eq!(result.dispatch, EmbeddingDispatch::ResponseReceived);
    assert_eq!(result.reservation, reservation(30));
}

#[tokio::test]
async fn unsupported_content_encoding_is_not_implicitly_decoded() {
    let mut reply = Reply::json(&valid_response(19));
    reply.extra_headers.push(("Content-Encoding".into(), "gzip".into()));
    let result = attempt(reply, 30).await;
    assert!(matches!(result.outcome, EmbeddingOutcome::Failed(EmbeddingFailure::ResponseEncoding)));
    assert!(result.usage.is_none());
    assert_eq!(result.reservation, reservation(30));
}

#[tokio::test]
async fn non_json_content_type_is_not_trusted_even_with_a_json_looking_body() {
    let mut reply = Reply::json(&valid_response(19));
    reply.content_type = "text/html".into();
    let result = attempt(reply, 30).await;
    assert!(matches!(result.outcome, EmbeddingOutcome::Failed(EmbeddingFailure::ResponseType)));
    assert!(result.usage.is_none() && result.configured_cost_micro.is_none());
    assert_eq!(result.reservation, reservation(30));
}
