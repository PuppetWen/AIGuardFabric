//! Real pending body/auth-result futures use one server window; no environment or clock change.
use super::*;
use std::time::Duration;

fn window() -> (agf_core::time::Timestamp, tokio::time::Instant) {
    (agf_core::time::Timestamp::now(), tokio::time::Instant::now() + Duration::from_millis(10))
}

#[tokio::test]
async fn a_held_http_body_is_cancelled_at_the_original_window_without_polling_the_rest() {
    let (entered, mut received) = tokio::sync::oneshot::channel();
    let (release, waiting) = tokio::sync::oneshot::channel::<()>();
    let stream = futures::stream::once(async move {
        let _ = entered.send(());
        let _ = waiting.await;
        Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"private body must not enter diagnostics"))
    });
    let body = axum::body::Body::from_stream(stream);
    let result = within_gateway_window(Some(window()), axum::body::to_bytes(body, 1024)).await;
    assert!(matches!(result, Err(DomainError::Timeout(_))));
    assert!(received.try_recv().is_ok());
    assert!(release.send(()).is_err(), "timed-out reader releases its actual pending body");
}

#[tokio::test]
async fn pending_authentication_result_does_not_create_a_fresh_model_window() {
    let (entered, mut received) = tokio::sync::oneshot::channel();
    let (release, waiting) = tokio::sync::oneshot::channel::<()>();
    // The production extractor supplies this exact result type; no fake Principal is returned.
    let authentication = async move {
        let _ = entered.send(());
        let _ = waiting.await;
        std::future::pending::<Result<Principal, ApiError>>().await
    };
    let result = within_gateway_window(Some(window()), authentication).await;
    assert!(matches!(result, Err(DomainError::Timeout(_))));
    assert!(received.try_recv().is_ok());
    assert!(release.send(()).is_err());
}

#[tokio::test]
async fn an_unkeyed_legacy_future_retains_its_original_result() {
    let (release, waiting) = tokio::sync::oneshot::channel::<u32>();
    let future = async move {
        tokio::task::yield_now().await;
        waiting.await
    };
    let sender = tokio::spawn(async move {
        let _ = release.send(42);
    });
    let result = within_gateway_window(None, future).await;
    assert!(matches!(result, Ok(Ok(42))));
    assert!(sender.await.is_ok());
}
