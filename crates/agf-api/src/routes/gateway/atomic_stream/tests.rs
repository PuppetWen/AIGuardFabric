use super::*;
use crate::gateway_settlement::{committed_for_test, controlled_for_test};
use agf_aigw::wire::{FinishReason, StreamChunk, Usage};
use agf_core::error::{DomainError, DomainResult};

fn failure() -> DomainError {
    DomainError::Internal("Controlled delivery fixture failed".into())
}

async fn body(response: Response) -> DomainResult<String> {
    let bytes =
        tokio::time::timeout(std::time::Duration::from_secs(2), axum::body::to_bytes(response.into_body(), 64 * 1024))
            .await
            .map_err(|_| failure())?
            .map_err(|_| failure())?;
    String::from_utf8(bytes.to_vec()).map_err(|_| failure())
}

fn no_success(text: &str) {
    assert!(!text.contains("[DONE]"));
    assert!(!text.contains("event: message_stop"));
    assert!(text.contains("api_error"));
}

#[tokio::test]
async fn closed_owner_channel_without_commit_is_a_real_sse_error() -> DomainResult<()> {
    for protocol in [Protocol::OpenAi, Protocol::Anthropic] {
        let (stream, sender) = controlled_for_test();
        drop(sender);
        no_success(&body(response(protocol, stream)).await?);
    }
    Ok(())
}

#[tokio::test]
async fn terminal_usage_fields_do_not_forge_a_committed_delivery() -> DomainResult<()> {
    for protocol in [Protocol::OpenAi, Protocol::Anthropic] {
        let (stream, sender) = controlled_for_test();
        let terminal = StreamChunk {
            finish_reason: Some(FinishReason::Stop),
            usage: Some(Usage { prompt_tokens: 1, completion_tokens: 1, ..Usage::default() }),
            ..StreamChunk::default()
        };
        sender.send(Ok(Delivery::Chunk(terminal))).await.map_err(|_| failure())?;
        let owner = tokio::spawn(async move {
            let _sender = sender;
            std::future::pending::<()>().await;
        });
        owner.abort();
        assert!(owner.await.is_err_and(|error| error.is_cancelled()));
        no_success(&body(response(protocol, stream)).await?);
    }
    Ok(())
}

#[tokio::test]
async fn explicit_stream_failure_cannot_be_upgraded_by_a_late_marker() -> DomainResult<()> {
    for protocol in [Protocol::OpenAi, Protocol::Anthropic] {
        let (stream, sender) = controlled_for_test();
        sender.send(Err(failure())).await.map_err(|_| failure())?;
        sender.send(Ok(committed_for_test())).await.map_err(|_| failure())?;
        drop(sender);
        no_success(&body(response(protocol, stream)).await?);
    }
    Ok(())
}

#[tokio::test]
async fn explicit_committed_delivery_emits_exactly_one_protocol_terminator() -> DomainResult<()> {
    for protocol in [Protocol::OpenAi, Protocol::Anthropic] {
        let (stream, sender) = controlled_for_test();
        sender.send(Ok(committed_for_test())).await.map_err(|_| failure())?;
        drop(sender);
        let text = body(response(protocol, stream)).await?;
        assert!(!text.contains("api_error"));
        let marker = match protocol {
            Protocol::OpenAi => "[DONE]",
            Protocol::Anthropic => "event: message_stop",
        };
        assert_eq!(text.matches(marker).count(), 1);
    }
    Ok(())
}

#[tokio::test]
async fn native_anthropic_stop_without_commit_cannot_escape_through_chunk_encoding() -> DomainResult<()> {
    let (stream, sender) = controlled_for_test();
    let stop =
        StreamChunk { anthropic_event: Some(serde_json::json!({"type":"message_stop"})), ..StreamChunk::default() };
    sender.send(Ok(Delivery::Chunk(stop))).await.map_err(|_| failure())?;
    drop(sender);
    no_success(&body(response(Protocol::Anthropic, stream)).await?);
    Ok(())
}

#[tokio::test]
async fn committed_content_filter_replacement_remains_an_intentional_protocol_end() -> DomainResult<()> {
    let (stream, sender) = controlled_for_test();
    let replacement = StreamChunk { finish_reason: Some(FinishReason::ContentFilter), ..StreamChunk::default() };
    sender.send(Ok(Delivery::Chunk(replacement))).await.map_err(|_| failure())?;
    sender.send(Ok(committed_for_test())).await.map_err(|_| failure())?;
    drop(sender);
    let text = body(response(Protocol::OpenAi, stream)).await?;
    assert!(text.contains("content_filter"));
    assert_eq!(text.matches("[DONE]").count(), 1);
    assert!(!text.contains("api_error"));
    Ok(())
}

#[tokio::test]
async fn dropping_sse_body_closes_delivery_instead_of_granting_a_new_run() -> DomainResult<()> {
    let (stream, sender) = controlled_for_test();
    drop(response(Protocol::OpenAi, stream));
    tokio::time::timeout(std::time::Duration::from_secs(2), sender.closed()).await.map_err(|_| failure())?;
    assert!(sender.send(Ok(committed_for_test())).await.is_err());
    Ok(())
}
