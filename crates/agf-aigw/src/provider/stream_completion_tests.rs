//! 真实本地 HTTP 字节流：缺失结束证据不得伪造成功，显式终止帧保持兼容。
use super::*;
use futures::StreamExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

async fn response(bytes: Vec<u8>) -> DomainResult<reqwest::Response> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move {
        let Ok((mut socket, _)) = listener.accept().await else { return };
        let mut head = Vec::new();
        let mut chunk = [0_u8; 1024];
        while !head.windows(4).any(|part| part == b"\r\n\r\n") {
            let Ok(count) = socket.read(&mut chunk).await else { return };
            if count == 0 || head.len() + count > 8192 {
                return;
            }
            head.extend_from_slice(&chunk[..count]);
        }
        let header = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", bytes.len());
        if socket.write_all(header.as_bytes()).await.is_ok() {
            let _ = socket.write_all(&bytes).await;
        }
    });
    reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()
        .map_err(|_| invalid())?
        .get(format!("http://{address}/owned-stream"))
        .send()
        .await
        .map_err(|_| invalid())
}

fn invalid() -> DomainError {
    DomainError::PreconditionFailed("本地流完成证据回归夹具失败".into())
}

fn partial() -> String {
    format!(
        "data: {}\n\n",
        json!({"choices":[{"index":0,"delta":{"content":"partial"},"finish_reason":null}],
        "usage":{"prompt_tokens":40,"completion_tokens":3,"total_tokens":43}})
    )
}

async fn sse(bytes: Vec<u8>) -> DomainResult<(Vec<DomainResult<StreamChunk>>, ProviderState)> {
    let state = ProviderState::default();
    let chunks = sse_stream("owned-test", response(bytes).await?, state.clone(), from_openai_chunk).collect().await;
    Ok((chunks, state))
}

#[tokio::test]
async fn eof_with_numeric_usage_preserves_partial_then_reports_failure_without_stop() -> DomainResult<()> {
    let (chunks, state) = sse(partial().into_bytes()).await?;
    assert_eq!(chunks.len(), 2);
    let first = chunks[0].as_ref().map_err(|_| invalid())?;
    assert_eq!(first.usage.map(|usage| (usage.prompt_tokens, usage.completion_tokens)), Some((40, 3)));
    assert!(first.finish_reason.is_none());
    assert!(matches!(&chunks[1], Err(DomainError::DependencyUnavailable { .. })));
    assert_eq!(state.snapshot().total_failure, 1);
    Ok(())
}

#[tokio::test]
async fn actual_done_frame_can_finish_numeric_usage_without_inventing_another_finish() -> DomainResult<()> {
    let (chunks, state) = sse((partial() + "data: [DONE]\n\n").into_bytes()).await?;
    assert_eq!(chunks.len(), 2);
    assert!(chunks.iter().all(Result::is_ok));
    assert_eq!(chunks[1].as_ref().map_err(|_| invalid())?.finish_reason, Some(FinishReason::Stop));
    assert_eq!(state.snapshot().total_failure, 0);
    Ok(())
}

#[tokio::test]
async fn real_finish_reason_and_done_emit_one_finish_and_eof_without_usage_fails() -> DomainResult<()> {
    let stop =
        format!("data: {}\n\ndata: [DONE]\n\n", json!({"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}));
    let (chunks, _) = sse((partial() + &stop).into_bytes()).await?;
    assert!(chunks.iter().all(Result::is_ok));
    assert_eq!(chunks.iter().filter(|item| item.as_ref().is_ok_and(|chunk| chunk.finish_reason.is_some())).count(), 1);
    let (empty, state) = sse(Vec::new()).await?;
    assert!(matches!(empty.as_slice(), [Err(DomainError::DependencyUnavailable { .. })]));
    assert_eq!(state.snapshot().total_failure, 1);
    Ok(())
}

fn bedrock(value: Value) -> DomainResult<Vec<u8>> {
    let payload = serde_json::to_vec(&value)?;
    let size = u32::try_from(payload.len() + 16).map_err(|_| invalid())?;
    let mut frame = Vec::new();
    frame.extend_from_slice(&size.to_be_bytes());
    frame.extend_from_slice(&[0_u8; 8]);
    frame.extend_from_slice(&payload);
    frame.extend_from_slice(&[0_u8; 4]);
    Ok(frame)
}

async fn events(bytes: Vec<u8>) -> DomainResult<(Vec<DomainResult<StreamChunk>>, ProviderState)> {
    let state = ProviderState::default();
    let chunks = bedrock_event_stream(response(bytes).await?, state.clone()).collect().await;
    Ok((chunks, state))
}

#[tokio::test]
async fn bedrock_numeric_usage_without_message_stop_is_partial_and_failure() -> DomainResult<()> {
    let bytes = bedrock(json!({"metadata":{"usage":{"inputTokens":40,"outputTokens":3}}}))?;
    let (chunks, state) = events(bytes).await?;
    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0].as_ref().map_err(|_| invalid())?.usage.map(|usage| usage.prompt_tokens), Some(40));
    assert!(chunks[0].as_ref().map_err(|_| invalid())?.finish_reason.is_none());
    assert!(matches!(&chunks[1], Err(DomainError::DependencyUnavailable { .. })));
    assert_eq!(state.snapshot().total_failure, 1);
    Ok(())
}

#[tokio::test]
async fn bedrock_real_stop_has_one_finish_and_truncated_tail_is_error() -> DomainResult<()> {
    let mut bytes = bedrock(json!({"messageStop":{"stopReason":"max_tokens"}}))?;
    bytes.extend(bedrock(json!({"metadata":{"usage":{"inputTokens":40,"outputTokens":3}}}))?);
    let (chunks, state) = events(bytes.clone()).await?;
    assert_eq!(chunks.len(), 2);
    assert!(chunks.iter().all(Result::is_ok));
    assert_eq!(chunks[0].as_ref().map_err(|_| invalid())?.finish_reason, Some(FinishReason::Length));
    assert_eq!(state.snapshot().total_failure, 0);
    bytes.extend_from_slice(&[0_u8; 5]);
    let (truncated, state) = events(bytes).await?;
    assert!(matches!(truncated.last(), Some(Err(DomainError::DependencyUnavailable { .. }))));
    assert_eq!(state.snapshot().total_failure, 1);
    Ok(())
}
