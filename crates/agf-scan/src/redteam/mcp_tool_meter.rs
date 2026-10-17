//! A reserved tool call is refunded if its caller exits before starting delivery.
use agf_core::error::{DomainError, DomainResult};
use futures::future::BoxFuture;
use std::future::Future;

/// Delivery and result status of one direct MCP tool request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolCallOutcome {
    /// A valid tool result arrived without its error flag.
    Succeeded,
    /// The upstream returned an HTTP, protocol or tool execution error.
    Failed,
    /// Delivery started, but the transport could not confirm its outcome.
    Unknown,
    /// The request was never delivered and its reservation can be refunded.
    NotDelivered,
    /// The caller cancelled delivery; its result remains unknown.
    Cancelled,
}

type Settlement = Box<dyn FnOnce(ToolCallOutcome) -> BoxFuture<'static, DomainResult<()>> + Send>;

/// A cancellation-safe receipt with a distinct state before outbound delivery starts.
pub struct ToolCallReceipt {
    settlement: Option<Settlement>,
    sending: bool,
}

impl ToolCallReceipt {
    /// Bind one settlement callback, invoked once on completion or cancellation.
    #[must_use]
    pub fn new<F, Fut>(settlement: F) -> Self
    where
        F: FnOnce(ToolCallOutcome) -> Fut + Send + 'static,
        Fut: Future<Output = DomainResult<()>> + Send + 'static,
    {
        Self { settlement: Some(Box::new(move |outcome| Box::pin(settlement(outcome)))), sending: false }
    }

    /// Mark delivery immediately before starting the outbound HTTP operation.
    pub fn mark_sending(&mut self) {
        self.sending = true;
    }

    /// Settlement continues even if the campaign is cancelled while waiting for it.
    pub async fn finish(mut self, outcome: ToolCallOutcome) -> DomainResult<()> {
        if let Some(settlement) = self.settlement.take() {
            tokio::spawn(settlement(outcome)).await.map_err(|_| DomainError::DependencyUnavailable {
                dependency: "mcp-tool-meter".into(),
                cause: "Tool settlement task did not complete".into(),
            })??;
        }
        Ok(())
    }
}

impl std::fmt::Debug for ToolCallReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolCallReceipt").field("sending", &self.sending).finish_non_exhaustive()
    }
}

impl Drop for ToolCallReceipt {
    fn drop(&mut self) {
        if let Some(settlement) = self.settlement.take()
            && let Ok(runtime) = tokio::runtime::Handle::try_current()
        {
            let outcome = if self.sending { ToolCallOutcome::Cancelled } else { ToolCallOutcome::NotDelivered };
            runtime.spawn(async move {
                if let Err(error) = settlement(outcome).await {
                    tracing::warn!(%error, "Cancelled MCP tool reservation could not settle");
                }
            });
        }
    }
}
