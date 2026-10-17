use tokio::sync::watch;

/// Explicit cancellation; no global environment or background retry worker.
#[derive(Debug, Clone)]
pub struct EmbeddingCancellation {
    sender: watch::Sender<bool>,
}

impl Default for EmbeddingCancellation {
    fn default() -> Self {
        let (sender, _receiver) = watch::channel(false);
        Self { sender }
    }
}

impl EmbeddingCancellation {
    pub fn cancel(&self) {
        self.sender.send_replace(true);
    }

    pub fn is_cancelled(&self) -> bool {
        *self.sender.borrow()
    }

    pub(crate) async fn cancelled(&self) {
        let mut receiver = self.sender.subscribe();
        loop {
            if *receiver.borrow() {
                return;
            }
            if receiver.changed().await.is_err() {
                return;
            }
        }
    }
}
