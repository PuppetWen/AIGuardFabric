//! Deduplication commits only after persistence; failed/cancelled batches leave no suppression keys.
use super::*;

pub(super) type Window = Mutex<HashMap<String, Timestamp>>;

pub(super) struct DedupBatch<'a> {
    window: &'a Window,
    pending: HashMap<String, Timestamp>,
    seconds: i64,
}

impl<'a> DedupBatch<'a> {
    pub(super) fn new(window: &'a Window, seconds: i64) -> Self {
        if seconds > 0 {
            let now = Timestamp::now();
            window
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .retain(|_, seen| now.since_secs(seen) <= seconds.saturating_mul(2));
        }
        Self { window, pending: HashMap::new(), seconds }
    }

    pub(super) fn check(&mut self, event: &Event, at: Timestamp) -> bool {
        if self.seconds <= 0 {
            return false;
        }
        let key = format!("{}:{}", event.tenant_id, event.dedup_key());
        let previous = self
            .pending
            .get(&key)
            .copied()
            .or_else(|| self.window.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(&key).copied());
        if previous.is_some_and(|previous| at.since_secs(&previous) <= self.seconds) {
            return true;
        }
        self.pending.insert(key, at);
        false
    }

    pub(super) fn commit(self) {
        if !self.pending.is_empty() {
            self.window.lock().unwrap_or_else(std::sync::PoisonError::into_inner).extend(self.pending);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_batches_do_not_suppress_retry_and_tenants_are_separate() {
        let window = Window::default();
        let mut event = Event::new(TenantId::default_tenant(), Id::new(), IngestProtocol::Otlp);
        event.raw_hash = "same".into();
        let now = Timestamp::now();
        let mut failed = DedupBatch::new(&window, 300);
        assert!(!failed.check(&event, now));
        assert!(failed.check(&event, now));
        drop(failed);
        let mut retry = DedupBatch::new(&window, 300);
        assert!(!retry.check(&event, now));
        retry.commit();
        let mut next = DedupBatch::new(&window, 300);
        assert!(next.check(&event, now));
        event.tenant_id = TenantId::new();
        assert!(!next.check(&event, now));
    }
}
