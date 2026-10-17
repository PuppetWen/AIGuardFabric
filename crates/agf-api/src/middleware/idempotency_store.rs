//! Bounded local receipts. In-flight or uncertain operations cannot be blindly executed twice.
use super::*;
use std::sync::Arc;

const MAX_ENTRIES: usize = 2048;
const MAX_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct StoredResponse {
    pub status: StatusCode,
    pub headers: axum::http::HeaderMap,
    pub body: Bytes,
    pub permissions: Vec<(String, String)>,
    pub authorization: String,
}
#[derive(Debug, Clone)]
struct Entry {
    fingerprint: String,
    response: Option<StoredResponse>,
    stored_at: Instant,
    in_flight: bool,
}
#[derive(Debug)]
pub struct IdempotencyStore {
    ttl_secs: u64,
    entries: Mutex<HashMap<String, Entry>>,
}
impl IdempotencyStore {
    #[must_use]
    pub fn new(ttl_secs: u64) -> Self {
        Self { ttl_secs, entries: Mutex::new(HashMap::new()) }
    }
    /// None claims first execution; Some is a completed receipt. Pending requests return conflict.
    pub(super) fn begin(&self, key: &str, fingerprint: &str) -> Result<Option<StoredResponse>, ApiError> {
        let mut entries =
            self.entries.lock().map_err(|_| DomainError::Internal("Idempotency store unavailable".into()))?;
        entries.retain(|_, entry| entry.in_flight || entry.stored_at.elapsed().as_secs() < self.ttl_secs);
        if let Some(entry) = entries.get(key) {
            if entry.fingerprint != fingerprint {
                return Err(DomainError::Conflict(
                    "Idempotency-Key was already used with different request inputs".into(),
                )
                .into());
            }
            return entry.response.clone().map(Some).ok_or_else(|| {
                DomainError::Conflict(
                    "Request is running or its outcome is uncertain; inspect the resource before retrying".into(),
                )
                .into()
            });
        }
        if entries.len() >= MAX_ENTRIES {
            return Err(DomainError::RateLimited("Idempotency receipt capacity reached; retry later".into()).into());
        }
        entries.insert(
            key.into(),
            Entry { fingerprint: fingerprint.into(), response: None, stored_at: Instant::now(), in_flight: true },
        );
        Ok(None)
    }
    pub(super) fn complete(&self, key: &str, response: StoredResponse) {
        if let Ok(mut entries) = self.entries.lock() {
            let bytes: usize = entries.values().filter_map(|e| e.response.as_ref()).map(|r| r.body.len()).sum();
            if bytes + response.body.len() <= MAX_BYTES {
                if let Some(entry) = entries.get_mut(key) {
                    entry.response = Some(response);
                }
            }
        }
    }
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.lock().map(|entries| entries.len()).unwrap_or(0)
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

pub(super) struct ReceiptLease {
    pub store: Arc<IdempotencyStore>,
    pub key: String,
}
impl Drop for ReceiptLease {
    fn drop(&mut self) {
        if let Ok(mut entries) = self.store.entries.lock() {
            if let Some(entry) = entries.get_mut(&self.key) {
                entry.in_flight = false;
                entry.stored_at = Instant::now();
            }
        }
    }
}

tokio::task_local! {
    pub(super) static REPLAY_PERMISSIONS: Arc<Mutex<Vec<(String,String)>>>;
}

pub(super) fn record_permission(group: &str, action: &str) {
    let _ = REPLAY_PERMISSIONS.try_with(|trace| {
        if let Ok(mut trace) = trace.lock() {
            let permission = (group.to_owned(), action.to_owned());
            if !trace.contains(&permission) {
                trace.push(permission);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pending_claims_do_not_expire_or_allow_capacity_eviction() {
        let store = Arc::new(IdempotencyStore::new(0));
        assert!(store.begin("first", "body").is_ok());
        assert!(store.begin("first", "body").is_err(), "An active request cannot expire into a second execution");
        for index in 1..MAX_ENTRIES {
            assert!(store.begin(&index.to_string(), "body").is_ok());
        }
        assert_eq!(store.begin("overflow", "body").unwrap_err().status, StatusCode::TOO_MANY_REQUESTS);
        drop(ReceiptLease { store: Arc::clone(&store), key: "first".into() });
        assert!(store.begin("first", "body").is_ok(), "The configured receipt TTL begins after execution ends");
    }
}
