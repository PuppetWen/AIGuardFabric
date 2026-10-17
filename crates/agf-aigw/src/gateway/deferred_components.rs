//! Bounded evidence journal shared with the owning API; no prompt, response or credential fields.
use super::*;
use std::collections::BTreeSet;

/// Maximum physically dispatchable chat candidates under one original request.
pub const MAX_CHAT_COMPONENTS: usize = 8;

/// A stable reservation identity supplied only by the authenticated settlement owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeferredComponentAnchor {
    pub usage_id: Id,
    pub endpoint_id: Id,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeferredEvidence {
    NotSent,
    LocalReply,
    SentUsageKnown,
    SentUsagePartial,
    SentUsageUnknown,
}

/// Safe evidence snapshot. Partial usage is a proven lower bound, never a complete invoice.
#[derive(Debug, Clone)]
pub struct DeferredComponentOutcome {
    pub anchor: DeferredComponentAnchor,
    pub evidence: DeferredEvidence,
    pub usage: Option<UsageRecord>,
}

pub(super) struct ComponentJournal {
    rows: parking_lot::Mutex<Vec<DeferredComponentOutcome>>,
}

impl ComponentJournal {
    pub(super) fn new(anchors: Vec<DeferredComponentAnchor>) -> DomainResult<Self> {
        let mut usage_ids = BTreeSet::new();
        let mut endpoint_ids = BTreeSet::new();
        if anchors.is_empty()
            || anchors.len() > MAX_CHAT_COMPONENTS
            || anchors.iter().any(|row| {
                row.usage_id.is_nil()
                    || row.endpoint_id.is_nil()
                    || !usage_ids.insert(row.usage_id)
                    || !endpoint_ids.insert(row.endpoint_id)
            })
        {
            return Err(invalid());
        }
        Ok(Self {
            rows: parking_lot::Mutex::new(
                anchors
                    .into_iter()
                    .map(|anchor| DeferredComponentOutcome { anchor, evidence: DeferredEvidence::NotSent, usage: None })
                    .collect(),
            ),
        })
    }

    pub(super) fn anchors(&self) -> Vec<DeferredComponentAnchor> {
        self.rows.lock().iter().map(|row| row.anchor).collect()
    }

    pub(super) fn entered(&self, endpoint: Id) -> DomainResult<()> {
        let mut rows = self.rows.lock();
        let at = rows.iter().position(|row| row.anchor.endpoint_id == endpoint).ok_or_else(invalid)?;
        if rows[at].evidence != DeferredEvidence::NotSent
            || rows[at + 1..].iter().any(|row| row.evidence != DeferredEvidence::NotSent)
            || rows[..at].iter().any(|row| {
                matches!(
                    row.evidence,
                    DeferredEvidence::SentUsageKnown
                        | DeferredEvidence::LocalReply
                        | DeferredEvidence::SentUsagePartial
                )
            })
        {
            return Err(invalid());
        }
        rows[at].evidence = DeferredEvidence::SentUsageUnknown;
        Ok(())
    }

    pub(super) fn observe(&self, mut input: crate::meter::UsageInput<'_>, complete: bool) -> DomainResult<()> {
        let mut rows = self.rows.lock();
        let row = rows.iter_mut().find(|row| row.anchor.endpoint_id == input.endpoint.id).ok_or_else(invalid)?;
        if input.cache_hit {
            if row.evidence != DeferredEvidence::NotSent || row.anchor != rows_anchor(input.id, input.endpoint.id) {
                return Err(invalid());
            }
        } else if !matches!(row.evidence, DeferredEvidence::SentUsageUnknown | DeferredEvidence::SentUsagePartial) {
            return Err(invalid());
        }
        input.id = row.anchor.usage_id;
        let record = Meter::record_deferred(input)?;
        if let Some(previous) = &row.usage {
            if record.prompt_tokens < previous.prompt_tokens
                || record.completion_tokens < previous.completion_tokens
                || record.cached_tokens < previous.cached_tokens
                || record.cache_write_tokens < previous.cache_write_tokens
                || record.cache_write_1h_tokens < previous.cache_write_1h_tokens
            {
                return Err(invalid());
            }
        }
        row.evidence = if record.cache_hit {
            DeferredEvidence::LocalReply
        } else if complete {
            DeferredEvidence::SentUsageKnown
        } else {
            DeferredEvidence::SentUsagePartial
        };
        row.usage = Some(record);
        Ok(())
    }

    pub(super) fn selected_usage(&self, endpoint: Id) -> Option<UsageRecord> {
        self.rows.lock().iter().find(|row| row.anchor.endpoint_id == endpoint).and_then(|row| row.usage.clone())
    }

    pub(super) fn snapshot(&self) -> Vec<DeferredComponentOutcome> {
        self.rows.lock().clone()
    }
}

fn rows_anchor(usage_id: Id, endpoint_id: Id) -> DeferredComponentAnchor {
    DeferredComponentAnchor { usage_id, endpoint_id }
}
fn invalid() -> DomainError {
    DomainError::Conflict("Paid component differs from its immutable bounded single-dispatch journal".into())
}
