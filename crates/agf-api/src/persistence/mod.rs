//! Legacy write-behind bridge and startup hydration.
//!
//! Runtime findings, alerts, cases and API-key handlers use the asynchronous durable
//! repository methods. This bridge remains for fixture imports and resources that
//! still journal synchronous mutations. Its counters describe only those writes;
//! they are not a complete inventory of every durable control-plane feature.
//!
//! A journaled mutation can return before SQL commits. A process crash or queue
//! overflow may lose that mutation; metrics and warnings expose the failure but
//! cannot undo the earlier response. Remaining resources need transactional paths.
//!
//! Legacy alert writes retain a process-local identity remap. Case imports now
//! preserve the caller's case ID and timeline event IDs; display-number collisions
//! allocate a new number without changing the ID. Replayed creates do not overwrite
//! later case state. No alias is inferred for historical IDs already lost by an
//! older release, because title or timestamp similarity is not a reliable identity.
//!
//! Tenant-owned SQL operations use the tenant transaction and RLS boundary. Startup
//! hydration is a separate maintenance read; the cache remains keyed by tenant ID.
//!
//! See `store::durable_cases`, `store::durable_alerts` and their database regression
//! tests for the current runtime guarantees rather than assuming all handlers use
//! the bridge.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use agf_core::asset::{Asset, AssetChange};
use agf_core::case::{Case, CaseEvent};
use agf_core::enums::{AlertState, CaseState, EvidenceLevel, LifecycleState, RiskDomain, Severity};
use agf_core::error::{DomainError, DomainResult};
use agf_core::ids::{Id, TenantId};
use agf_core::pagination::PageRequest;
use agf_core::policy::Policy;
use agf_core::rbac::ApiKey;
use agf_core::risk::{Finding, FindingState};
use agf_core::time::Timestamp;
use agf_storage::{AlertRepo, ApiKeyRepo, AssetRepo, AuditRepo, CaseRepo, FindingRepo, PolicyRepo, Store};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tracing::{debug, info, warn};

use crate::store::ApiStore;

/// 写后持久化桥：水合 + 队列 + PG 消费者任务。
#[derive(Debug)]
pub struct PersistenceBridge {
    queue: Arc<WriteQueue>,
    store: Arc<Store>,
    hydration: Mutex<HydrationReport>,
    /// Legacy journal identity mapping; new case imports retain their supplied IDs.
    remap: Mutex<BTreeMap<(TenantId, Id), Id>>,
}

pub use consts::*;
pub use types::*;

mod bridge_apply;
mod bridge_core;
mod bridge_hydrate;
mod consts;
mod types;
