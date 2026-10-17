//! API repositories with an explicit offline memory mode.
//!
//! With PostgreSQL, runtime paths for findings, alerts, cases and API keys use their
//! asynchronous `*_durable` methods: SQL is authoritative and a successful write
//! has committed before the cache is refreshed. Case creation, alert ownership and
//! the initial timeline are one transaction. State transitions lock the case and
//! commit the new state with its timeline entry. Supplied case/event IDs remain stable.
//!
//! Legacy synchronous methods are retained for offline operation, fixtures and
//! resources still using `crate::persistence`. Those journaled writes can be lost
//! if the process exits before the background bridge commits; they must not be
//! described as transactionally durable. Asset runtime reads use SQL; discovery,
//! governance, histories and baselines commit in one tenant-scoped transaction.
//!
//! Control-plane features such as model endpoints, policies, reports and durable
//! SOAR runs also use tenant-scoped `ConfigStore` records in their own services.
//! The in-memory projection here is not the persistence contract of those APIs.
//! Audit commits to PostgreSQL before returning and reads across instances. Most audit
//! writes use a separate transaction; cloud inventory, MCP/model endpoints and log-source
//! configuration commit their success audit with the corresponding business data.
//!
//! Without a database, this store is process-local and cannot survive restart.
//! No mutex is held across an asynchronous database or network operation.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use agf_asset::service::{AssetBackend, InventoryStats};
use agf_core::asset::{Asset, AssetChange};
use agf_core::audit::{AuditLog, GENESIS_HASH};
use agf_core::case::{Case, CaseEvent};
use agf_core::enums::{AlertState, CaseState, EvidenceLevel, LifecycleState, QuotaDimension, RiskDomain, Severity};
use agf_core::error::{DomainError, DomainResult};
use agf_core::ids::{Id, TenantId};
use agf_core::pagination::{Page, PageRequest};
use agf_core::policy::Policy;
use agf_core::quota::{Quota, QuotaWindow};
use agf_core::rbac::ApiKey;
use agf_core::redteam::{RedteamCampaign, RedteamReport, RedteamResult};
use agf_core::report::{Report, ReportFormat, ReportKind, ReportState};
use agf_core::risk::Finding;
use agf_core::time::{TimeRange, Timestamp};
use async_trait::async_trait;

use crate::pagination_page;
use crate::persistence::{AlertWrite, PgWrite, WriteQueue};

/// 内存状态（单锁保护；所有操作都是短临界区且不跨 `await`）。
#[derive(Debug, Default)]
struct Memory {
    assets: BTreeMap<(TenantId, Id), Asset>,
    changes: Vec<AssetChange>,
    snapshots: BTreeMap<(TenantId, String, Id), String>,
    findings: BTreeMap<(TenantId, Id), Finding>,
    policies: BTreeMap<(TenantId, Id), Policy>,
    alerts: BTreeMap<(TenantId, Id), agf_core::alert::Alert>,
    cases: BTreeMap<(TenantId, Id), Case>,
    case_events: Vec<CaseEvent>,
    case_seq: BTreeMap<i32, u32>,
    audits: BTreeMap<TenantId, Vec<AuditLog>>,
    quotas: BTreeMap<(TenantId, Id), Quota>,
    quota_usage: BTreeMap<(TenantId, Id), i64>,
    scans: BTreeMap<(TenantId, Id), ScanJob>,
    campaign_records: BTreeMap<(TenantId, Id), CampaignRecord>,
    campaigns: BTreeMap<(TenantId, Id), RedteamCampaign>,
    campaign_results: BTreeMap<(TenantId, Id), Vec<RedteamResult>>,
    campaign_reports: BTreeMap<(TenantId, Id), RedteamReport>,
    reports: BTreeMap<(TenantId, Id), Report>,
    api_keys: Vec<ApiKey>,
    route_policies: BTreeMap<(TenantId, Id), ModelRoutePolicy>,
    soar_runs: BTreeMap<(TenantId, Id), SoarRunRecord>,
}

/// 数据层入口。
#[derive(Debug)]
pub struct ApiStore {
    memory: Mutex<Memory>,
    database: Option<Arc<agf_storage::Store>>,
    /// 写后持久化队列（`None` = 离线内存模式，写入不落 PG）。
    ///
    /// 写方法在**改完内存之后**塞一条 [`PgWrite`] 进来；队列满时丢弃并计数（见
    /// [`crate::persistence::WriteQueue::enqueue`]）。它由 `AppState` 的
    /// [`crate::persistence::PersistenceBridge`] 创建并持有（同一个 `Arc`）。
    journal: Option<Arc<WriteQueue>>,
}

mod alerts;
mod asset_findings;
mod asset_names;
mod asset_operations;
pub(crate) use asset_selection::exposure as asset_exposure;
mod asset_deletion;
mod asset_facet_sql;
pub(crate) mod asset_facets;
mod asset_queries;
mod asset_selection;
mod asset_statistics;
pub(crate) use asset_selection::AssetSelection;
mod api_key_audited;
pub(crate) mod asset_transaction;
mod assets;
mod campaign_alerts;
mod campaign_findings;
mod campaign_queries;
mod campaign_record;
mod campaign_sql;
mod cases;
pub(crate) mod cloud_assets;
mod console_models;
mod console_store;
mod core;
mod durable_alerts;
mod durable_assets;
mod durable_audit;
mod durable_campaigns;
mod durable_cases;
mod durable_scans;
mod findings;
mod hydrate;
pub(crate) mod model_assets;
pub(crate) mod mse_discovery;
mod ops;
pub(crate) mod privatelink_discovery;
mod scan_completion;
mod scan_queries;
mod scan_records;
pub(crate) mod search;
pub(crate) mod skill_publication_offline;
mod support;
mod tasks;
pub(crate) use campaign_record::CAMPAIGN_TIMEOUT;
pub use campaign_record::CampaignRecord;
mod types;

pub use console_models::{ModelRoutePolicy, SoarRunRecord};
pub use support::{PlatformSnapshot, action_label, new_report, parse_case_code, recent_window};
pub use types::{ScanJob, ScanJobState};

mod alert_history;

mod durable_findings;
