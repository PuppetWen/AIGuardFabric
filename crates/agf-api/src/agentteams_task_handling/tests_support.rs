use super::{Actor, FailureEvidence, Journal, ResolutionInput, ResolutionPlan, VerifiedSource, source_proof, util};
use crate::integration_store::Stored;
use agf_core::{
    credential::KeyBackend,
    enums::{HealthState, IngestProtocol},
    error::DomainResult,
    ids::{Id, TenantId, deterministic_id},
    source::{CollectionMode, LogSource, SourceConnection, SourceRecord},
    time::Timestamp,
};
use agf_ingest::pipeline::AgentTeamsAuditRecord;
use agf_storage::crypto::FieldCipher;
use secrecy::SecretString;

pub(super) struct Fixture {
    pub(super) tenant: TenantId,
    pub(super) actor: Actor,
    pub(super) cipher: FieldCipher,
    pub(super) cloud: Stored,
    pub(super) source: SourceRecord,
    pub(super) now: Timestamp,
}
impl Fixture {
    pub(super) fn new() -> DomainResult<Self> {
        let tenant = TenantId::default_tenant();
        let now = Timestamp::now();
        let cipher = FieldCipher::new(&[31; 32], "owned-task-handling", KeyBackend::LocalFile)?;
        let cloud_id = crate::integration_store::id(tenant, "alicloud-agentteams");
        let private = cipher.encrypt(
            &SecretString::from("{\"synthetic-secret\":\"private-test-only\"}".to_owned()),
            &FieldCipher::make_aad(&tenant, &cloud_id),
        )?;
        let cloud = Stored {
            id: cloud_id,
            name: "alicloud-agentteams".into(),
            enabled: true,
            mock: true,
            version: 1,
            updated_at: now,
            private,
        };
        let source = SourceRecord {
            source: Some(LogSource {
                id: Id::new(),
                tenant_id: tenant,
                name: "owned SDK error source".into(),
                protocol: IngestProtocol::Webhook,
                vendor: "owned".into(),
                product: "agentteams".into(),
                enabled: true,
                parser_id: None,
                connection: SourceConnection::default(),
                mode: CollectionMode::Push,
                poll_interval_secs: None,
                require_mtls: false,
                allowed_cidrs: Vec::new(),
                max_message_bytes: 1_048_576,
                max_eps: 10_000,
                tags: Vec::new(),
                health: HealthState::Unconfigured,
                last_event_at: None,
                total_events: 0,
                last_error: None,
                created_at: now,
                updated_at: now,
            }),
            ..SourceRecord::default()
        };
        Ok(Self {
            tenant,
            actor: Actor { subject_id: Id::new(), identity_tenant: tenant, subject_kind: "user".into() },
            cipher,
            cloud,
            source,
            now,
        })
    }
    pub(super) fn source_id(&self) -> DomainResult<Id> {
        self.source.source.as_ref().map(|source| source.id).ok_or_else(util::corrupt)
    }
    pub(super) fn record(&self, label: &str) -> DomainResult<AgentTeamsAuditRecord> {
        let scope = deterministic_id("owned-task-scope", &self.tenant.to_string());
        Ok(AgentTeamsAuditRecord {
            id: deterministic_id("agf.agentteams.event", &format!("{}:{scope}:{label}", self.tenant)),
            tenant_id: self.tenant,
            scope_id: scope,
            source_id: self.source_id()?,
            binding_id: Id::new(),
            external_event_id: label.into(),
            content_hash: "a".repeat(64),
            event_time: self.now.offset_secs(-1),
            received_at: self.now,
            kind: "task".into(),
            from_team: Some("owned-team".into()),
            from_worker: None,
            from_asset: Some(Id::new()),
            to_team: None,
            to_worker: None,
            to_asset: None,
            task_id: Some("owned-task".into()),
            trace_id: Some("owned-trace".into()),
            span_id: None,
            parent_span_id: None,
            status: "error".into(),
            duration_ms: None,
            message_preview: "a collector statement, not cloud proof".into(),
            mocked: true,
        })
    }
    pub(super) fn evidence(&self, label: &str) -> DomainResult<FailureEvidence> {
        FailureEvidence::derive(self.tenant, &self.record(label)?)
    }
    pub(super) fn input(&self, version: u64) -> DomainResult<ResolutionInput> {
        Ok(ResolutionInput {
            request_id: Id::new(),
            expected_version: version,
            expected_cloud_configuration_version: self.cloud.version,
            expected_source_fingerprint: source_proof::issue(&self.cipher, self.tenant, &self.cloud, &self.source)?,
            decision: super::Decision::Acknowledged,
        })
    }
    pub(super) fn verified(&self, input: &ResolutionInput) -> DomainResult<VerifiedSource> {
        let proof = source_proof::authenticate(
            &self.cipher,
            self.tenant,
            self.source_id()?,
            &input.expected_source_fingerprint,
        )?;
        source_proof::check_current(&proof, &self.cloud, &self.source)
    }
    pub(super) fn resolve(
        &self,
        journal: &Journal,
        evidence: &FailureEvidence,
        current: Option<&super::Handling>,
        previous: Option<&super::RequestFact>,
        verified: Option<&VerifiedSource>,
        input: &ResolutionInput,
    ) -> DomainResult<ResolutionPlan> {
        super::resolve(
            super::reducer::ResolutionContext {
                tenant: self.tenant,
                actor: &self.actor,
                now: self.now,
                journal,
                evidence,
                current,
                previous_request: previous,
                source: verified,
            },
            input,
        )
    }
}
