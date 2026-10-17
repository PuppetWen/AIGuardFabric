-- One immutable, tenant-scoped receipt per alert / escalation tier.
-- The alert update, receipt and notification queue are committed in one transaction.
CREATE TABLE alert_escalation_receipts (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    alert_id uuid NOT NULL REFERENCES alerts(id),
    policy_version bigint NOT NULL CHECK (policy_version > 0),
    tier smallint NOT NULL CHECK (tier BETWEEN 1 AND 3),
    severity text NOT NULL,
    enqueued_at timestamptz NOT NULL,
    actor text NOT NULL,
    notification_ids jsonb NOT NULL,
    PRIMARY KEY (tenant_id,alert_id,tier)
);
CREATE INDEX alert_escalation_history ON alert_escalation_receipts (tenant_id,enqueued_at DESC);
ALTER TABLE alert_escalation_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_escalation_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY alert_escalation_receipts_tenant ON alert_escalation_receipts
    USING (tenant_id=agf_current_tenant()) WITH CHECK (tenant_id=agf_current_tenant());
GRANT SELECT,INSERT ON alert_escalation_receipts TO agf_tenant_runtime;
