-- Trigger receipts exclude already evaluated alert identities, including non-matches.
CREATE UNIQUE INDEX console_soar_trigger_alert ON console_configurations
    (tenant_id,(payload->>'automation_id'),(payload->>'alert_id'))
    WHERE kind='soar-automation-delivery' AND deleted_at IS NULL;
CREATE INDEX console_soar_trigger_history ON console_configurations
    (tenant_id,(payload->>'automation_id'),updated_at DESC,id DESC)
    WHERE kind='soar-automation-delivery' AND deleted_at IS NULL;
CREATE INDEX alerts_automation_created ON alerts (tenant_id,created_at,id);
