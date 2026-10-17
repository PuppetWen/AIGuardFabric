-- Retain historical rows and provenance. Runtime records contain immutable case snapshots,
-- per-case evidence and the report, committed together; no write-behind acknowledgement.
ALTER TABLE redteam_campaigns ADD COLUMN IF NOT EXISTS record jsonb;
ALTER TABLE redteam_campaigns ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE redteam_campaigns ADD COLUMN IF NOT EXISTS deleted_at timestamptz;
UPDATE redteam_campaigns c SET record=jsonb_build_object(
    'campaign',to_jsonb(c)-'record'-'updated_at'-'deleted_at',
    'results',COALESCE((SELECT jsonb_agg(to_jsonb(r) ORDER BY r.executed_at,r.id)
        FROM redteam_results r WHERE r.campaign_id=c.id AND r.tenant_id=c.tenant_id),'[]'::jsonb),
    'report',(SELECT to_jsonb(r) FROM redteam_reports r WHERE r.campaign_id=c.id AND r.tenant_id=c.tenant_id
        ORDER BY r.generated_at DESC,r.id LIMIT 1)
) WHERE record IS NULL;
ALTER TABLE redteam_campaigns ALTER COLUMN record SET NOT NULL;
CREATE INDEX IF NOT EXISTS ix_redteam_active ON redteam_campaigns(tenant_id,created_at)
    WHERE state IN ('queued','running') AND deleted_at IS NULL;
