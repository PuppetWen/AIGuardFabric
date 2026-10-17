-- Preserve task summaries across instances without retaining submitted prompt/config text.
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS result jsonb;
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS deleted_at timestamptz;
UPDATE scan_jobs SET result=jsonb_build_object(
    'id',id,'tenant_id',tenant_id,'name',name,
    'state',CASE WHEN state='completed' THEN 'succeeded' ELSE state END,
    'targets',total_targets,'domains','[]'::jsonb,'progress',progress,
    'use_llm_judge',false,'rule_hits','{}'::jsonb,'finding_count',findings_count,
    'risk_score',NULL,'max_severity','info','summary','Legacy task; detailed assessment unavailable',
    'elapsed_ms',0,'error',error,'requested_by','legacy',
    'created_at',created_at,'started_at',started_at,'finished_at',finished_at)
WHERE result IS NULL;
ALTER TABLE scan_jobs ALTER COLUMN result SET NOT NULL;
CREATE INDEX IF NOT EXISTS ix_scan_jobs_active ON scan_jobs(tenant_id,created_at)
    WHERE state IN ('queued','running') AND deleted_at IS NULL;
