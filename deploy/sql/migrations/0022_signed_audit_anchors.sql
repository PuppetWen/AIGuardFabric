-- 旧行明确保留为无签名历史检查点，绝不补签历史数据。
ALTER TABLE audit_chain_anchors ADD COLUMN chain_kind text NOT NULL DEFAULT 'management';
ALTER TABLE audit_chain_anchors ADD COLUMN chain_id uuid;
ALTER TABLE audit_chain_anchors ADD COLUMN agent_id uuid REFERENCES assets(id);
ALTER TABLE audit_chain_anchors ADD COLUMN signed_envelope text;
UPDATE audit_chain_anchors SET chain_id=tenant_id WHERE chain_id IS NULL;
ALTER TABLE audit_chain_anchors ALTER COLUMN chain_id SET NOT NULL;
ALTER TABLE audit_chain_anchors ADD CONSTRAINT audit_anchor_kind CHECK
    (chain_kind IN ('management','agent-runtime'));
ALTER TABLE audit_chain_anchors ADD CONSTRAINT audit_anchor_identity CHECK
    ((chain_kind='management' AND agent_id IS NULL) OR (chain_kind='agent-runtime' AND agent_id IS NOT NULL));
CREATE UNIQUE INDEX ux_signed_audit_anchor_sequence ON audit_chain_anchors
    (tenant_id, chain_kind, chain_id, up_to_sequence) WHERE signed_envelope IS NOT NULL;
CREATE INDEX ix_signed_audit_anchor_agent ON audit_chain_anchors
    (tenant_id, agent_id, chain_id, up_to_sequence) WHERE signed_envelope IS NOT NULL;

CREATE TABLE agent_runtime_audit_entries (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id uuid NOT NULL REFERENCES assets(id),
    chain_id uuid NOT NULL,
    sequence bigint NOT NULL CHECK (sequence>0),
    entry_hash text NOT NULL,
    -- TEXT 保留 Agent 的 AuditLog 哈希所使用的规范 JSON 对象顺序。
    payload text NOT NULL,
    UNIQUE (tenant_id, agent_id, chain_id, sequence)
);
ALTER TABLE agent_runtime_audit_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_runtime_audit_entries FORCE ROW LEVEL SECURITY;
CREATE POLICY agf_tenant_boundary ON agent_runtime_audit_entries
    USING (tenant_id=agf_current_tenant()) WITH CHECK (tenant_id=agf_current_tenant());
GRANT SELECT, INSERT ON agent_runtime_audit_entries TO agf_tenant_runtime;
-- 运行时应用凭据无权静默改写或删除签名历史。
REVOKE UPDATE, DELETE ON agent_runtime_audit_entries FROM agf_tenant_runtime;
REVOKE UPDATE, DELETE ON audit_chain_anchors FROM agf_tenant_runtime;
GRANT SELECT, INSERT ON audit_chain_anchors TO agf_tenant_runtime;
