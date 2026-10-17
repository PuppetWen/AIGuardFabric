-- Immutable daily baselines: discovery updates cannot rewrite an accepted inventory run.
CREATE TABLE asset_inventory_runs (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    id uuid NOT NULL,
    inventory_date date NOT NULL,
    payload jsonb NOT NULL,
    PRIMARY KEY (tenant_id,id),
    UNIQUE (tenant_id,inventory_date)
);
CREATE TABLE asset_inventory_snapshots (
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    payload jsonb NOT NULL,
    PRIMARY KEY (tenant_id,run_id,asset_id),
    FOREIGN KEY (tenant_id,run_id) REFERENCES asset_inventory_runs(tenant_id,id)
);
CREATE TABLE asset_inventory_changes (
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    position integer NOT NULL,
    payload jsonb NOT NULL,
    PRIMARY KEY (tenant_id,run_id,position),
    FOREIGN KEY (tenant_id,run_id) REFERENCES asset_inventory_runs(tenant_id,id)
);
ALTER TABLE asset_inventory_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_inventory_runs FORCE ROW LEVEL SECURITY;
CREATE POLICY asset_inventory_runs_tenant ON asset_inventory_runs
    USING (tenant_id=agf_current_tenant()) WITH CHECK (tenant_id=agf_current_tenant());
ALTER TABLE asset_inventory_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_inventory_snapshots FORCE ROW LEVEL SECURITY;
CREATE POLICY asset_inventory_snapshots_tenant ON asset_inventory_snapshots
    USING (tenant_id=agf_current_tenant()) WITH CHECK (tenant_id=agf_current_tenant());
ALTER TABLE asset_inventory_changes ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_inventory_changes FORCE ROW LEVEL SECURITY;
CREATE POLICY asset_inventory_changes_tenant ON asset_inventory_changes
    USING (tenant_id=agf_current_tenant()) WITH CHECK (tenant_id=agf_current_tenant());
GRANT SELECT,INSERT ON asset_inventory_runs,asset_inventory_snapshots,asset_inventory_changes TO agf_tenant_runtime;
