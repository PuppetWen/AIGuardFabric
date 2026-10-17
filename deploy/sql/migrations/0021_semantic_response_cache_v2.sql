-- No pgvector dependency: exact f64 cosine is computed over at most 128 authenticated candidates.
-- This table never imports plaintext rows from the legacy semantic_cache table.
CREATE TABLE semantic_response_cache_v2 (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    id uuid NOT NULL,
    domain_hash text NOT NULL CHECK (domain_hash ~ '^[0-9a-f]{64}$'),
    dimensions integer NOT NULL CHECK (dimensions BETWEEN 1 AND 4096),
    created_ms bigint NOT NULL,
    expires_ms bigint NOT NULL,
    sealed_bytes integer NOT NULL CHECK (sealed_bytes BETWEEN 1 AND 262144),
    payload bytea NOT NULL,
    PRIMARY KEY (tenant_id,id),
    CHECK (expires_ms>created_ms AND expires_ms::numeric-created_ms::numeric<=900000),
    CHECK (octet_length(payload)=sealed_bytes)
);
CREATE INDEX semantic_response_cache_v2_lookup ON semantic_response_cache_v2(tenant_id,domain_hash,created_ms,id);
ALTER TABLE semantic_response_cache_v2 ENABLE ROW LEVEL SECURITY;
ALTER TABLE semantic_response_cache_v2 FORCE ROW LEVEL SECURITY;
CREATE POLICY semantic_response_cache_v2_tenant ON semantic_response_cache_v2
    USING (tenant_id=agf_current_tenant()) WITH CHECK (tenant_id=agf_current_tenant());
GRANT SELECT,INSERT,UPDATE,DELETE ON semantic_response_cache_v2 TO agf_tenant_runtime;
