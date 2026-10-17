-- 所有租户事务切换到无 RLS 绕过权限的角色；连接所有者仅用于迁移/平台操作。
DO $$
DECLARE t record;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='agf_tenant_runtime') THEN
        CREATE ROLE agf_tenant_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='agf_tenant_runtime' AND (rolsuper OR rolbypassrls)) THEN
        RAISE EXCEPTION 'agf_tenant_runtime must not have SUPERUSER or BYPASSRLS';
    END IF;
    EXECUTE format('GRANT agf_tenant_runtime TO %I', current_user);
    GRANT USAGE ON SCHEMA public TO agf_tenant_runtime;
    -- 补齐历史迁移遗漏的 refresh_tokens、login_attempts 等租户表。
    FOR t IN SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
             JOIN pg_attribute a ON a.attrelid=c.oid AND a.attname='tenant_id' AND NOT a.attisdropped
             WHERE n.nspname='public' AND NOT c.relrowsecurity AND c.relkind IN ('r','p') LOOP
        EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t.relname);
        EXECUTE format('CREATE POLICY agf_tenant_boundary ON public.%I USING (tenant_id=agf_current_tenant()) WITH CHECK (tenant_id=agf_current_tenant())', t.relname);
    END LOOP;
    FOR t IN SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
             WHERE n.nspname='public' AND c.relrowsecurity AND c.relkind IN ('r','p') LOOP
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON public.%I TO agf_tenant_runtime', t.relname);
    END LOOP;
    GRANT SELECT ON permissions, asset_types TO agf_tenant_runtime;
END $$;

-- API Key 尚未确定租户时，只允许按随机前缀定位租户；完整验证在租户事务内执行。
CREATE FUNCTION agf_api_key_tenant(key_prefix text) RETURNS uuid
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT tenant_id FROM public.api_keys
    WHERE prefix=key_prefix AND NOT revoked AND deleted_at IS NULL
    LIMIT 1
$$;
REVOKE ALL ON FUNCTION agf_api_key_tenant(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION agf_api_key_tenant(text) TO agf_tenant_runtime;
