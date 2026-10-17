//! Verify tenant RLS policies and the non-bypass runtime role.
use super::{AppError, PgPool};

const FUNCTION_POLICY: &str = "(tenant_id = agf_current_tenant())";
const CONFIG_POLICY: &str = "(tenant_id = (NULLIF(current_setting('agf.tenant_id'::text, true), ''::text))::uuid)";

pub(super) struct Inspection {
    pub enabled_tables: i64,
    pub tenant_tables: i64,
    pub unprotected: Vec<String>,
    pub runtime_role_safe: bool,
}

pub(super) async fn inspect(pool: &PgPool) -> Result<Inspection, AppError> {
    let role: Option<(bool, bool, bool)> =
        sqlx::query_as("SELECT rolsuper, rolbypassrls, rolcanlogin FROM pg_roles WHERE rolname='agf_tenant_runtime'")
            .fetch_optional(pool)
            .await
            .map_err(|e| AppError::Fatal(anyhow::anyhow!("检查租户数据库角色失败: {e}")))?;
    let mut runtime_role_safe = matches!(role, Some((false, false, false)));
    if runtime_role_safe {
        let mut tx = pool.begin().await.map_err(|e| AppError::Fatal(anyhow::anyhow!("开启租户角色探测失败: {e}")))?;
        sqlx::query("SET LOCAL ROLE agf_tenant_runtime")
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Fatal(anyhow::anyhow!("切换租户运行角色失败: {e}")))?;
        for tenant in ["00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002"] {
            sqlx::query("SELECT set_config('agf.tenant_id',$1,true)")
                .bind(tenant)
                .execute(&mut *tx)
                .await
                .map_err(|e| AppError::Fatal(anyhow::anyhow!("设置租户角色探测上下文失败: {e}")))?;
            let observed: Option<String> = sqlx::query_scalar("SELECT agf_current_tenant()::text")
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| AppError::Fatal(anyhow::anyhow!("读取租户策略函数失败: {e}")))?;
            if observed.as_deref() != Some(tenant) {
                runtime_role_safe = false;
                break;
            }
        }
        tx.rollback().await.map_err(|e| AppError::Fatal(anyhow::anyhow!("回滚租户角色探测失败: {e}")))?;
    }
    let rows: Vec<(String, bool, bool, i64, bool)> = sqlx::query_as(
        "SELECT c.relname::text, c.relrowsecurity,
                c.relowner = r.oid AND NOT c.relforcerowsecurity,
                count(p.policyname)::bigint,
                coalesce(bool_and(p.cmd='ALL' AND p.permissive='PERMISSIVE'
                    AND p.roles::text='{public}'
                    AND ((p.qual=$1 AND p.with_check=$1)
                      OR (p.qual=$2 AND p.with_check=$2))), false)
         FROM pg_class c
         JOIN pg_namespace n ON n.oid=c.relnamespace
         JOIN pg_attribute a ON a.attrelid=c.oid AND a.attname='tenant_id' AND NOT a.attisdropped
         JOIN pg_roles r ON r.rolname='agf_tenant_runtime'
         LEFT JOIN pg_policies p ON p.schemaname=n.nspname AND p.tablename=c.relname
         WHERE n.nspname='public' AND c.relkind IN ('r','p')
         GROUP BY c.oid, c.relname, c.relrowsecurity, c.relowner, c.relforcerowsecurity, r.oid
         ORDER BY c.relname",
    )
    .bind(FUNCTION_POLICY)
    .bind(CONFIG_POLICY)
    .fetch_all(pool)
    .await
    .map_err(|e| AppError::Fatal(anyhow::anyhow!("检查租户 RLS 策略失败: {e}")))?;
    let tenant_tables = i64::try_from(rows.len()).unwrap_or(i64::MAX);
    let enabled_tables =
        i64::try_from(rows.iter().filter(|(_, enabled, _, _, _)| *enabled).count()).unwrap_or(i64::MAX);
    let unprotected = rows
        .into_iter()
        .filter(|(_, enabled, owner_bypass, policies, expected)| {
            !enabled || *owner_bypass || *policies != 1 || !expected
        })
        .map(|(name, _, _, _, _)| name)
        .collect();
    Ok(Inspection { enabled_tables, tenant_tables, unprotected, runtime_role_safe })
}
