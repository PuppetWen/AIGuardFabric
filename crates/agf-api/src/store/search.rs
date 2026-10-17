//! Bounded search projections. Only explicitly authorized resource groups are queried.
use super::*;
use agf_storage::map_sqlx_err;

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct SearchRecord {
    pub id: String,
    pub label: String,
    pub kind: String,
    pub hint: String,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum SearchResource {
    Assets,
    Findings,
    Alerts,
    Cases,
}

impl SearchResource {
    pub(crate) const fn permission(self) -> &'static str {
        match self {
            Self::Assets => "assets",
            Self::Findings => "findings",
            Self::Alerts => "alerts",
            Self::Cases => "cases",
        }
    }

    fn projection(self) -> &'static str {
        match self {
            Self::Assets => "SELECT id::text, name AS label,
                CASE kind WHEN 'agent' THEN 'agent' WHEN 'mcp-server' THEN 'mcp' WHEN 'mcp-client' THEN 'mcp' ELSE 'asset' END AS kind,
                concat_ws(' · ',kind,department) AS hint,
                concat_ws(E'\\n',id::text,name,owner,department,endpoint,fingerprint,tags::text) AS text
                FROM assets WHERE deleted_at IS NULL",
            Self::Findings => "SELECT id::text,title AS label,'finding'::text AS kind,
                concat_ws(' · ',severity,rule_keys->>0) AS hint,
                concat_ws(E'\\n',id::text,title,summary,target,rule_keys::text) AS text
                FROM findings WHERE deleted_at IS NULL",
            Self::Alerts => "SELECT id::text,title AS label,'alert'::text AS kind,
                concat_ws(' · ',severity,state) AS hint,
                concat_ws(E'\\n',id::text,title,description) AS text FROM alerts WHERE deleted_at IS NULL",
            Self::Cases => "SELECT id::text,title AS label,'case'::text AS kind,
                concat_ws(' · ',code,severity,state) AS hint,
                concat_ws(E'\\n',id::text,code,title,summary,owner,tags::text) AS text FROM cases",
        }
    }
}

fn record(id: Id, label: &str, kind: &str, hint: String) -> SearchRecord {
    SearchRecord { id: id.to_string(), label: label.into(), kind: kind.into(), hint }
}
fn contains(needle: &str, fields: &[&str]) -> bool {
    fields.iter().any(|field| field.to_lowercase().contains(needle))
}

impl ApiStore {
    pub(crate) async fn search_records(
        &self,
        tenant: TenantId,
        resource: SearchResource,
        needle: &str,
        limit: i64,
    ) -> DomainResult<Vec<SearchRecord>> {
        let Some(database) = &self.database else { return self.search_memory(tenant, resource, needle, limit) };
        let sql = format!(
            "SELECT id,label,kind,hint FROM ({}) s WHERE strpos(lower(text),$1)>0
            ORDER BY (lower(id)=$1 OR lower(label)=$1) DESC,lower(label),id LIMIT $2",
            resource.projection()
        );
        let needle = needle.to_owned();
        database
            .with_tenant(tenant, move |tx| {
                Box::pin(async move {
                    sqlx::query("SET LOCAL statement_timeout = '2000ms'")
                        .execute(&mut **tx)
                        .await
                        .map_err(|e| map_sqlx_err("search_timeout", &e))?;
                    sqlx::query_as(&sql)
                        .bind(needle)
                        .bind(limit)
                        .fetch_all(&mut **tx)
                        .await
                        .map_err(|e| map_sqlx_err("search", &e))
                })
            })
            .await
    }

    fn search_memory(
        &self,
        tenant: TenantId,
        resource: SearchResource,
        needle: &str,
        limit: i64,
    ) -> DomainResult<Vec<SearchRecord>> {
        let memory = self.lock()?;
        let mut rows: Vec<SearchRecord> = match resource {
            SearchResource::Assets => memory
                .assets
                .iter()
                .filter(|((owner, _), a)| {
                    *owner == tenant
                        && contains(
                            needle,
                            &[
                                &a.id.to_string(),
                                &a.name,
                                a.owner.as_deref().unwrap_or_default(),
                                a.department.as_deref().unwrap_or_default(),
                                a.endpoint.as_deref().unwrap_or_default(),
                                &a.fingerprint,
                                &a.tags.join("\n"),
                            ],
                        )
                })
                .map(|(_, a)| {
                    record(
                        a.id,
                        &a.name,
                        match a.kind {
                            agf_core::enums::AssetKind::Agent => "agent",
                            agf_core::enums::AssetKind::McpServer | agf_core::enums::AssetKind::McpClient => "mcp",
                            _ => "asset",
                        },
                        format!("{} · {}", a.kind.as_str(), a.department.as_deref().unwrap_or("-")),
                    )
                })
                .collect(),
            SearchResource::Findings => memory
                .findings
                .iter()
                .filter(|((owner, _), f)| {
                    *owner == tenant
                        && contains(
                            needle,
                            &[&f.id.to_string(), &f.title, &f.summary, &f.target, &f.rule_keys.join("\n")],
                        )
                })
                .map(|(_, f)| {
                    record(
                        f.id,
                        &f.title,
                        "finding",
                        format!("{} · {}", f.severity.as_str(), f.rule_keys.first().map_or("-", String::as_str)),
                    )
                })
                .collect(),
            SearchResource::Alerts => memory
                .alerts
                .iter()
                .filter(|((owner, _), a)| {
                    *owner == tenant && contains(needle, &[&a.id.to_string(), &a.title, &a.description])
                })
                .map(|(_, a)| {
                    record(a.id, &a.title, "alert", format!("{} · {}", a.severity.as_str(), a.state.as_str()))
                })
                .collect(),
            SearchResource::Cases => memory
                .cases
                .iter()
                .filter(|((owner, _), c)| {
                    *owner == tenant
                        && contains(
                            needle,
                            &[
                                &c.id.to_string(),
                                &c.code,
                                &c.title,
                                &c.summary,
                                c.owner.as_deref().unwrap_or_default(),
                                &c.tags.join("\n"),
                            ],
                        )
                })
                .map(|(_, c)| {
                    record(
                        c.id,
                        &c.title,
                        "case",
                        format!("{} · {} · {}", c.code, c.severity.as_str(), c.state.as_str()),
                    )
                })
                .collect(),
        };
        rows.sort_by_key(|row| {
            (
                !(row.id.to_lowercase() == needle || row.label.to_lowercase() == needle),
                row.label.to_lowercase(),
                row.id.clone(),
            )
        });
        rows.truncate(usize::try_from(limit).unwrap_or_default());
        Ok(rows)
    }
}
