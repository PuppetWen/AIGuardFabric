//! Search permissions are checked independently; results link to exact objects.
use super::*;
use crate::store::search::SearchResource;

pub(super) async fn search(
    State(state): State<AppState>,
    principal: Principal,
    query: ListQuery,
) -> ApiResult<Json<Vec<SearchHitView>>> {
    let allowed = |group| principal.require(&state, group, "read").is_ok();
    if !["assets", "findings", "alerts", "cases", "rules", "redteam"].iter().any(|g| allowed(g)) {
        // Preserve password/MFA preconditions instead of masking them as an empty result.
        principal.require(&state, "assets", "read")?;
    }
    let needle = query.q.as_deref().unwrap_or_default().trim().to_lowercase();
    if needle.chars().count() > 128 || needle.chars().any(char::is_control) {
        return Err(DomainError::Validation(
            "Search query must be at most 128 characters without control characters".into(),
        )
        .into());
    }
    let limit = query.filter_i64("limit")?.unwrap_or(SEARCH_DEFAULT_LIMIT);
    if !(1..=SEARCH_MAX_LIMIT).contains(&limit) {
        return Err(DomainError::Validation(format!("Search limit must be 1..{SEARCH_MAX_LIMIT}")).into());
    }
    if needle.is_empty() {
        return Ok(Json(vec![]));
    }
    let mut groups = vec![];
    for resource in [SearchResource::Assets, SearchResource::Findings, SearchResource::Alerts, SearchResource::Cases] {
        if !allowed(resource.permission()) {
            continue;
        }
        let rows = state.store.search_records(principal.tenant, resource, &needle, limit).await?;
        groups.push(
            rows.into_iter()
                .map(|r| {
                    let to = match resource {
                        SearchResource::Assets => format!("/assets/{}", r.id),
                        SearchResource::Findings => format!("/findings?finding={}", r.id),
                        SearchResource::Alerts => format!("/alerts?alert={}", r.id),
                        SearchResource::Cases => format!("/cases/{}", r.id),
                    };
                    SearchHitView { id: r.id, label: r.label, kind: r.kind, hint: r.hint, to }
                })
                .collect::<Vec<_>>(),
        );
    }
    if allowed("rules") {
        let pack = crate::rule_store::pack(&state, principal.tenant).await?;
        groups.push(
            pack.rules
                .iter()
                .filter(|r| matches(&needle, &[&r.key, &r.name, &r.description, &r.tags.join("\n")]))
                .map(|r| SearchHitView {
                    id: r.key.clone(),
                    label: r.name.clone(),
                    kind: "rule".into(),
                    hint: format!("{} · {} · v{}", r.domain.as_str(), r.severity.as_str(), r.version),
                    to: format!("/rules?rule={}", encode(&r.key)),
                })
                .collect(),
        );
    }
    if allowed("redteam") {
        groups.push(
            state
                .redteam_cases
                .cases()
                .iter()
                .filter(|c| matches(&needle, &[&c.key, &c.title, c.category.as_str(), &c.tags.join("\n")]))
                .map(|c| SearchHitView {
                    id: c.key.clone(),
                    label: c.title.clone(),
                    kind: "redteam".into(),
                    hint: format!("{} · {}", c.category.as_str(), c.severity.as_str()),
                    to: format!("/redteam?testCase={}", encode(&c.key)),
                })
                .collect(),
        );
    }
    for group in &mut groups {
        group.sort_by_key(|r| {
            (!(r.id.to_lowercase() == needle || r.label.to_lowercase() == needle), r.label.to_lowercase(), r.id.clone())
        });
    }
    // Exact matches first, then round-robin by resource: assets cannot crowd out incidents.
    let mut hits = Vec::new();
    for group in &mut groups {
        let count =
            group.iter().take_while(|r| r.id.to_lowercase() == needle || r.label.to_lowercase() == needle).count();
        hits.extend(group.drain(..count));
    }
    let limit = usize::try_from(limit).unwrap_or_default();
    for index in 0..limit {
        for group in &groups {
            if let Some(row) = group.get(index) {
                hits.push(row.clone());
            }
        }
        if hits.len() >= limit {
            break;
        }
    }
    hits.truncate(limit);
    Ok(Json(hits))
}
fn matches(needle: &str, fields: &[&str]) -> bool {
    fields.iter().any(|f| f.to_lowercase().contains(needle))
}
fn encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}
