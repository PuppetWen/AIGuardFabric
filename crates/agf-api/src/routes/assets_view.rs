//! Keep observed scores, declared network metadata and authorized finding counts distinct.
use crate::{error::ApiResult, middleware::Principal, query::ListQuery, state::AppState};
use agf_core::{asset::Asset, ids::Id, pagination::Page};
use serde_json::{Value, json};
use std::collections::BTreeMap;

async fn counts(state: &AppState, principal: &Principal, ids: &[Id]) -> ApiResult<Option<BTreeMap<Id, i64>>> {
    if principal.require(state, "findings", "read").is_err() {
        return Ok(None);
    }
    Ok(Some(state.store.asset_open_findings(principal.tenant, ids).await?))
}

fn render(asset: &Asset, counts: Option<&BTreeMap<Id, i64>>) -> ApiResult<Value> {
    let mut view = serde_json::to_value(asset)?;
    view["risk_score"] = json!(asset.risk_score);
    view["exposure"] = json!(crate::store::asset_exposure(asset));
    // Counts describe saved findings, not whether an assessment has run or the asset is safe.
    view["open_findings"] = json!(counts.and_then(|rows| rows.get(&asset.id)));
    Ok(view)
}

pub(super) async fn detail(state: &AppState, principal: &Principal, asset: &Asset) -> ApiResult<Value> {
    let counts = counts(state, principal, &[asset.id]).await?;
    render(asset, counts.as_ref())
}

pub(super) async fn page(
    state: &AppState,
    principal: &Principal,
    query: &ListQuery,
    page: &Page<Asset>,
) -> ApiResult<Value> {
    let counts = if query.fields.is_empty() || query.fields.iter().any(|field| field == "open_findings") {
        counts(state, principal, &page.items.iter().map(|asset| asset.id).collect::<Vec<_>>()).await?
    } else {
        None
    };
    let mut response = query.render_page(page)?;
    response["items"] = Value::Array(
        page.items
            .iter()
            .map(|asset| render(asset, counts.as_ref()).map(|value| query.project(&value)))
            .collect::<ApiResult<Vec<_>>>()?,
    );
    Ok(response)
}
