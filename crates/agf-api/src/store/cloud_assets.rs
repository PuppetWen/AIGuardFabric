//! 云盘点只刷新云来源属性；数据库资产与快照由调用方同事务发布。
use super::asset_transaction::AssetTransaction;
use crate::state::AppState;
use agf_asset::service::AssetBackend;
use agf_core::{asset::Asset, error::DomainResult, ids::Id};
use std::collections::BTreeMap;

pub(crate) async fn merge_in_transaction(
    tx: &AssetTransaction<'_>,
    discovered: &[Asset],
) -> DomainResult<BTreeMap<String, Id>> {
    let mut ids = BTreeMap::new();
    let mut ordered = discovered.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|asset| &asset.fingerprint);
    for item in ordered {
        let existing = tx.find_by_fingerprint(item.tenant_id, &item.fingerprint).await?;
        let asset = merge_fields(existing, item);
        let id = tx.upsert(item.tenant_id, &asset).await?;
        ids.insert(asset.name, id);
    }
    Ok(ids)
}

pub(crate) fn merge_offline(state: &AppState, discovered: &[Asset]) -> DomainResult<BTreeMap<String, Id>> {
    let mut ids = BTreeMap::new();
    for item in discovered {
        let existing = state.store.asset_find_by_fingerprint(item.tenant_id, &item.fingerprint)?;
        let asset = merge_fields(existing, item);
        state.store.hydrate_asset(&asset)?;
        ids.insert(asset.name.clone(), asset.id);
    }
    Ok(ids)
}
fn merge_fields(existing: Option<Asset>, fresh: &Asset) -> Asset {
    let Some(mut current) = existing else { return fresh.clone() };
    current.name = fresh.name.clone();
    current.vendor = fresh.vendor.clone();
    current.version = fresh.version.clone();
    current.last_seen_at = fresh.last_seen_at;
    current.updated_at = fresh.updated_at;
    current.attributes.extend(fresh.attributes.clone());
    current
}
