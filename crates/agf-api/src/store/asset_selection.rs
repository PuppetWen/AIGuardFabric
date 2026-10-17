use super::*;
use agf_core::enums::AssetKind;

#[derive(Clone, Default)]
pub(crate) struct AssetSelection {
    pub kinds: Vec<String>,
    pub facets: super::asset_facets::FacetSelection,
    pub lifecycles: Vec<String>,
    pub classifications: Vec<String>,
    pub departments: Vec<String>,
    pub exposures: Vec<String>,
    pub min_exposure: Option<u8>,
}

impl AssetSelection {
    pub(crate) fn from_query(query: &crate::query::ListQuery) -> DomainResult<Self> {
        fn values(query: &crate::query::ListQuery, primary: &str, alias: &str) -> Vec<String> {
            let mut rows = query.filter_many(primary);
            rows.extend(query.filter_many(alias));
            rows.sort();
            rows.dedup();
            rows
        }
        let mut result = Self {
            departments: values(query, "departments", "department"),
            facets: super::asset_facets::FacetSelection::from_query(query)?,
            min_exposure: query.filter_i64("min_exposure")?.map(|value| u8::try_from(value.clamp(0, 100)).unwrap_or(0)),
            ..Default::default()
        };
        for kind in values(query, "kinds", "kind") {
            let mapped: Vec<&str> = match kind.as_str() {
                "mcp" => vec!["mcp-server", "mcp-client"],
                "model" => vec!["model-endpoint"],
                "tool" => vec!["skill"],
                "skill" if query.filter("kinds").is_some() => vec!["skill", "prompt-template"],
                "datasource" => vec!["data-source", "rag-kb", "vector-store"],
                "endpoint" => vec!["compute-node", "ide-plugin", "collector", "other"],
                other => {
                    AssetKind::parse(other).map_err(DomainError::Validation)?;
                    vec![other]
                }
            };
            result.kinds.extend(mapped.into_iter().map(ToString::to_string));
        }
        for value in values(query, "lifecycles", "lifecycle") {
            let mapped = match value.as_str() {
                "planned" => vec!["requested"],
                "onboarding" => vec!["under-review", "trial"],
                "active" => vec!["production", "changing"],
                "deprecated" => vec!["archived"],
                "retired" => vec!["rejected"],
                "requested" | "under-review" | "trial" | "production" | "changing" | "archived" | "rejected" => {
                    vec![value.as_str()]
                }
                _ => return Err(DomainError::Validation("Unknown asset lifecycle filter".into())),
            };
            result.lifecycles.extend(mapped.into_iter().map(ToString::to_string));
        }
        result.classifications = values(query, "classifications", "data_class");
        if result
            .classifications
            .iter()
            .any(|value| !matches!(value.as_str(), "public" | "internal" | "confidential" | "restricted"))
        {
            return Err(DomainError::Validation("Unknown asset classification filter".into()));
        }
        result.exposures = values(query, "exposures", "exposure");
        if result
            .exposures
            .iter()
            .any(|value| !matches!(value.as_str(), "public-internet" | "partner" | "intranet" | "isolated" | "unknown"))
        {
            return Err(DomainError::Validation("Unknown asset exposure filter".into()));
        }
        if [&result.kinds, &result.lifecycles, &result.classifications, &result.departments, &result.exposures]
            .into_iter()
            .any(|list| list.len() > 100 || list.iter().any(|v| v.len() > 256))
        {
            return Err(DomainError::Validation("Asset filter exceeds 100 entries or 256 bytes per value".into()));
        }
        Ok(result)
    }

    pub(super) fn matches(&self, asset: &Asset) -> bool {
        fn contains(list: &[String], value: &str) -> bool {
            list.is_empty() || list.iter().any(|s| s == value)
        }
        self.facets.matches(asset)
            && contains(&self.kinds, asset.kind.as_str())
            && contains(&self.lifecycles, asset.lifecycle.as_str())
            && contains(&self.classifications, asset.data_class.as_str())
            && contains(&self.departments, asset.department.as_deref().unwrap_or_default())
            && contains(&self.exposures, exposure(asset))
            && self.min_exposure.is_none_or(|v| asset.exposure_score >= v)
    }
}

pub(crate) fn exposure(asset: &Asset) -> &'static str {
    match asset.network_zone.as_deref().unwrap_or_default().trim().to_ascii_lowercase().as_str() {
        "public" => "public-internet",
        "dmz" => "partner",
        "isolated" => "isolated",
        "endpoint" | "intranet" | "private" => "intranet",
        _ => "unknown",
    }
}

pub(super) const EXPOSURE_SQL: &str =
    "CASE lower(trim(COALESCE(a.network_zone,''))) WHEN 'public' THEN 'public-internet'
    WHEN 'dmz' THEN 'partner' WHEN 'isolated' THEN 'isolated' WHEN 'endpoint' THEN 'intranet'
    WHEN 'intranet' THEN 'intranet' WHEN 'private' THEN 'intranet' ELSE 'unknown' END";
