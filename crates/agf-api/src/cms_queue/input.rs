use super::{MAX_BODY, util};
use agf_core::{error::DomainResult, ids::Id, time::Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Payload {
    Event { name: String, content: String, at: Timestamp },
    Metric { name: String, value: f64, dimensions: BTreeMap<String, String>, at: Timestamp },
}

impl Payload {
    pub(super) fn validate(&self) -> DomainResult<()> {
        let name = self.name();
        if name.is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
            return Err(util::invalid());
        }
        match self {
            Self::Event { content, .. } if content.is_empty() || content.len() > 4096 => return Err(util::invalid()),
            Self::Metric { value, dimensions, .. } => {
                if !value.is_finite()
                    || dimensions.len() > 16
                    || dimensions.iter().any(|(k, v)| {
                        k.is_empty()
                            || k.len() > 128
                            || v.is_empty()
                            || v.len() > 256
                            || k.chars().chain(v.chars()).any(char::is_control)
                    })
                {
                    return Err(util::invalid());
                }
            }
            Self::Event { .. } => {}
        }
        util::bound(self, MAX_BODY)?;
        Ok(())
    }
    pub(super) fn name(&self) -> &str {
        match self {
            Self::Event { name, .. } | Self::Metric { name, .. } => name,
        }
    }
    pub(super) fn action(&self) -> &'static str {
        match self {
            Self::Event { .. } => "PutCustomEvent",
            Self::Metric { .. } => "PutCustomMetric",
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Enqueue {
    pub request_id: Id,
    pub configuration_version: u64,
    pub expected_generation: u64,
    pub items: Vec<Payload>,
    #[serde(default)]
    pub initialize_mock_fixture: bool,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Send {
    pub request_id: Id,
    pub expected_generation: u64,
    pub item_ids: Vec<Id>,
    #[serde(default)]
    pub confirm_live: bool,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Archive {
    pub request_id: Id,
    pub expected_generation: u64,
    pub item_ids: Vec<Id>,
}
pub(super) fn ids(id: Id, items: &[Id], max: usize) -> DomainResult<()> {
    if id.is_nil()
        || items.is_empty()
        || items.len() > max
        || items.iter().any(Id::is_nil)
        || items.iter().collect::<BTreeSet<_>>().len() != items.len()
    {
        return Err(util::invalid());
    }
    Ok(())
}
