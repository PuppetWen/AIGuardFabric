//! 模板构造底座：映射小工具（`fmap`/`smap`/`cmap`/`dmap`）与 `base()` 模板构造器。

use super::*;

pub(super) fn fmap(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs.iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())).collect()
}

pub(super) fn smap(pairs: &[(&str, Severity)]) -> BTreeMap<String, Severity> {
    pairs.iter().map(|(k, v)| ((*k).to_string(), *v)).collect()
}

pub(super) fn cmap(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs.iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())).collect()
}

pub(super) fn dmap(pairs: &[(&str, &str)]) -> BTreeMap<String, Value> {
    pairs.iter().map(|(k, v)| ((*k).to_string(), Value::from(*v))).collect()
}

/// Wazuh 的 `rule.level`（0-15）分级表。
#[must_use]
pub fn wazuh_severity_map() -> BTreeMap<String, Severity> {
    (0_u8..=15)
        .map(|level| {
            let severity = match level {
                0..=3 => Severity::Info,
                4..=6 => Severity::Low,
                7..=9 => Severity::Medium,
                10..=12 => Severity::High,
                _ => Severity::Critical,
            };
            (level.to_string(), severity)
        })
        .collect()
}

/// 构造模板骨架（其余字段由调用方按需覆盖）。
#[allow(clippy::too_many_arguments)]
pub(super) fn base(
    key: &str,
    name: &str,
    vendor: &str,
    product: &str,
    engine: ParserEngine,
    pattern: &str,
    protocols: &[IngestProtocol],
    fixture: &str,
    description: &str,
) -> ParserDefinition {
    ParserDefinition {
        key: key.to_string(),
        name: name.to_string(),
        vendor: vendor.to_string(),
        product: product.to_string(),
        protocols: protocols.to_vec(),
        engine,
        pattern: pattern.to_string(),
        fallback_patterns: Vec::new(),
        mapping: FieldMapping::default(),
        derived: BTreeMap::new(),
        required_fields: Vec::new(),
        version: 1,
        builtin: true,
        ai_inferred: false,
        description: description.to_string(),
        sample_fixture: format!("{FIXTURE_DIR_REL}/{fixture}"),
    }
}
