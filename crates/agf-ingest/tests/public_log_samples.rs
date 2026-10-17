#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
//! Public original captures: provenance, field extraction and original-byte hashes.
//! HTTP preview and actual replay are covered by agf-api/tests/public_log_replay.rs.

mod common;

use common::*;

const FIXTURES: &[(&str, &str)] = &[
    ("public/aws-cloudtrail-json.log", include_str!("../../../tests/fixtures/logs/public/aws-cloudtrail-json.log")),
    (
        "public/azure-entra-service-principal-json.log",
        include_str!("../../../tests/fixtures/logs/public/azure-entra-service-principal-json.log"),
    ),
    (
        "public/crowdstrike-falcon-fdr-process-json.log",
        include_str!("../../../tests/fixtures/logs/public/crowdstrike-falcon-fdr-process-json.log"),
    ),
    (
        "public/paloalto-panos-threat-csv.log",
        include_str!("../../../tests/fixtures/logs/public/paloalto-panos-threat-csv.log"),
    ),
    ("public/zeek-conn-json.log", include_str!("../../../tests/fixtures/logs/public/zeek-conn-json.log")),
];
const MANIFEST: &str = include_str!("../../../tests/fixtures/logs/public/manifest.json");
const LICENSE: &str = include_str!("../../../tests/fixtures/logs/public/LICENSE.splunk-attack-data");
const NOTICE: &str = include_str!("../../../tests/fixtures/logs/public/NOTICE.md");

fn samples() -> Vec<serde_json::Value> {
    serde_json::from_str::<serde_json::Value>(MANIFEST).expect("public manifest")["samples"]
        .as_array()
        .expect("samples array")
        .clone()
}

fn fixture(sample: &serde_json::Value) -> &'static str {
    FIXTURES.iter().find(|(name, _)| Some(*name) == sample["fixture"].as_str()).expect("fixed fixture").1
}

#[test]
fn original_public_capture_provenance_covers_five_actual_vendors() {
    let rows = samples();
    assert_eq!(rows.len(), FIXTURES.len());
    let vendors: BTreeSet<_> = rows.iter().map(|row| row["vendor"].as_str().unwrap()).collect();
    assert_eq!(vendors.len(), 5);
    assert!(LICENSE.contains("Apache License") && LICENSE.contains("Version 2.0"));
    assert!(NOTICE.contains("public laboratory data") && NOTICE.contains("Copyright 2025 Splunk"));
    let main = manifest();
    assert_eq!(main.public_samples.len(), 5);
    for row in &rows {
        assert_eq!(row["synthetic"], false);
        assert_eq!(row["sourceLine"], 1);
        assert_eq!(row["license"], "Apache-2.0");
        assert_eq!(row["datasetKind"], "public-lab-capture");
        let revision = row["source"]["revision"].as_str().unwrap();
        assert_eq!(revision, "a92cc4e6d7e39d56a0840d206a0963eeee0e22db");
        assert_eq!(row["source"]["repository"], "https://github.com/splunk/attack_data");
        assert_eq!(
            row["source"]["url"],
            format!(
                "https://media.githubusercontent.com/media/splunk/attack_data/{revision}/{}",
                row["source"]["path"].as_str().unwrap()
            )
        );
        let source_hash = row["source"]["sha256"].as_str().unwrap();
        assert_eq!(source_hash.len(), 64);
        assert!(source_hash.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(agf_core::secret::content_hash(fixture(row)).to_uppercase(), row["fixtureSha256"].as_str().unwrap());
        assert_eq!(main.public_samples.get(row["key"].as_str().unwrap()), Some(row));
    }
}

#[test]
fn public_records_extract_real_fields_and_preserve_original_byte_hashes() {
    let mut registry = ParserRegistry::new();
    registry.load_dir(&parsers_dir()).expect("load production templates");
    assert!(registry.invalid_templates().is_empty());
    for row in samples() {
        let key = row["key"].as_str().unwrap();
        let parser = registry.find_key(key).expect("production parser");
        assert_eq!(parser.definition.vendor, row["vendor"].as_str().unwrap());
        // Include the captured original line ending in the raw value and its hash.
        let raw = fixture(&row);
        let first = engine::parse_with(&parser.definition, raw);
        assert!(first.matched, "{key}: {:?}", first.error);
        assert!(first.derived_errors.is_empty());
        for (path, expected) in row["expect"].as_object().unwrap() {
            assert_eq!(
                first.fields.get(path).and_then(engine::value_to_text).as_deref(),
                expected.as_str(),
                "{key}: {path}"
            );
        }
        let meta = SourceMeta {
            tenant_id: TenantId::default_tenant(),
            source_id: Id::new(),
            source_name: format!("public-{key}"),
            vendor: parser.definition.vendor.clone(),
            product: parser.definition.product.clone(),
            protocol: protocol_of(row["protocol"].as_str()),
            tags: vec!["public-lab-capture".to_owned()],
            ingested_at: Timestamp::now(),
        };
        let event = normalize::normalize(&first, &meta, raw, "public-raw-test");
        assert_eq!(event.raw, normalize::parse_raw_value(raw));
        assert_eq!(event.raw_hash, agf_core::secret::content_hash(raw));
        assert_eq!(event.category.as_str(), row["expect"]["event.category"].as_str().unwrap());
        assert_eq!(event.severity.as_str(), row["expect"]["event.severity"].as_str().unwrap());
        assert_eq!(event.raw_hash.to_uppercase(), row["fixtureSha256"].as_str().unwrap());
    }
}

#[test]
fn quoted_csv_preserves_commas_quotes_tabs_and_rejects_broken_fields() {
    let mut registry = ParserRegistry::new();
    registry.load_dir(&parsers_dir()).expect("load templates");
    let mut definition = registry.find_key("paloalto-panos-threat-csv").unwrap().definition.clone();
    definition.pattern = "serial,url,action".to_owned();
    definition.required_fields = vec!["serial".to_owned(), "url".to_owned()];
    definition.mapping = agf_core::parser::FieldMapping::default();
    definition.mapping.map.insert("url".to_owned(), "url.path".to_owned());
    definition.mapping.map.insert("serial".to_owned(), "observer.serial_number".to_owned());
    definition.mapping.map.insert("action".to_owned(), "event.action_raw".to_owned());
    let output = engine::parse_with(&definition, "Oct 15 12:08:38 firewall 123,\"/a,b/\"\"value\"\"\tend\",allow");
    assert!(output.matched, "{:?}", output.error);
    assert_eq!(output.fields.get("url.path").and_then(engine::value_to_text).as_deref(), Some("/a,b/\"value\"\tend"));
    assert_eq!(output.fields.get("event.action_raw").and_then(engine::value_to_text).as_deref(), Some("allow"));
    assert!(!engine::parse_with(&definition, "123,\"unterminated,allow").matched);
    assert!(!engine::parse_with(&definition, "123,\"closed\"junk,allow").matched);
    // Existing comma-separated headers also accept TSV data. A quoted comma is data.
    let tsv = "123\t\"/a,b/\"\"value\"\"\"\tallow";
    let output = engine::parse_with(&definition, tsv);
    assert!(output.matched, "{:?}", output.error);
    assert_eq!(output.fields.get("url.path").and_then(engine::value_to_text).as_deref(), Some("/a,b/\"value\""));
    assert_eq!(output.fields.get("event.action_raw").and_then(engine::value_to_text).as_deref(), Some("allow"));
    definition.pattern = "serial\turl\taction".to_owned();
    let explicit_tsv = engine::parse_with(&definition, tsv);
    assert!(explicit_tsv.matched, "{:?}", explicit_tsv.error);
    assert_eq!(explicit_tsv.fields, output.fields);
}
