use agf_core::error::{DomainError, DomainResult};
use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Number, Value};
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeMap, fmt};

pub(super) const MAX_CONFIG_BYTES: usize = 64 * 1024;

/// Configuration text has separate bounds from the complete provider response.
/// Reject duplicate object keys instead of letting serde_json silently choose one.
pub(super) fn parse(raw: &str) -> DomainResult<Value> {
    if raw.len() > MAX_CONFIG_BYTES {
        return Err(DomainError::Parse("APIG policy config exceeds 64 KiB".into()));
    }
    let mut decoder = serde_json::Deserializer::from_str(raw);
    let Unique(value) = Unique::deserialize(&mut decoder)
        .map_err(|_| DomainError::Parse("APIG policy config is invalid or has duplicate keys".into()))?;
    decoder.end().map_err(|_| DomainError::Parse("APIG policy config has trailing data".into()))?;
    if !value.is_object() {
        return Err(DomainError::Parse("APIG policy config must be an object".into()));
    }
    Ok(value)
}

pub(super) fn canonical(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let sorted: BTreeMap<_, _> = object.iter().map(|(key, value)| (key.clone(), canonical(value))).collect();
            Value::Object(sorted.into_iter().collect())
        }
        Value::Array(values) => Value::Array(values.iter().map(canonical).collect()),
        value => value.clone(),
    }
}

pub(super) fn fingerprint(value: &Value) -> String {
    hex::encode(Sha256::digest(canonical(value).to_string().as_bytes()))
}

struct Unique(Value);

impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        decoder.deserialize_any(UniqueVisitor)
    }
}

struct UniqueVisitor;

impl<'de> Visitor<'de> for UniqueVisitor {
    type Value = Unique;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JSON with unique object keys")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Unique, E> {
        Ok(Unique(Value::Bool(value)))
    }
    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Unique, E> {
        Ok(Unique(Value::Number(value.into())))
    }
    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Unique, E> {
        Ok(Unique(Value::Number(value.into())))
    }
    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Unique, E> {
        Number::from_f64(value).map(|number| Unique(Value::Number(number))).ok_or_else(|| E::custom("invalid number"))
    }
    fn visit_str<E: de::Error>(self, value: &str) -> Result<Unique, E> {
        Ok(Unique(Value::String(value.into())))
    }
    fn visit_string<E: de::Error>(self, value: String) -> Result<Unique, E> {
        Ok(Unique(Value::String(value)))
    }
    fn visit_none<E: de::Error>(self) -> Result<Unique, E> {
        Ok(Unique(Value::Null))
    }
    fn visit_unit<E: de::Error>(self) -> Result<Unique, E> {
        Ok(Unique(Value::Null))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Unique, A::Error> {
        let mut values = Vec::new();
        while let Some(Unique(value)) = sequence.next_element()? {
            values.push(value);
        }
        Ok(Unique(Value::Array(values)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut source: A) -> Result<Unique, A::Error> {
        let mut object = Map::new();
        while let Some(key) = source.next_key::<String>()? {
            if object.contains_key(&key) {
                return Err(de::Error::custom("duplicate object key"));
            }
            let Unique(value) = source.next_value()?;
            object.insert(key, value);
        }
        Ok(Unique(Value::Object(object)))
    }
}
