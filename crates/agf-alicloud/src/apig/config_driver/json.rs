use agf_core::error::{DomainError, DomainResult};
use serde::{
    Deserialize, Deserializer,
    de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Number, Value};
use sha2::{Digest as _, Sha256};
use std::{
    cell::Cell,
    collections::BTreeMap,
    fmt::{self, Write as _},
    rc::Rc,
};

pub(super) const MAX_CONFIG_BYTES: usize = 64 * 1024;

/// Configuration text has separate bounds from the complete provider response.
/// JSON and restricted YAML share exact unique string-key validation.
pub(super) fn parse(raw: &str) -> DomainResult<Value> {
    if raw.len() > MAX_CONFIG_BYTES {
        return Err(DomainError::Parse("APIG configuration exceeds 64 KiB".into()));
    }
    let value = match parse_json(raw) {
        Ok(value) => value,
        Err(_) => {
            safe_yaml(raw)?;
            let Unique(value) =
                Budget::new(true).deserialize(serde_yaml::Deserializer::from_str(raw)).map_err(|_| invalid())?;
            value
        }
    };
    if !value.is_object() {
        return Err(DomainError::Parse("APIG configuration must be an object".into()));
    }
    Ok(value)
}

fn parse_json(raw: &str) -> DomainResult<Value> {
    let mut decoder = serde_json::Deserializer::from_str(raw);
    let Unique(value) = Unique::deserialize(&mut decoder).map_err(|_| invalid())?;
    decoder.end().map_err(|_| invalid())?;
    Ok(value)
}

/// Preserve the original document format, not comments or original key ordering.
pub(super) fn encode_like(original: &str, value: &Value) -> DomainResult<String> {
    let value = canonical(value);
    let raw = if parse_json(original).is_ok() {
        value.to_string()
    } else {
        // Quoted YAML mapping keys and JSON-compatible values keep every scalar unambiguous.
        // Nested flow mappings/sequences are YAML too; string contents cannot become syntax.
        let object = value.as_object().ok_or_else(invalid)?;
        let mut encoded = String::new();
        for (key, value) in object {
            writeln!(&mut encoded, "{}: {value}", Value::String(key.clone())).map_err(|_| invalid())?;
        }
        encoded
    };
    if raw.len() > MAX_CONFIG_BYTES || parse(&raw)? != value {
        return Err(invalid());
    }
    Ok(raw)
}

fn invalid() -> DomainError {
    DomainError::Parse("APIG configuration is invalid, ambiguous or exceeds its safe bounds".into())
}

// Reject YAML expansion syntax before any document is loaded. Quoted tokens and literal/folded block
// content are values, not aliases/tags. Multiline quoted scalars are unsupported in this profile.
fn safe_yaml(raw: &str) -> DomainResult<()> {
    let mut block_indent = None;
    for line in raw.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let indent = line.bytes().take_while(|byte| *byte == b' ').count();
        if block_indent.is_some_and(|level| indent > level) {
            continue;
        }
        block_indent = None;
        let bytes = line.as_bytes();
        let (mut index, mut quote, mut plain, mut quoted_scalar) = (0, None, false, false);
        while let Some(&byte) = bytes.get(index) {
            if let Some(delimiter) = quote {
                if delimiter == b'"' && byte == b'\\' {
                    index += 2;
                    continue;
                }
                if byte == delimiter {
                    if delimiter == b'\'' && bytes.get(index + 1) == Some(&b'\'') {
                        index += 2;
                        continue;
                    }
                    quote = None;
                    quoted_scalar = true;
                }
                index += 1;
                continue;
            }
            match byte {
                b'#' if !plain || index == 0 || bytes[index - 1].is_ascii_whitespace() => break,
                b'&' | b'*' | b'!' if !plain => return Err(invalid()),
                b'%' if !plain => return Err(invalid()),
                b'\'' | b'"' => {
                    if !plain {
                        quote = Some(byte);
                    }
                    plain = true;
                }
                b'|' | b'>' if !plain => {
                    let header = line[index + 1..].split('#').next().unwrap_or("").trim();
                    if header.len() > 2 || !header.bytes().all(|c| c == b'+' || c == b'-' || (b'1'..=b'9').contains(&c))
                    {
                        return Err(invalid());
                    }
                    block_indent = Some(indent);
                    break;
                }
                // A quoted flow key may have an adjacent value without whitespace.
                // Its colon must start a new node before inspecting anchors/aliases/tags.
                b':' if quoted_scalar
                    || bytes.get(index + 1).is_none_or(|c| c.is_ascii_whitespace() || b",[]{}".contains(c)) =>
                {
                    plain = false;
                    quoted_scalar = false;
                }
                b'[' | b']' | b'{' | b'}' | b',' => {
                    plain = false;
                    quoted_scalar = false;
                }
                b'-' | b'?' if !plain && bytes.get(index + 1).is_none_or(u8::is_ascii_whitespace) => {}
                byte if byte.is_ascii_whitespace() => {}
                _ => {
                    plain = true;
                    quoted_scalar = false;
                }
            }
            index += 1;
        }
        if quote.is_some() {
            return Err(invalid());
        }
    }
    Ok(())
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
        Budget::new(false).deserialize(decoder)
    }
}

#[derive(Clone)]
struct Budget {
    nodes: Rc<Cell<usize>>,
    bytes: Rc<Cell<usize>>,
    depth: usize,
    yaml: bool,
}
impl Budget {
    fn new(yaml: bool) -> Self {
        Self {
            nodes: Rc::new(Cell::new(if yaml { 8_192 } else { MAX_CONFIG_BYTES })),
            bytes: Rc::new(Cell::new(MAX_CONFIG_BYTES)),
            depth: 0,
            yaml,
        }
    }
    fn child(&self) -> Self {
        Self { depth: self.depth + 1, ..self.clone() }
    }
    fn charge<E: de::Error>(&self, bytes: usize) -> Result<(), E> {
        let remaining = self.bytes.get().checked_sub(bytes).ok_or_else(|| E::custom("configuration byte bound"))?;
        self.bytes.set(remaining);
        Ok(())
    }
}
impl<'de> DeserializeSeed<'de> for Budget {
    type Value = Unique;
    fn deserialize<D: Deserializer<'de>>(self, decoder: D) -> Result<Unique, D::Error> {
        let nodes = self
            .nodes
            .get()
            .checked_sub(1)
            .ok_or_else(|| <D::Error as de::Error>::custom("configuration node bound"))?;
        if self.depth > if self.yaml { 64 } else { 128 } {
            return Err(de::Error::custom("configuration depth bound"));
        }
        self.nodes.set(nodes);
        decoder.deserialize_any(UniqueVisitor(self))
    }
}

struct UniqueVisitor(Budget);

impl<'de> Visitor<'de> for UniqueVisitor {
    type Value = Unique;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded configuration with unique string keys")
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
        self.0.charge(value.len())?;
        Ok(Unique(Value::String(value.into())))
    }
    fn visit_string<E: de::Error>(self, value: String) -> Result<Unique, E> {
        self.0.charge(value.len())?;
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
        while let Some(Unique(value)) = sequence.next_element_seed(self.0.child())? {
            values.push(value);
        }
        Ok(Unique(Value::Array(values)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut source: A) -> Result<Unique, A::Error> {
        let mut object = Map::new();
        while let Some(StringKey(key)) = source.next_key()? {
            if self.0.yaml {
                let remaining = self
                    .0
                    .nodes
                    .get()
                    .checked_sub(1)
                    .ok_or_else(|| <A::Error as de::Error>::custom("configuration node bound"))?;
                self.0.nodes.set(remaining);
            }
            self.0.charge::<A::Error>(key.len())?;
            if object.contains_key(&key) || self.0.yaml && key == "<<" {
                return Err(de::Error::custom("duplicate or merge object key"));
            }
            let Unique(value) = source.next_value_seed(self.0.child())?;
            object.insert(key, value);
        }
        Ok(Unique(Value::Object(object)))
    }
}

struct StringKey(String);
impl<'de> Deserialize<'de> for StringKey {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct KeyVisitor;
        impl Visitor<'_> for KeyVisitor {
            type Value = StringKey;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("string configuration key")
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<StringKey, E> {
                Ok(StringKey(value.into()))
            }
            fn visit_string<E: de::Error>(self, value: String) -> Result<StringKey, E> {
                Ok(StringKey(value))
            }
        }
        decoder.deserialize_any(KeyVisitor)
    }
}
