//! Lossless HTTP record framing shared by push and pull ingestion.
//!
//! Array brackets, commas and whitespace outside a JSON value belong to the batch
//! envelope. Inside each value, spelling, escapes, key order and whitespace remain
//! unchanged. Line frames retain their LF/CRLF terminator and surrounding spaces;
//! whitespace-only lines are framing and are ignored.

use serde_json::value::RawValue;

/// Decode JSON string elements only for transports whose existing contract sends
/// their contents (for example syslog inside a webhook JSON string array).
#[derive(Debug, Clone, Copy)]
pub enum ArrayStrings {
    /// Keep the JSON string's original quotes and escapes.
    Preserve,
    /// Decode the JSON string envelope into its original content.
    Decode,
}

/// Split a valid JSON array without reserializing its values.
#[must_use]
pub fn json_array_records(body: &[u8], strings: ArrayStrings) -> Option<Vec<Vec<u8>>> {
    let text = std::str::from_utf8(body).ok()?;
    let values: Vec<&RawValue> = serde_json::from_str(text.trim()).ok()?;
    Some(
        values
            .into_iter()
            .map(|value| {
                let raw = value.get();
                if matches!(strings, ArrayStrings::Decode) && raw.starts_with('"') {
                    if let Ok(decoded) = serde_json::from_str::<String>(raw) {
                        return decoded.into_bytes();
                    }
                }
                raw.as_bytes().to_vec()
            })
            .collect(),
    )
}

/// Yield nonblank line frames without modifying any byte inside a frame.
pub fn line_records(body: &[u8]) -> impl Iterator<Item = &[u8]> {
    body.split_inclusive(|byte| *byte == b'\n').filter(|line| !String::from_utf8_lossy(line).trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn array_values_retain_lexical_bytes_and_only_drop_the_batch_envelope() {
        let body = br#" [ { "z":1e+02, "a":"\u0061", "z": 2 }, 1.00, [ true, null ] ] "#;
        let records = json_array_records(body, ArrayStrings::Preserve).unwrap_or_default();
        assert_eq!(
            records,
            [br#"{ "z":1e+02, "a":"\u0061", "z": 2 }"#.to_vec(), b"1.00".to_vec(), b"[ true, null ]".to_vec(),]
        );
    }

    #[test]
    fn webhook_string_envelopes_keep_the_existing_decoding_contract() {
        let body = br#"["  <34>line\r\n", "\u0061"]"#;
        assert_eq!(
            json_array_records(body, ArrayStrings::Decode).unwrap_or_default(),
            [b"  <34>line\r\n".to_vec(), b"a".to_vec(),]
        );
        assert_eq!(json_array_records(body, ArrayStrings::Preserve).unwrap_or_default()[1], br#""\u0061""#);
    }

    #[test]
    fn line_frames_keep_spaces_tabs_and_crlf_while_ignoring_blank_lines() {
        let body = b"\r\n \t{\"a\":1} \t\r\n  {\"b\":2}  \n\t\r\nlast ";
        assert_eq!(
            line_records(body).collect::<Vec<_>>(),
            [b" \t{\"a\":1} \t\r\n".as_slice(), b"  {\"b\":2}  \n", b"last ",]
        );
    }

    #[test]
    fn line_framing_does_not_replace_non_utf8_bytes() {
        assert_eq!(line_records(b" \xff\r\n").collect::<Vec<_>>(), [b" \xff\r\n".as_slice()]);
    }
}
