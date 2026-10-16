//! Canonical CBOR, the way every record and every piece of associated data is
//! encoded. Canonical means: definite lengths, shortest integers, no floats,
//! and map keys sorted by their encoded bytes (shortest first, then bytewise;
//! RFC 8949 §4.2.1). Two writers that agree on the content produce the same
//! bytes, so signatures and hashes are stable.

use ciborium::Value;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::{Error, Result};

/// Unknown fields a record carried when it was read. They are written back
/// untouched, so a newer app's additions survive an older app's rewrite.
pub type Extra = std::collections::BTreeMap<String, Value>;

/// Encodes a value as canonical CBOR.
pub fn to_canonical<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>> {
    let value = Value::serialized(value).map_err(|e| Error::Encode(e.to_string()))?;
    let value = canonicalize(value)?;
    let mut out = Vec::new();
    ciborium::into_writer(&value, &mut out).map_err(|e| Error::Encode(e.to_string()))?;
    Ok(out)
}

/// Decodes a value from CBOR (canonical or not: readers are lenient).
pub fn from_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    ciborium::from_reader(bytes).map_err(|e| Error::Decode(e.to_string()))
}

fn canonicalize(value: Value) -> Result<Value> {
    Ok(match value {
        Value::Map(entries) => {
            let mut keyed = Vec::with_capacity(entries.len());
            for (k, v) in entries {
                let k = canonicalize(k)?;
                let mut kb = Vec::new();
                ciborium::into_writer(&k, &mut kb).map_err(|e| Error::Encode(e.to_string()))?;
                keyed.push((kb, k, canonicalize(v)?));
            }
            keyed.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then_with(|| a.0.cmp(&b.0)));
            if keyed.windows(2).any(|w| w[0].0 == w[1].0) {
                return Err(Error::Encode("a map has the same key twice".into()));
            }
            Value::Map(keyed.into_iter().map(|(_, k, v)| (k, v)).collect())
        }
        Value::Array(items) => {
            Value::Array(items.into_iter().map(canonicalize).collect::<Result<_>>()?)
        }
        Value::Tag(tag, inner) => Value::Tag(tag, Box::new(canonicalize(*inner)?)),
        Value::Float(_) => return Err(Error::Encode("records never hold floats".into())),
        other => other,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Rec {
        zeta: u32,
        #[serde(flatten)]
        extra: Extra,
        a: String,
    }

    #[test]
    fn keys_are_sorted_shortest_first_then_bytewise() {
        let mut extra = Extra::new();
        extra.insert("bb".into(), Value::Integer(1.into()));
        extra.insert("c".into(), Value::Integer(2.into()));
        let rec = Rec {
            zeta: 7,
            extra,
            a: "x".into(),
        };
        let bytes = to_canonical(&rec).unwrap();
        // a4 (map of 4): "a", "c", "bb", "zeta"
        assert_eq!(&bytes[..2], &[0xa4, 0x61]);
        assert_eq!(bytes[2], b'a');
        let back: Rec = from_slice(&bytes).unwrap();
        assert_eq!(back, rec);
        assert_eq!(
            to_canonical(&back).unwrap(),
            bytes,
            "stable across a round trip"
        );
    }
}
