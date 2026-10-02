use crate::error::CoseError;
use ciborium::Value;
use serde::de::{self, DeserializeOwned, SeqAccess};
use serde::Serialize;

/// Deserializes exactly one CBOR item. Trailing bytes are an error.
pub(crate) fn from_slice<T: DeserializeOwned>(mut bytes: &[u8]) -> Result<T, CoseError> {
    let value = ciborium::de::from_reader(&mut bytes)
        .map_err(|e| CoseError::SerializationError(Box::new(e)))?;
    if !bytes.is_empty() {
        return Err(CoseError::SerializationError(
            format!("{} trailing byte(s) after CBOR item", bytes.len()).into(),
        ));
    }
    Ok(value)
}

/// Deserializes exactly one untagged CBOR item.
pub(crate) fn from_slice_untagged<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CoseError> {
    let value: Value = from_slice(bytes)?;
    untagged(value, "item").map_err(|e| CoseError::SerializationError(e.into()))
}

fn untagged<T: DeserializeOwned>(value: Value, what: &str) -> Result<T, String> {
    if let Value::Tag(tag, _) = value {
        return Err(format!("unexpected tag {tag} on {what}"));
    }
    value.deserialized().map_err(|e| match e {
        ciborium::value::Error::Custom(s) => s,
    })
}

pub(crate) fn to_vec<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, CoseError> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf)
        .map_err(|e| CoseError::SerializationError(Box::new(e)))?;
    Ok(buf)
}

/// Reads the next sequence element and rejects it if it carries a CBOR tag.
///
/// ciborium's typed deserializers skip tags silently, which serde_cbor did
/// not; COSE fields are untagged, so a tag is a malformed message.
pub(crate) fn next_untagged<'de, A, T>(seq: &mut A, field: &'static str) -> Result<T, A::Error>
where
    A: SeqAccess<'de>,
    T: DeserializeOwned,
{
    let value: Value = match seq.next_element()? {
        Some(v) => v,
        None => return Err(de::Error::missing_field(field)),
    };
    untagged(value, field).map_err(de::Error::custom)
}
