//! COSE HeaderMap

use ciborium::value::{CanonicalValue, Value};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::error::CoseError;

/// Re-export of `ciborium::value::Value` for use in header map keys and values.
pub use ciborium::value::Value as CborValue;

/// Re-export of `ciborium::value::Integer` for constructing `CborValue::Integer` variants.
pub use ciborium::value::Integer as CborInteger;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
/// Implementation of header_map, with CborValue keys and CborValue values.
pub struct HeaderMap(
    #[serde(deserialize_with = "::serde_with::rust::maps_duplicate_key_is_error::deserialize")]
    BTreeMap<CanonicalValue, Value>,
);

impl HeaderMap {
    /// Creates an empty HeaderMap
    pub fn new() -> Self {
        HeaderMap(BTreeMap::new())
    }

    /// Inserts an element into HeaderMap. Both key and value are CborValue.
    /// If key already has a value, that value is returned.
    pub fn insert(&mut self, key: CborValue, value: CborValue) -> Option<CborValue> {
        self.0.insert(CanonicalValue::from(key), value)
    }

    /// Returns the element at key.
    pub fn get(&self, key: &CborValue) -> Option<&CborValue> {
        // CanonicalValue does not implement Borrow<Value>, so we must clone the key on every lookup.
        self.0.get(&CanonicalValue::from(key.clone()))
    }

    /// Returns true if HeaderMap has no elements, false otherwise.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Parses a slice of bytes into a HeaderMap, if possible.
    pub fn from_bytes(header_map: &[u8]) -> Result<Self, CoseError> {
        crate::cbor::from_slice(header_map)
    }
}

/// Validates that a byte slice deserializes as a well-formed CBOR header map.
pub(crate) fn validate_protected_bytes(bytes: &[u8]) -> Result<(), CoseError> {
    crate::cbor::from_slice::<HeaderMap>(bytes).map(|_| ())
}

pub(crate) fn map_to_empty_or_serialized(map: &HeaderMap) -> Result<Vec<u8>, CoseError> {
    if map.is_empty() {
        Ok(vec![])
    } else {
        crate::cbor::to_vec(map)
    }
}
