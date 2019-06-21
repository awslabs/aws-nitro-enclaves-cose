use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use serde_cbor::Value as CborValue;
use serde_cbor::Error as CborError;
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::collections::BTreeMap;

pub type HeaderMap = BTreeMap<CborValue, CborValue>;

/// Values from https://tools.ietf.org/html/rfc8152#section-8.1
#[derive(Debug, Copy, Clone, Serialize_repr, Deserialize_repr)]
#[repr(i8)]
pub enum SignatureAlgorithm {
    ES256 = -7,  //  ECDSA w/ SHA-256
    ES384 = -35, //  ECDSA w/ SHA-384
    ES512 = -36, // ECDSA w/ SHA-512
}

impl Into<HeaderMap> for SignatureAlgorithm {
    fn into(self) -> HeaderMap {
        // Convenience method for creating the map that would go into the signature structures
        // Can be appended into a larger HeaderMap
        // `1` is the index defined in the spec for Algorithm
        let mut map = HeaderMap::new();
        map.insert(1.into(), (self as i8).into());
        map
    }
}

///  https://tools.ietf.org/html/rfc8152#section-4.4
///
///  In order to create a signature, a well-defined byte stream is needed.
///  The Sig_structure is used to create the canonical form.  This signing
///  and verification process takes in the body information (COSE_Sign or
///  COSE_Sign1), the signer information (COSE_Signature), and the
///  application data (external source).  A Sig_structure is a CBOR array.
///  The fields of the Sig_structure in order are:
///
///  1.  A text string identifying the context of the signature.  The
///      context string is:
///
///         "Signature" for signatures using the COSE_Signature structure.
///
///         "Signature1" for signatures using the COSE_Sign1 structure.
///
///         "CounterSignature" for signatures used as counter signature
///         attributes.
///
///  2.  The protected attributes from the body structure encoded in a
///      bstr type.  If there are no protected attributes, a bstr of
///      length zero is used.
///
///  3.  The protected attributes from the signer structure encoded in a
///      bstr type.  If there are no protected attributes, a bstr of
///      length zero is used.  This field is omitted for the COSE_Sign1
///      signature structure.
///
///  4.  The protected attributes from the application encoded in a bstr
///      type.  If this field is not supplied, it defaults to a zero-
///      length binary string.  (See Section 4.3 for application guidance
///      on constructing this field.)
///
///  5.  The payload to be signed encoded in a bstr type.  The payload is
///      placed here independent of how it is transported.
///
///  Note: A struct serializes to a map, while a tuple serializes to an array,
///  which is why this struct is actually a tuple
///  Note: This structure only needs to be serializable, since it's
///  used for generating a signature and not transported anywhere. Both
///  sides need to generate it independently.
#[derive(Debug, Clone, Serialize)]
pub struct SigStructure(
    /// context: "Signature" / "Signature1" / "CounterSignature"
    String,
    /// body_protected : empty_or_serialized_map,
    ByteBuf,
    /// ? sign_protected : empty_or_serialized_map,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    Option<ByteBuf>,
    /// external_aad : bstr,
    ByteBuf,
    /// payload : bstr
    ByteBuf,
);

fn map_to_empty_or_serialized(map: &HeaderMap) -> Result<Vec<u8>, CborError> {
    if map.is_empty() {
        Ok(vec![])
    } else {
        Ok(serde_cbor::to_vec(map)?)
    }
}

impl SigStructure {
    /// Takes the protected field of the COSE_Sign object and a raw slice of bytes as payload and creates a
    /// SigStructure for one signer from it
    pub fn new_sign1(body_protected: &[u8], payload: &[u8]) -> Result<Self, CborError> {
        Ok(SigStructure(
            String::from("Signature1"),
            ByteBuf::from(body_protected.to_vec()),
            None,
            ByteBuf::new(),
            ByteBuf::from(payload.to_vec()),
        ))
    }

    /// Takes the protected field of the COSE_Sign object and a CborValue as payload and creates a
    /// SigStructure for one signer from it
    pub fn new_sign1_cbor_value(
        body_protected: &[u8],
        payload: &CborValue,
    ) -> Result<Self, CborError> {
        Self::new_sign1(body_protected, &serde_cbor::to_vec(payload)?)
    }

    /// Serializes the SigStructure to . We don't care about deserialization, since
    /// both sides are supposed to compute the SigStructure and compare.
    pub fn as_bytes(&self) -> Result<Vec<u8>, CborError> {
        serde_cbor::to_vec(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Public domain work: Pride and Prejudice by Jane Austen, taken from https://www.gutenberg.org/files/1342/1342.txt
    const TEXT: &[u8] = b"It is a truth universally acknowledged, that a single man in possession of a good fortune, must be in want of a wife.";

    #[test]
    fn map_serialization() {
        // Empty map
        let map: HeaderMap = HeaderMap::new();
        assert_eq!(map_to_empty_or_serialized(&map).unwrap(), []);

        // Checks that the body_protected field will be serialized correctly
        let map: HeaderMap = SignatureAlgorithm::ES256.into();
        assert_eq!(
            map_to_empty_or_serialized(&map).unwrap(),
            [0xa1, 0x01, 0x26]
        );

        let map: HeaderMap = SignatureAlgorithm::ES384.into();
        assert_eq!(
            map_to_empty_or_serialized(&map).unwrap(),
            [0xa1, 0x01, 0x38, 0x22]
        );

        let map: HeaderMap = SignatureAlgorithm::ES512.into();
        assert_eq!(
            map_to_empty_or_serialized(&map).unwrap(),
            [0xa1, 0x01, 0x38, 0x23]
        );
    }

    #[test]
    fn sig_structure_text() {
        let map = HeaderMap::new();

        let map_serialized = map_to_empty_or_serialized(&map).unwrap();
        let sig_structure = SigStructure::new_sign1(&map_serialized, TEXT).unwrap();

        assert_eq!(
            vec![
                0x84, /* "Signature1" */
                0x6A, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31,
                /* protected: */
                0x40, /* unprotected: */
                0x40, /* payload: */
                0x58, 0x75, 0x49, 0x74, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74, 0x72, 0x75, 0x74,
                0x68, 0x20, 0x75, 0x6E, 0x69, 0x76, 0x65, 0x72, 0x73, 0x61, 0x6C, 0x6C, 0x79, 0x20,
                0x61, 0x63, 0x6B, 0x6E, 0x6F, 0x77, 0x6C, 0x65, 0x64, 0x67, 0x65, 0x64, 0x2C, 0x20,
                0x74, 0x68, 0x61, 0x74, 0x20, 0x61, 0x20, 0x73, 0x69, 0x6E, 0x67, 0x6C, 0x65, 0x20,
                0x6D, 0x61, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x70, 0x6F, 0x73, 0x73, 0x65, 0x73, 0x73,
                0x69, 0x6F, 0x6E, 0x20, 0x6F, 0x66, 0x20, 0x61, 0x20, 0x67, 0x6F, 0x6F, 0x64, 0x20,
                0x66, 0x6F, 0x72, 0x74, 0x75, 0x6E, 0x65, 0x2C, 0x20, 0x6D, 0x75, 0x73, 0x74, 0x20,
                0x62, 0x65, 0x20, 0x69, 0x6E, 0x20, 0x77, 0x61, 0x6E, 0x74, 0x20, 0x6F, 0x66, 0x20,
                0x61, 0x20, 0x77, 0x69, 0x66, 0x65, 0x2E,
            ],
            sig_structure.as_bytes().unwrap()
        );

        let map: HeaderMap = SignatureAlgorithm::ES256.into();
        let map_serialized = map_to_empty_or_serialized(&map).unwrap();
        let sig_structure = SigStructure::new_sign1(&map_serialized, TEXT).unwrap();
        assert_eq!(
            vec![
                0x84, /* "Signature1" */
                0x6A, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31,
                /* protected: */
                0x43, 0xA1, 0x01, 0x26, /* unprotected: */
                0x40, /* payload: */
                0x58, 0x75, 0x49, 0x74, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74, 0x72, 0x75, 0x74,
                0x68, 0x20, 0x75, 0x6E, 0x69, 0x76, 0x65, 0x72, 0x73, 0x61, 0x6C, 0x6C, 0x79, 0x20,
                0x61, 0x63, 0x6B, 0x6E, 0x6F, 0x77, 0x6C, 0x65, 0x64, 0x67, 0x65, 0x64, 0x2C, 0x20,
                0x74, 0x68, 0x61, 0x74, 0x20, 0x61, 0x20, 0x73, 0x69, 0x6E, 0x67, 0x6C, 0x65, 0x20,
                0x6D, 0x61, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x70, 0x6F, 0x73, 0x73, 0x65, 0x73, 0x73,
                0x69, 0x6F, 0x6E, 0x20, 0x6F, 0x66, 0x20, 0x61, 0x20, 0x67, 0x6F, 0x6F, 0x64, 0x20,
                0x66, 0x6F, 0x72, 0x74, 0x75, 0x6E, 0x65, 0x2C, 0x20, 0x6D, 0x75, 0x73, 0x74, 0x20,
                0x62, 0x65, 0x20, 0x69, 0x6E, 0x20, 0x77, 0x61, 0x6E, 0x74, 0x20, 0x6F, 0x66, 0x20,
                0x61, 0x20, 0x77, 0x69, 0x66, 0x65, 0x2E,
            ],
            sig_structure.as_bytes().unwrap()
        );
    }
}
