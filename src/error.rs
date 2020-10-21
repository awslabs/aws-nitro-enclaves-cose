//! COSE Operation errors and causes

use serde_cbor::Error as CborError;

#[derive(Debug)]
/// Aggregation of all error types returned by this library
pub enum COSEError {
    /// Signature could not be performed due to OpenSSL error.
    SignatureError(openssl::error::ErrorStack),
    /// This feature is not yet fully implemented according
    /// to the spec.
    UnimplementedError,
    /// This specific configuration is not supported, although
    /// the spec allows it.
    UnsupportedError(String),
    /// Could not verify signature.
    UnverifiedSignature,
    /// Deserialized structure does not respect the COSE specification.
    SpecificationError(String),
    /// Error while serializing or deserializing structures.
    SerializationError(CborError),
}
