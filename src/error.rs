//! COSE Operation errors and causes

use std::error::Error;
use std::fmt;

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

impl fmt::Display for COSEError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            COSEError::SignatureError(e) => write!(f, "Signature error: {}", e),
            COSEError::UnimplementedError => write!(f, "Not implemented"),
            COSEError::UnsupportedError(e) => write!(f, "Not supported: {}", e),
            COSEError::UnverifiedSignature => write!(f, "Unverified signature"),
            COSEError::SpecificationError(e) => write!(f, "Specification error: {}", e),
            COSEError::SerializationError(e) => write!(f, "Serialization error: {}", e),
        }
    }
}

impl Error for COSEError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            COSEError::SignatureError(e) => Some(e),
            COSEError::SerializationError(e) => Some(e),
            _ => None,
        }
    }
}
