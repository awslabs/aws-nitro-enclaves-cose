//! COSE Operation errors and causes

use std::error::Error;
use std::fmt;

use serde_cbor::Error as CborError;

#[derive(Debug)]
/// Aggregation of all error types returned by this library
pub enum CoseError {
    /// Failed to generate random bytes
    EntropyError(Box<dyn Error>),
    /// Computation of a cryptographic hash failed
    HashingError(Box<dyn Error>),
    /// Signature could not be performed due to OpenSSL error.
    SignatureError(Box<dyn Error>),
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
    /// Tag is missing or incorrect.
    TagError(Option<u64>),
    /// Encryption could not be performed due to OpenSSL error.
    EncryptionError(Box<dyn Error>),
    /// TPM error occured
    #[cfg(feature = "key_tpm")]
    TpmError(tss_esapi::Error),
    /// AWS sign error occured
    #[cfg(feature = "key_kms")]
    AwsSignError(aws_sdk_kms::types::SdkError<aws_sdk_kms::error::SignError>),
    /// AWS verify error occured
    #[cfg(feature = "key_kms")]
    AwsVerifyError(aws_sdk_kms::types::SdkError<aws_sdk_kms::error::VerifyError>),
    /// AWS GetPublicKey error occured
    #[cfg(all(feature = "key_kms", feature = "key_openssl_pkey"))]
    AwsGetPublicKeyError(aws_sdk_kms::types::SdkError<aws_sdk_kms::error::GetPublicKeyError>),
}

impl fmt::Display for CoseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoseError::EntropyError(e) => write!(f, "Entropy error: {}", e),
            CoseError::HashingError(e) => write!(f, "Hashing failed: {}", e),
            CoseError::SignatureError(e) => write!(f, "Signature error: {}", e),
            CoseError::UnimplementedError => write!(f, "Not implemented"),
            CoseError::UnsupportedError(e) => write!(f, "Not supported: {}", e),
            CoseError::UnverifiedSignature => write!(f, "Unverified signature"),
            CoseError::SpecificationError(e) => write!(f, "Specification error: {}", e),
            CoseError::SerializationError(e) => write!(f, "Serialization error: {}", e),
            CoseError::TagError(Some(tag)) => write!(f, "Tag {} was not expected", tag),
            CoseError::TagError(None) => write!(f, "Expected tag is missing"),
            CoseError::EncryptionError(e) => write!(f, "Encryption error: {}", e),
            #[cfg(feature = "key_tpm")]
            CoseError::TpmError(e) => write!(f, "TPM error: {}", e),
            #[cfg(feature = "key_kms")]
            CoseError::AwsSignError(e) => write!(f, "AWS sign error: {}", e),
            #[cfg(feature = "key_kms")]
            CoseError::AwsVerifyError(e) => write!(f, "AWS verify error: {}", e),
            #[cfg(all(feature = "key_kms", feature = "key_openssl_pkey"))]
            CoseError::AwsGetPublicKeyError(e) => write!(f, "AWS GetPublicKey error: {}", e),
        }
    }
}

impl Error for CoseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            CoseError::SignatureError(e) => e.source(),
            CoseError::SerializationError(e) => Some(e),
            _ => None,
        }
    }
}
