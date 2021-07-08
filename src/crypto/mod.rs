//! (Signing) cryptography abstraction

use openssl::{hash::MessageDigest, nid::Nid};

use crate::{error::COSEError, sign::SignatureAlgorithm};

#[cfg(feature = "key_kms")]
pub mod kms;
#[cfg(feature = "key_openssl_pkey")]
mod openssl_pkey;
#[cfg(feature = "key_tpm")]
pub mod tpm;

/// A public key that can verify an existing signature
pub trait SigningPublicKey {
    /// This returns the signature algorithm and message digest to be used for this
    /// public key.
    fn get_parameters(&self) -> Result<(SignatureAlgorithm, MessageDigest), COSEError>;

    /// Given a vector of data and a signature, returns a boolean whether the signature
    /// was valid.
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, COSEError>;
}

/// Follows the recommandations put in place by the RFC and doesn't deal with potential
/// mismatches: https://tools.ietf.org/html/rfc8152#section-8.1.
pub fn ec_curve_to_parameters(
    curve_name: Nid,
) -> Result<(SignatureAlgorithm, MessageDigest, usize), COSEError> {
    let sig_alg = match curve_name {
        // Recommended to use with SHA256
        Nid::X9_62_PRIME256V1 => SignatureAlgorithm::ES256,
        // Recommended to use with SHA384
        Nid::SECP384R1 => SignatureAlgorithm::ES384,
        // Recommended to use with SHA512
        Nid::SECP521R1 => SignatureAlgorithm::ES512,
        _ => {
            return Err(COSEError::UnsupportedError(format!(
                "Curve name {:?} is not supported",
                curve_name
            )))
        }
    };

    Ok((
        sig_alg,
        sig_alg.suggested_message_digest(),
        sig_alg.key_length(),
    ))
}

/// A private key that can produce new signatures
pub trait SigningPrivateKey: SigningPublicKey {
    /// Given a slice of data, returns a signature
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, COSEError>;
}
