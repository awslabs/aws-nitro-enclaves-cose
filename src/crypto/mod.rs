//! (Signing) cryptography abstraction

use openssl::{hash::MessageDigest, nid::Nid};

use crate::{error::COSEError, sign::SignatureAlgorithm};

#[cfg(feature = "key_openssl_pkey")]
mod openssl_pkey;

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
    match curve_name {
        // Recommended to use with SHA256
        Nid::X9_62_PRIME256V1 => Ok((SignatureAlgorithm::ES256, MessageDigest::sha256(), 32)),
        // Recommended to use with SHA384
        Nid::SECP384R1 => Ok((SignatureAlgorithm::ES384, MessageDigest::sha384(), 48)),
        // Recommended to use with SHA512
        Nid::SECP521R1 => Ok((
            SignatureAlgorithm::ES512,
            MessageDigest::sha512(),
            66, /* Not a typo */
        )),
        _ => Err(COSEError::UnsupportedError(format!(
            "Curve name {:?} is not supported",
            curve_name
        ))),
    }
}

/// A private key that can produce new signatures
pub trait SigningPrivateKey: SigningPublicKey {
    /// Given a slice of data, returns a signature
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, COSEError>;
}
