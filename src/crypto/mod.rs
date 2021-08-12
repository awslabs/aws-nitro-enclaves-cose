//! Cryptography abstraction

use crate::{error::CoseError, sign::SignatureAlgorithm};

/// Message digest functions
#[derive(Debug, Copy, Clone)]
pub enum HashFunction {
    /// SHA256
    Sha256,
    /// SHA384
    Sha384,
    /// SHA512
    Sha512,
}

// Switch between the different crypto algorithms
#[cfg(feature = "crypto_openssl")]
mod crypto_openssl;
#[cfg(feature = "crypto_openssl")]
pub use crypto_openssl::*;

#[cfg(feature = "crypto_ring")]
mod crypto_ring;
#[cfg(feature = "crypto_ring")]
pub use crypto_ring::*;

#[cfg(not(any(feature = "crypto_openssl", feature = "crypto_ring")))]
compile_error!("Please enable a crypto implementation");

// Import the different shipped signing crypto
#[cfg(feature = "key_openssl_pkey")]
mod openssl_pkey;

/// A public key that can verify an existing signature
pub trait SigningPublicKey {
    /// This returns the signature algorithm and message digest to be used for this
    /// public key.
    fn get_parameters(&self) -> Result<(SignatureAlgorithm, HashFunction), CoseError>;

    /// Given a digest and a signature, returns a boolean whether the signature
    /// was valid.
    fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<bool, CoseError>;
}

/// A private key that can produce new signatures
pub trait SigningPrivateKey: SigningPublicKey {
    /// Given a digest, returns a signature
    fn sign(&self, digest: &[u8]) -> Result<Vec<u8>, CoseError>;
}
