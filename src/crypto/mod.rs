//! (Signing) cryptography abstraction

use crate::encrypt::CoseAlgorithm;
use crate::error::CoseError;
use crate::header_map::HeaderMap;
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::str::FromStr;

pub(crate) mod der_util;

#[cfg(feature = "openssl")]
mod openssl;

#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
mod ring_like;

#[cfg(feature = "openssl")]
pub(crate) type ActiveBackend = self::openssl::Openssl;

#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
pub(crate) type ActiveBackend = self::ring_like::RingLike;

#[cfg(feature = "openssl")]
pub use self::openssl::{EcPrivateKey, EcPublicKey};

#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
pub use self::ring_like::{EcPrivateKey, EcPublicKey};

#[cfg(feature = "key_kms")]
pub mod kms;
#[cfg(feature = "key_tpm")]
pub mod tpm;

/// A trait exposing a source of entropy
pub(crate) trait Entropy {
    /// Fill the provided `buff` with cryptographic random values.
    fn rand_bytes(buff: &mut [u8]) -> Result<(), CoseError>;
}

/// A trait exposing various aead encryption algorithms.
pub(crate) trait Encryption {
    /// Encryption for AEAD ciphers such as AES GCM.
    ///
    /// Additional Authenticated Data (AEAD) can be provided in the `aad` field, and the authentication tag
    /// will be copied into the `tag` field.
    ///
    /// The size of the `tag` buffer indicates the required size of the tag. While some ciphers support
    /// a range of tag sizes, it is recommended to pick the maximum size. For AES GCM, this is 16 bytes,
    /// for example.
    fn encrypt_aead(
        algo: EncryptionAlgorithm,
        key: &[u8],
        iv: Option<&[u8]>,
        aad: &[u8],
        data: &[u8],
        tag: &mut [u8],
    ) -> Result<Vec<u8>, CoseError>;
}

/// Cryptographic algorithm that should be used with the `Encryption`/`Decryption` traits
pub enum EncryptionAlgorithm {
    /// 128-bit AES in Galois/Counter Mode
    Aes128Gcm,
    /// 192-bit AES in Galois/Counter Mode
    Aes192Gcm,
    /// 256-bit AES in Galois/Counter Mode
    Aes256Gcm,
}

impl From<CoseAlgorithm> for EncryptionAlgorithm {
    fn from(algo: CoseAlgorithm) -> EncryptionAlgorithm {
        match algo {
            CoseAlgorithm::AesGcm96_128_128 => EncryptionAlgorithm::Aes128Gcm,
            CoseAlgorithm::AesGcm96_128_192 => EncryptionAlgorithm::Aes192Gcm,
            CoseAlgorithm::AesGcm96_128_256 => EncryptionAlgorithm::Aes256Gcm,
        }
    }
}

/// A trait exposing various aead decryption algorithms.
pub(crate) trait Decryption {
    /// Like `decrypt`, but for AEAD ciphers such as AES GCM.
    ///
    /// Additional Authenticated Data can be provided in the `aad` field, and the authentication tag
    /// should be provided in the `tag` field.
    fn decrypt_aead(
        algo: EncryptionAlgorithm,
        key: &[u8],
        iv: Option<&[u8]>,
        aad: &[u8],
        data: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, CoseError>;
}

/// Cryptographic hash algorithms that can be used with the `Hash` trait
#[derive(Debug, Copy, Clone)]
pub enum MessageDigest {
    /// 256-bit Secure Hash Algorithm
    Sha256,
    /// 384-bit Secure Hash Algorithm
    Sha384,
    /// 512-bit Secure Hash Algorithm
    Sha512,
}

#[cfg(feature = "openssl")]
impl From<MessageDigest> for ::openssl::hash::MessageDigest {
    fn from(digest: MessageDigest) -> Self {
        match digest {
            MessageDigest::Sha256 => ::openssl::hash::MessageDigest::sha256(),
            MessageDigest::Sha384 => ::openssl::hash::MessageDigest::sha384(),
            MessageDigest::Sha512 => ::openssl::hash::MessageDigest::sha512(),
        }
    }
}

/// A trait exposing various cryptographic hash algorithms
#[allow(dead_code)]
pub(crate) trait Hash {
    /// Computes the hash of the `data` with provided hash function
    fn hash(digest: MessageDigest, data: &[u8]) -> Result<Vec<u8>, CoseError>;
}

/// A public key that can verify an existing signature
pub trait SigningPublicKey {
    /// This returns the signature algorithm and message digest to be used for this
    /// public key.
    fn get_parameters(&self) -> Result<(SignatureAlgorithm, MessageDigest), CoseError>;

    /// Returns true if this backend hashes the input internally.
    ///
    /// When true, callers must pass the raw pre-image bytes.  When false (the
    /// default), callers must pass a pre-computed digest produced by the
    /// algorithm returned from `get_parameters`.
    fn hashes_internally(&self) -> bool {
        false
    }

    /// Verify `signature` over `digest`.
    ///
    /// Unless `hashes_internally()` returns true, `digest` must be a
    /// pre-computed hash of the data to verify (e.g. the serialised
    /// `Sig_Structure`), produced with the algorithm from `get_parameters`.
    fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<bool, CoseError>;
}

/// A private key that can produce new signatures
pub trait SigningPrivateKey: SigningPublicKey {
    /// Sign `digest`.
    ///
    /// Unless `hashes_internally()` returns true, `digest` must be a
    /// pre-computed hash of the data to sign (e.g. the serialised
    /// `Sig_Structure`), produced with the algorithm from `get_parameters`.
    fn sign(&self, digest: &[u8]) -> Result<Vec<u8>, CoseError>;
}

/// Values from <https://tools.ietf.org/html/rfc8152#section-8.1>
#[derive(Debug, Copy, Clone, Serialize_repr, Deserialize_repr)]
#[repr(i8)]
pub enum SignatureAlgorithm {
    ///  ECDSA w/ SHA-256
    ES256 = -7,
    ///  ECDSA w/ SHA-384
    ES384 = -35,
    /// ECDSA w/ SHA-512
    ES512 = -36,
}

impl SignatureAlgorithm {
    /// Key length of the given signature algorithm
    pub fn key_length(&self) -> usize {
        match self {
            SignatureAlgorithm::ES256 => 32,
            SignatureAlgorithm::ES384 => 48,
            // Not a typo
            SignatureAlgorithm::ES512 => 66,
        }
    }

    /// Suggested cryptographic hash function given a signature algorithm
    pub fn suggested_message_digest(&self) -> MessageDigest {
        match self {
            SignatureAlgorithm::ES256 => MessageDigest::Sha256,
            SignatureAlgorithm::ES384 => MessageDigest::Sha384,
            SignatureAlgorithm::ES512 => MessageDigest::Sha512,
        }
    }
}

impl FromStr for SignatureAlgorithm {
    type Err = CoseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ES256" => Ok(SignatureAlgorithm::ES256),
            "ES384" => Ok(SignatureAlgorithm::ES384),
            "ES512" => Ok(SignatureAlgorithm::ES512),
            name => Err(CoseError::UnsupportedError(format!(
                "Algorithm '{}' is not supported",
                name
            ))),
        }
    }
}

impl std::fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let string_name = match self {
            SignatureAlgorithm::ES256 => "ES256",
            SignatureAlgorithm::ES384 => "ES384",
            SignatureAlgorithm::ES512 => "ES512",
        };
        write!(f, "{}", string_name)
    }
}

impl From<SignatureAlgorithm> for HeaderMap {
    fn from(sig_alg: SignatureAlgorithm) -> Self {
        // Convenience method for creating the map that would go into the signature structures
        // Can be appended into a larger HeaderMap
        // `1` is the index defined in the spec for Algorithm
        let mut map = HeaderMap::new();
        map.insert(1.into(), (sig_alg as i8).into());
        map
    }
}
