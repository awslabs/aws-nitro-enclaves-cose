//! (Signing) cryptography abstraction

use crate::encrypt::COSEAlgorithm;
use crate::{error::CoseError, sign::SignatureAlgorithm};
use ::openssl::nid::Nid;
use ::openssl::symm::Cipher;

mod openssl;
pub use self::openssl::OpenSSL;

#[cfg(feature = "key_openssl_pkey")]
mod openssl_pkey;
#[cfg(feature = "key_tpm")]
pub mod tpm;

/// A trait exposing various aead encryption algorithms.
pub trait Encryption {
    /// Fill the provided `buff` with cryptographic random values.
    fn rand_bytes(buff: &mut [u8]) -> Result<(), CoseError>;

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

impl From<COSEAlgorithm> for EncryptionAlgorithm {
    fn from(algo: COSEAlgorithm) -> EncryptionAlgorithm {
        match algo {
            COSEAlgorithm::AesGcm96_128_128 => EncryptionAlgorithm::Aes128Gcm,
            COSEAlgorithm::AesGcm96_128_192 => EncryptionAlgorithm::Aes192Gcm,
            COSEAlgorithm::AesGcm96_128_256 => EncryptionAlgorithm::Aes256Gcm,
        }
    }
}

impl From<EncryptionAlgorithm> for Cipher {
    fn from(algo: EncryptionAlgorithm) -> Cipher {
        match algo {
            EncryptionAlgorithm::Aes128Gcm => Cipher::aes_128_gcm(),
            EncryptionAlgorithm::Aes192Gcm => Cipher::aes_192_gcm(),
            EncryptionAlgorithm::Aes256Gcm => Cipher::aes_256_gcm(),
        }
    }
}

/// A trait exposing various aead decryption algorithms.
pub trait Decryption {
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
pub enum MessageDigest {
    /// 256-bit Secure Hash Algorithm
    Sha256,
    /// 384-bit Secure Hash Algorithm
    Sha384,
    /// 512-bit Secure Hash Algorithm
    Sha512,
}

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
pub trait Hash {
    /// Computes the hash of the `data` with provided hash function
    fn hash(digest: MessageDigest, data: &[u8]) -> Result<Vec<u8>, CoseError>;
}

/// A public key that can verify an existing signature
pub trait SigningPublicKey {
    /// This returns the signature algorithm and message digest to be used for this
    /// public key.
    fn get_parameters(&self) -> Result<(SignatureAlgorithm, MessageDigest), CoseError>;

    /// Given a digest and a signature, returns a boolean whether the signature
    /// was valid.
    fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<bool, CoseError>;
}

/// Follows the recommandations put in place by the RFC and doesn't deal with potential
/// mismatches: https://tools.ietf.org/html/rfc8152#section-8.1.
pub fn ec_curve_to_parameters(
    curve_name: Nid,
) -> Result<(SignatureAlgorithm, MessageDigest, usize), CoseError> {
    let sig_alg = match curve_name {
        // Recommended to use with SHA256
        Nid::X9_62_PRIME256V1 => SignatureAlgorithm::ES256,
        // Recommended to use with SHA384
        Nid::SECP384R1 => SignatureAlgorithm::ES384,
        // Recommended to use with SHA512
        Nid::SECP521R1 => SignatureAlgorithm::ES512,
        _ => {
            return Err(CoseError::UnsupportedError(format!(
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

fn merge_ec_signature(bytes_r: &[u8], bytes_s: &[u8], key_length: usize) -> Vec<u8> {
    assert!(bytes_r.len() <= key_length);
    assert!(bytes_s.len() <= key_length);

    let mut signature_bytes = vec![0u8; key_length * 2];

    // This is big-endian encoding so padding might be added at the start if the factor is
    // too short.
    let offset_copy = key_length - bytes_r.len();
    signature_bytes[offset_copy..offset_copy + bytes_r.len()].copy_from_slice(bytes_r);

    // This is big-endian encoding so padding might be added at the start if the factor is
    // too short.
    let offset_copy = key_length - bytes_s.len() + key_length;
    signature_bytes[offset_copy..offset_copy + bytes_s.len()].copy_from_slice(bytes_s);

    signature_bytes
}

/// A private key that can produce new signatures
pub trait SigningPrivateKey: SigningPublicKey {
    /// Given a digest, returns a signature
    fn sign(&self, digest: &[u8]) -> Result<Vec<u8>, CoseError>;
}
