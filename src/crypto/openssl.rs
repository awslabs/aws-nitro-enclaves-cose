use super::{Decryption, Encryption, EncryptionAlgorithm, Entropy, Hash, MessageDigest};
use crate::error::CoseError;
use openssl::symm::Cipher;

/// Type that implements various cryptographic traits using the OpenSSL library
pub struct Openssl;

impl Entropy for Openssl {
    fn rand_bytes(buff: &mut [u8]) -> Result<(), CoseError> {
        openssl::rand::rand_bytes(buff).map_err(|e| CoseError::EntropyError(Box::new(e)))
    }
}

impl Encryption for Openssl {
    /// Like `encrypt`, but for AEAD ciphers such as AES GCM.
    ///
    /// Additional Authenticated Data can be provided in the `aad` field, and the authentication tag
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
    ) -> Result<Vec<u8>, CoseError> {
        let cipher = match algo {
            EncryptionAlgorithm::Aes128Gcm => Cipher::aes_128_gcm(),
            EncryptionAlgorithm::Aes192Gcm => Cipher::aes_192_gcm(),
            EncryptionAlgorithm::Aes256Gcm => Cipher::aes_256_gcm(),
        };
        openssl::symm::encrypt_aead(cipher, key, iv, aad, data, tag)
            .map_err(|e| CoseError::EncryptionError(Box::new(e)))
    }
}

impl Decryption for Openssl {
    /// Like `decrypt`, but for AEAD ciphers such as AES GCM.
    ///
    /// Additional Authenticated Data can be provided in the `aad` field, and the authentication tag
    /// should be provided in the `tag` field.
    fn decrypt_aead(
        algo: EncryptionAlgorithm,
        key: &[u8],
        iv: Option<&[u8]>,
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, CoseError> {
        let cipher: Cipher = algo.into();
        openssl::symm::decrypt_aead(cipher, key, iv, aad, ciphertext, tag)
            .map_err(|e| CoseError::EncryptionError(Box::new(e)))
    }
}

impl Hash for Openssl {
    fn hash(digest: MessageDigest, data: &[u8]) -> Result<Vec<u8>, CoseError> {
        openssl::hash::hash(digest.into(), data)
            .map_err(|e| CoseError::HashingError(Box::new(e)))
            .map(|h| h.to_vec())
    }
}
