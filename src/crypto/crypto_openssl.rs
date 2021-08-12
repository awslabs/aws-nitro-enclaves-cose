//! OpenSSL crypto implementation

use openssl::{hash::MessageDigest, symm::Cipher};

use crate::{crypto::HashFunction, encrypt::COSEAlgorithm};

/// The type of errors reported
pub type CryptoError = openssl::error::ErrorStack;

/// Compute a message digest (hash), given a hash function and data
pub fn hash(hf: HashFunction, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    openssl::hash::hash(hf.into(), data).map(|x| x.to_vec())
}

/// Convert a value from the internal HashFunction to openssl MessageDigest
impl From<HashFunction> for MessageDigest {
    fn from(hf: HashFunction) -> openssl::hash::MessageDigest {
        match hf {
            HashFunction::Sha256 => MessageDigest::sha256(),
            HashFunction::Sha384 => MessageDigest::sha384(),
            HashFunction::Sha512 => MessageDigest::sha512(),
        }
    }
}

impl From<COSEAlgorithm> for Cipher {
    fn from(cc: COSEAlgorithm) -> Cipher {
        match cc {
            COSEAlgorithm::AesGcm96_128_128 => Cipher::aes_128_gcm(),
            COSEAlgorithm::AesGcm96_128_192 => Cipher::aes_192_gcm(),
            COSEAlgorithm::AesGcm96_128_256 => Cipher::aes_256_gcm(),
        }
    }
}

impl COSEAlgorithm {
    pub(crate) fn encrypt(
        &self,
        key: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Option<Vec<u8>>), CryptoError> {
        let cipher = Cipher::from(*self);

        let mut iv = vec![0; cipher.iv_len().unwrap()];
        openssl::rand::rand_bytes(&mut iv)?;

        let mut tag = vec![0; self.tag_size()];
        let mut ciphertext =
            openssl::symm::encrypt_aead(cipher, key, Some(&iv[..]), aad, plaintext, &mut tag)?;

        ciphertext.append(&mut tag);

        Ok((ciphertext, Some(iv)))
    }

    pub(crate) fn decrypt(
        &self,
        key: &[u8],
        aad: &[u8],
        iv: Option<&[u8]>,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let cipher = Cipher::from(*self);

        let (ciphertext, tag) = ciphertext.split_at(ciphertext.len() - self.tag_size());

        let plaintext = openssl::symm::decrypt_aead(cipher, key, iv, aad, ciphertext, tag)?;

        Ok(plaintext)
    }
}
