//! Ring crypto implementation

use crate::{crypto::HashFunction, encrypt::COSEAlgorithm};

use ring::{
    aead::{LessSafeKey, UnboundKey},
    rand::SecureRandom,
};

/// The type of errors reported
#[derive(Debug)]
pub enum CryptoError {
    /// An error returned by Ring
    RingError(ring::error::Unspecified),
    /// An unsupported cipher was used
    Unsupported(&'static str),
}

impl From<ring::error::Unspecified> for CryptoError {
    fn from(unspec: ring::error::Unspecified) -> Self {
        CryptoError::RingError(unspec)
    }
}

impl std::error::Error for CryptoError {}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            CryptoError::RingError(e) => e.fmt(f),
            CryptoError::Unsupported(s) => write!(f, "Unsupported algorithm: {}", s),
        }
    }
}

impl From<HashFunction> for &ring::digest::Algorithm {
    fn from(hf: HashFunction) -> &'static ring::digest::Algorithm {
        match hf {
            HashFunction::Sha256 => &ring::digest::SHA256,
            HashFunction::Sha384 => &ring::digest::SHA384,
            HashFunction::Sha512 => &ring::digest::SHA512,
        }
    }
}

/// Compute a message digest (hash), given a hash function and data
pub fn hash(hf: HashFunction, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    Ok(ring::digest::digest(hf.into(), data).as_ref().to_vec())
}

impl COSEAlgorithm {
    fn ring_algo(&self) -> Result<&'static ring::aead::Algorithm, CryptoError> {
        match self {
            COSEAlgorithm::AesGcm96_128_128 => Ok(&ring::aead::AES_128_GCM),
            COSEAlgorithm::AesGcm96_128_192 => Ok(&ring::aead::AES_256_GCM),
            COSEAlgorithm::AesGcm96_128_256 => Err(CryptoError::Unsupported("AES GCM 256")),
        }
    }

    pub(crate) fn encrypt(
        &self,
        key: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Option<Vec<u8>>), CryptoError> {
        let aad = ring::aead::Aad::from(aad);

        let rng = ring::rand::SystemRandom::new();
        let mut iv = vec![0; ring::aead::NONCE_LEN];
        rng.fill(&mut iv)?;
        let nonce = ring::aead::Nonce::try_assume_unique_for_key(&iv)?;

        let key = UnboundKey::new(self.ring_algo()?, key)?;
        let key = LessSafeKey::new(key);

        let mut inout = plaintext.to_vec();
        key.seal_in_place_append_tag(nonce, aad, &mut inout)?;

        Ok((inout, Some(iv)))
    }

    pub(crate) fn decrypt(
        &self,
        key: &[u8],
        aad: &[u8],
        iv: Option<&[u8]>,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let aad = ring::aead::Aad::from(aad);
        let nonce = match iv {
            Some(iv) => ring::aead::Nonce::try_assume_unique_for_key(&iv)?,
            None => return Err(CryptoError::Unsupported("Crypto without nonce")),
        };

        let key = UnboundKey::new(self.ring_algo()?, key)?;
        let key = LessSafeKey::new(key);

        let mut inout = ciphertext.to_vec();
        let plaintext = key.open_in_place(nonce, aad, &mut inout)?;

        Ok(plaintext.to_vec())
    }
}
