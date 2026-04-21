use super::{Decryption, Encryption, EncryptionAlgorithm, Entropy, Hash, MessageDigest};
use crate::crypto::{SignatureAlgorithm, SigningPrivateKey, SigningPublicKey};
use crate::error::CoseError;
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    ecdsa::EcdsaSig,
    nid::Nid,
    pkey::{PKey, Private, Public},
    symm::Cipher,
};

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
        let cipher = match algo {
            EncryptionAlgorithm::Aes128Gcm => Cipher::aes_128_gcm(),
            EncryptionAlgorithm::Aes192Gcm => Cipher::aes_192_gcm(),
            EncryptionAlgorithm::Aes256Gcm => Cipher::aes_256_gcm(),
        };
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

fn nid_for_algorithm(alg: SignatureAlgorithm) -> Nid {
    match alg {
        SignatureAlgorithm::ES256 => Nid::X9_62_PRIME256V1,
        SignatureAlgorithm::ES384 => Nid::SECP384R1,
        SignatureAlgorithm::ES512 => Nid::SECP521R1,
    }
}

/// Maps an EC curve NID to the corresponding COSE signature algorithm and parameters.
///
/// Follows the recommendations in RFC 8152 section 8.1.
pub(crate) fn ec_curve_to_parameters(
    curve_name: Nid,
) -> Result<(SignatureAlgorithm, MessageDigest, usize), CoseError> {
    let sig_alg = match curve_name {
        Nid::X9_62_PRIME256V1 => SignatureAlgorithm::ES256,
        Nid::SECP384R1 => SignatureAlgorithm::ES384,
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

/// An EC private key backed by OpenSSL
pub struct EcPrivateKey {
    inner: PKey<Private>,
}

/// An EC public key backed by OpenSSL
pub struct EcPublicKey {
    inner: PKey<Public>,
}

impl EcPrivateKey {
    /// Load from PKCS#8 DER-encoded private key bytes
    pub fn from_pkcs8(bytes: &[u8]) -> Result<Self, CoseError> {
        PKey::private_key_from_pkcs8(bytes)
            .map(|inner| EcPrivateKey { inner })
            .map_err(|e| CoseError::KeyDecodingError(Box::new(e)))
    }

    /// Load from PEM-encoded PKCS#8 private key
    #[cfg(feature = "pem")]
    pub fn from_pem(pem: &str) -> Result<Self, CoseError> {
        PKey::private_key_from_pem(pem.as_bytes())
            .map(|inner| EcPrivateKey { inner })
            .map_err(|e| CoseError::KeyDecodingError(Box::new(e)))
    }

    /// Extract the corresponding public key
    pub fn public_key(&self) -> Result<EcPublicKey, CoseError> {
        fn inner(pkey: &PKey<Private>) -> Result<EcPublicKey, openssl::error::ErrorStack> {
            let ec_key = pkey.ec_key()?;
            let ec_public = EcKey::from_public_key(ec_key.group(), ec_key.public_key())?;
            Ok(EcPublicKey { inner: PKey::from_ec_key(ec_public)? })
        }
        inner(&self.inner).map_err(|e| CoseError::KeyDecodingError(Box::new(e)))
    }

    /// Wrap a raw `PKey<Private>` without curve validation — only for tests exercising error paths
    #[cfg(test)]
    pub(crate) fn from_pkey_unchecked(pkey: PKey<Private>) -> Self {
        EcPrivateKey { inner: pkey }
    }

    /// Generate a fresh key pair for the given curve (test use only).
    #[cfg(test)]
    pub(crate) fn generate_test_keypair(curve: SignatureAlgorithm) -> Self {
        let group = EcGroup::from_curve_name(nid_for_algorithm(curve)).unwrap();
        let ec_key = EcKey::generate(&group).unwrap();
        EcPrivateKey {
            inner: PKey::from_ec_key(ec_key).unwrap(),
        }
    }
}

impl EcPublicKey {
    /// Build from SEC1 uncompressed point bytes (0x04 || x || y)
    pub fn from_sec1_bytes(curve: SignatureAlgorithm, bytes: &[u8]) -> Result<Self, CoseError> {
        fn inner(
            curve: SignatureAlgorithm,
            bytes: &[u8],
        ) -> Result<EcPublicKey, openssl::error::ErrorStack> {
            let group = EcGroup::from_curve_name(nid_for_algorithm(curve))?;
            let mut ctx = BigNumContext::new()?;
            let point = EcPoint::from_bytes(&group, bytes, &mut ctx)?;
            let ec_key = EcKey::from_public_key(&group, &point)?;
            Ok(EcPublicKey { inner: PKey::from_ec_key(ec_key)? })
        }
        inner(curve, bytes).map_err(|e| CoseError::KeyDecodingError(Box::new(e)))
    }

    /// Load from DER-encoded SubjectPublicKeyInfo (SPKI) bytes
    pub fn from_spki(bytes: &[u8]) -> Result<Self, CoseError> {
        PKey::public_key_from_der(bytes)
            .map(|inner| EcPublicKey { inner })
            .map_err(|e| CoseError::KeyDecodingError(Box::new(e)))
    }

    /// Load from PEM-encoded SubjectPublicKeyInfo public key
    #[cfg(feature = "pem")]
    pub fn from_pem(pem: &str) -> Result<Self, CoseError> {
        PKey::public_key_from_pem(pem.as_bytes())
            .map(|inner| EcPublicKey { inner })
            .map_err(|e| CoseError::KeyDecodingError(Box::new(e)))
    }
}

impl SigningPublicKey for EcPublicKey {
    fn get_parameters(&self) -> Result<(SignatureAlgorithm, MessageDigest), CoseError> {
        let curve_name = self
            .inner
            .ec_key()
            .map_err(|_| CoseError::UnsupportedError("Non-EC keys are not supported".to_string()))?
            .group()
            .curve_name()
            .ok_or_else(|| {
                CoseError::UnsupportedError("Anonymous EC keys are not supported".to_string())
            })?;
        let (sig_alg, digest, _) = ec_curve_to_parameters(curve_name)?;
        Ok((sig_alg, digest))
    }

    fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<bool, CoseError> {
        fn ecdsa_verify(
            bytes_r: &[u8],
            bytes_s: &[u8],
            digest: &[u8],
            key: &EcKey<Public>,
        ) -> Result<bool, openssl::error::ErrorStack> {
            let r = BigNum::from_slice(bytes_r)?;
            let s = BigNum::from_slice(bytes_s)?;
            EcdsaSig::from_private_components(r, s)?.verify(digest, key)
        }

        let key = self.inner.ec_key().map_err(|_| {
            CoseError::UnsupportedError("Non-EC keys are not yet supported".to_string())
        })?;
        let curve_name = key.group().curve_name().ok_or_else(|| {
            CoseError::UnsupportedError("Anonymous EC keys are not supported".to_string())
        })?;
        let (_, _, key_length) = ec_curve_to_parameters(curve_name)?;
        let (bytes_r, bytes_s) = signature.split_at(key_length);
        ecdsa_verify(bytes_r, bytes_s, digest, &key)
            .map_err(|e| CoseError::SignatureError(Box::new(e)))
    }
}

impl SigningPublicKey for EcPrivateKey {
    fn get_parameters(&self) -> Result<(SignatureAlgorithm, MessageDigest), CoseError> {
        let curve_name = self
            .inner
            .ec_key()
            .map_err(|_| CoseError::UnsupportedError("Non-EC keys are not supported".to_string()))?
            .group()
            .curve_name()
            .ok_or_else(|| {
                CoseError::UnsupportedError("Anonymous EC keys are not supported".to_string())
            })?;
        let (sig_alg, digest, _) = ec_curve_to_parameters(curve_name)?;
        Ok((sig_alg, digest))
    }

    fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<bool, CoseError> {
        self.public_key()?.verify(digest, signature)
    }
}

impl SigningPrivateKey for EcPrivateKey {
    fn sign(&self, digest: &[u8]) -> Result<Vec<u8>, CoseError> {
        let key = self.inner.ec_key().map_err(|_| {
            CoseError::UnsupportedError("Non-EC keys are not yet supported".to_string())
        })?;
        let curve_name = key.group().curve_name().ok_or_else(|| {
            CoseError::UnsupportedError("Anonymous EC keys are not supported".to_string())
        })?;
        let (_, _, key_length) = ec_curve_to_parameters(curve_name)?;
        // Signature = I2OSP(R, n) || I2OSP(S, n) per RFC 8017 section 4.1
        let signature =
            EcdsaSig::sign(digest, &key).map_err(|e| CoseError::SignatureError(Box::new(e)))?;
        let bytes_r = signature.r().to_vec();
        let bytes_s = signature.s().to_vec();
        Ok(crate::crypto::der_util::merge_ec_signature(&bytes_r, &bytes_s, key_length))
    }
}
