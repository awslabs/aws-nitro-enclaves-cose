use super::{Decryption, Encryption, EncryptionAlgorithm, Entropy, Hash, MessageDigest};
use crate::crypto::{SignatureAlgorithm, SigningPrivateKey, SigningPublicKey};
use crate::error::CoseError;
use der::asn1::ObjectIdentifier;
use pkcs8::PrivateKeyInfo;
use spki::SubjectPublicKeyInfoRef;
use std::convert::TryFrom;

#[cfg(feature = "ring")]
use ring as backend;
#[cfg(feature = "aws-lc-rs")]
use aws_lc_rs as backend;

// Both ring and aws-lc-rs put `public_key()` behind the `KeyPair` trait.
use backend::signature::KeyPair;

/// Newtype that boxes opaque backend errors as `std::error::Error`.
///
/// `ring::error::Unspecified` is deliberately opaque and does not implement
/// `std::error::Error`, so we wrap it here.  `aws-lc-rs` does implement
/// `Error`, but the same wrapper is harmless.
#[derive(Debug)]
struct BackendError<E: std::fmt::Debug + Send + Sync + 'static>(E);

impl<E: std::fmt::Debug + Send + Sync + 'static> std::fmt::Display for BackendError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl<E: std::fmt::Debug + Send + Sync + 'static> std::error::Error for BackendError<E> {}

fn box_err<E: std::fmt::Debug + Send + Sync + 'static>(
    e: E,
) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(BackendError(e))
}

/// Type that implements various cryptographic traits using ring or aws-lc-rs
pub struct RingLike;

impl Entropy for RingLike {
    fn rand_bytes(buff: &mut [u8]) -> Result<(), CoseError> {
        use backend::rand::SecureRandom;
        let rng = backend::rand::SystemRandom::new();
        rng.fill(buff).map_err(|e| CoseError::EntropyError(box_err(e)))
    }
}

fn prepare_aead(
    algo: EncryptionAlgorithm,
    key: &[u8],
    iv: Option<&[u8]>,
) -> Result<(backend::aead::LessSafeKey, backend::aead::Nonce), CoseError> {
    let algorithm = match algo {
        EncryptionAlgorithm::Aes128Gcm => &backend::aead::AES_128_GCM,
        EncryptionAlgorithm::Aes192Gcm => {
            #[cfg(feature = "ring")]
            {
                return Err(CoseError::UnsupportedError(
                    "AES-192-GCM is not supported by ring; use aws-lc-rs".to_string(),
                ));
            }
            #[cfg(feature = "aws-lc-rs")]
            {
                &backend::aead::AES_192_GCM
            }
        }
        EncryptionAlgorithm::Aes256Gcm => &backend::aead::AES_256_GCM,
    };
    let iv = iv.ok_or_else(|| {
        CoseError::UnsupportedError("IV is required for AES-GCM".to_string())
    })?;
    let nonce = backend::aead::Nonce::try_assume_unique_for_key(iv)
        .map_err(|e| CoseError::EncryptionError(box_err(e)))?;
    let unbound = backend::aead::UnboundKey::new(algorithm, key)
        .map_err(|e| CoseError::EncryptionError(box_err(e)))?;
    Ok((backend::aead::LessSafeKey::new(unbound), nonce))
}

impl Encryption for RingLike {
    fn encrypt_aead(
        algo: EncryptionAlgorithm,
        key: &[u8],
        iv: Option<&[u8]>,
        aad: &[u8],
        data: &[u8],
        tag: &mut [u8],
    ) -> Result<Vec<u8>, CoseError> {
        let (lsk, nonce) = prepare_aead(algo, key, iv)?;
        let mut in_out = data.to_vec();
        lsk.seal_in_place_append_tag(nonce, backend::aead::Aad::from(aad), &mut in_out)
            .map_err(|e| CoseError::EncryptionError(box_err(e)))?;
        // in_out is now ciphertext || tag; split them apart
        let tag_len = tag.len();
        let ct_len = in_out.len() - tag_len;
        tag.copy_from_slice(&in_out[ct_len..]);
        in_out.truncate(ct_len);
        Ok(in_out)
    }
}

impl Decryption for RingLike {
    fn decrypt_aead(
        algo: EncryptionAlgorithm,
        key: &[u8],
        iv: Option<&[u8]>,
        aad: &[u8],
        data: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, CoseError> {
        let (lsk, nonce) = prepare_aead(algo, key, iv)?;
        // open_in_place expects ciphertext || tag concatenated
        let mut in_out = data.to_vec();
        in_out.extend_from_slice(tag);
        let plaintext = lsk
            .open_in_place(nonce, backend::aead::Aad::from(aad), &mut in_out)
            .map_err(|e| CoseError::EncryptionError(box_err(e)))?;
        Ok(plaintext.to_vec())
    }
}

impl Hash for RingLike {
    fn hash(digest: MessageDigest, data: &[u8]) -> Result<Vec<u8>, CoseError> {
        let algorithm = match digest {
            MessageDigest::Sha256 => &backend::digest::SHA256,
            MessageDigest::Sha384 => &backend::digest::SHA384,
            MessageDigest::Sha512 => &backend::digest::SHA512,
        };
        Ok(backend::digest::digest(algorithm, data).as_ref().to_vec())
    }
}

// ── Curve OID constants ───────────────────────────────────────────────────────

const OID_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const OID_P521: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");

fn curve_oid_to_sig_alg(oid: ObjectIdentifier) -> Result<SignatureAlgorithm, CoseError> {
    match oid {
        _ if oid == OID_P256 => Ok(SignatureAlgorithm::ES256),
        _ if oid == OID_P384 => Ok(SignatureAlgorithm::ES384),
        _ if oid == OID_P521 => Ok(SignatureAlgorithm::ES512),
        _ => Err(CoseError::UnsupportedError(format!(
            "Unsupported EC curve OID: {}",
            oid
        ))),
    }
}

// ── Algorithm-constant helpers ────────────────────────────────────────────────

fn signing_alg(
    alg: SignatureAlgorithm,
) -> Result<&'static backend::signature::EcdsaSigningAlgorithm, CoseError> {
    match alg {
        SignatureAlgorithm::ES256 => Ok(&backend::signature::ECDSA_P256_SHA256_FIXED_SIGNING),
        SignatureAlgorithm::ES384 => Ok(&backend::signature::ECDSA_P384_SHA384_FIXED_SIGNING),
        SignatureAlgorithm::ES512 => signing_alg_es512(),
    }
}

#[cfg(feature = "ring")]
fn signing_alg_es512() -> Result<&'static backend::signature::EcdsaSigningAlgorithm, CoseError> {
    Err(CoseError::UnsupportedError(
        "ES512/P-521 is not supported by the ring backend; use aws-lc-rs".to_string(),
    ))
}

#[cfg(feature = "aws-lc-rs")]
fn signing_alg_es512() -> Result<&'static backend::signature::EcdsaSigningAlgorithm, CoseError> {
    Ok(&backend::signature::ECDSA_P521_SHA512_FIXED_SIGNING)
}

fn verify_alg(
    alg: SignatureAlgorithm,
) -> Result<&'static backend::signature::EcdsaVerificationAlgorithm, CoseError> {
    match alg {
        SignatureAlgorithm::ES256 => Ok(&backend::signature::ECDSA_P256_SHA256_FIXED),
        SignatureAlgorithm::ES384 => Ok(&backend::signature::ECDSA_P384_SHA384_FIXED),
        SignatureAlgorithm::ES512 => verify_alg_es512(),
    }
}

#[cfg(feature = "ring")]
fn verify_alg_es512() -> Result<&'static backend::signature::EcdsaVerificationAlgorithm, CoseError>
{
    Err(CoseError::UnsupportedError(
        "ES512/P-521 is not supported by the ring backend; use aws-lc-rs".to_string(),
    ))
}

#[cfg(feature = "aws-lc-rs")]
fn verify_alg_es512() -> Result<&'static backend::signature::EcdsaVerificationAlgorithm, CoseError>
{
    Ok(&backend::signature::ECDSA_P521_SHA512_FIXED)
}

// ── Backend API shims ─────────────────────────────────────────────────────────
// ring::EcdsaKeyPair::from_pkcs8(algo, bytes, rng) — rng used for blinding.
// aws-lc-rs::EcdsaKeyPair::from_pkcs8(algo, bytes)  — no rng parameter.

fn keypair_from_pkcs8(
    sig_alg: &'static backend::signature::EcdsaSigningAlgorithm,
    pkcs8: &[u8],
) -> Result<backend::signature::EcdsaKeyPair, CoseError> {
    #[cfg(feature = "ring")]
    {
        let rng = backend::rand::SystemRandom::new();
        backend::signature::EcdsaKeyPair::from_pkcs8(sig_alg, pkcs8, &rng)
            .map_err(|e| CoseError::KeyDecodingError(box_err(e)))
    }
    #[cfg(feature = "aws-lc-rs")]
    {
        backend::signature::EcdsaKeyPair::from_pkcs8(sig_alg, pkcs8)
            .map_err(|e| CoseError::KeyDecodingError(box_err(e)))
    }
}

// ── Key types ─────────────────────────────────────────────────────────────────

/// An EC private key backed by ring or aws-lc-rs.
pub struct EcPrivateKey {
    inner: backend::signature::EcdsaKeyPair,
    alg: SignatureAlgorithm,
}

/// An EC public key backed by ring or aws-lc-rs.
pub struct EcPublicKey {
    inner: backend::signature::UnparsedPublicKey<Vec<u8>>,
    alg: SignatureAlgorithm,
}

impl EcPrivateKey {
    /// Load from PKCS#8 DER-encoded private key bytes.
    pub fn from_pkcs8(bytes: &[u8]) -> Result<Self, CoseError> {
        let pki = PrivateKeyInfo::try_from(bytes)
            .map_err(|e| CoseError::KeyDecodingError(box_err(e)))?;
        let curve_oid = pki
            .algorithm
            .parameters_oid()
            .map_err(|e| CoseError::KeyDecodingError(box_err(e)))?;
        let alg = curve_oid_to_sig_alg(curve_oid)?;
        let sig_alg = signing_alg(alg)?;
        let inner = keypair_from_pkcs8(sig_alg, bytes)?;
        Ok(EcPrivateKey { inner, alg })
    }

    /// Load from PEM-encoded PKCS#8 private key.
    #[cfg(feature = "pem")]
    pub fn from_pem(pem: &str) -> Result<Self, CoseError> {
        let (_, doc) = der::SecretDocument::from_pem(pem)
            .map_err(|e| CoseError::KeyDecodingError(box_err(e)))?;
        Self::from_pkcs8(doc.as_bytes())
    }

    /// Extract the corresponding public key.
    pub fn public_key(&self) -> Result<EcPublicKey, CoseError> {
        let v_alg = verify_alg(self.alg)?;
        let pub_bytes = self.inner.public_key().as_ref().to_vec();
        Ok(EcPublicKey {
            inner: backend::signature::UnparsedPublicKey::new(v_alg, pub_bytes),
            alg: self.alg,
        })
    }

    /// Generate a fresh key pair for the given curve (test use only).
    #[cfg(test)]
    pub(crate) fn generate_test_keypair(curve: SignatureAlgorithm) -> Self {
        let sig_alg = signing_alg(curve).expect("supported curve");
        let rng = backend::rand::SystemRandom::new();
        let doc = backend::signature::EcdsaKeyPair::generate_pkcs8(sig_alg, &rng)
            .expect("key generation");
        EcPrivateKey::from_pkcs8(doc.as_ref()).expect("round-trip load")
    }
}

impl EcPublicKey {
    /// Build from SEC1 uncompressed point bytes (`0x04 || x || y`).
    pub fn from_sec1_bytes(curve: SignatureAlgorithm, bytes: &[u8]) -> Result<Self, CoseError> {
        let v_alg = verify_alg(curve)?;
        Ok(EcPublicKey {
            inner: backend::signature::UnparsedPublicKey::new(v_alg, bytes.to_vec()),
            alg: curve,
        })
    }

    /// Load from DER-encoded SubjectPublicKeyInfo (SPKI) bytes.
    pub fn from_spki(bytes: &[u8]) -> Result<Self, CoseError> {
        let spki_info = SubjectPublicKeyInfoRef::try_from(bytes)
            .map_err(|e| CoseError::KeyDecodingError(box_err(e)))?;
        let curve_oid = spki_info
            .algorithm
            .parameters_oid()
            .map_err(|e| CoseError::KeyDecodingError(box_err(e)))?;
        let alg = curve_oid_to_sig_alg(curve_oid)?;
        let v_alg = verify_alg(alg)?;
        let ec_point = spki_info.subject_public_key.raw_bytes().to_vec();
        Ok(EcPublicKey {
            inner: backend::signature::UnparsedPublicKey::new(v_alg, ec_point),
            alg,
        })
    }

    /// Load from PEM-encoded SubjectPublicKeyInfo public key.
    #[cfg(feature = "pem")]
    pub fn from_pem(pem: &str) -> Result<Self, CoseError> {
        let (_, doc) = der::Document::from_pem(pem)
            .map_err(|e| CoseError::KeyDecodingError(box_err(e)))?;
        Self::from_spki(doc.as_bytes())
    }
}

impl SigningPublicKey for EcPublicKey {
    fn get_parameters(&self) -> Result<(SignatureAlgorithm, MessageDigest), CoseError> {
        Ok((self.alg, self.alg.suggested_message_digest()))
    }

    fn hashes_internally(&self) -> bool {
        true
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, CoseError> {
        match self.inner.verify(message, signature) {
            Ok(()) => Ok(true),
            // ring/aws-lc-rs return Unspecified for both invalid signatures and key errors;
            // treat all failures as verification failures rather than hard errors.
            Err(_) => Ok(false),
        }
    }
}

impl SigningPublicKey for EcPrivateKey {
    fn get_parameters(&self) -> Result<(SignatureAlgorithm, MessageDigest), CoseError> {
        Ok((self.alg, self.alg.suggested_message_digest()))
    }

    fn hashes_internally(&self) -> bool {
        true
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, CoseError> {
        self.public_key()?.verify(message, signature)
    }
}

impl SigningPrivateKey for EcPrivateKey {
    /// Sign `message`.
    ///
    /// The backend hashes `message` internally before signing.  Pass the raw
    /// Sig_Structure bytes, not a pre-computed digest.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CoseError> {
        let rng = backend::rand::SystemRandom::new();
        let sig = self
            .inner
            .sign(&rng, message)
            .map_err(|e| CoseError::SignatureError(box_err(e)))?;
        // FIXED algorithms produce I2OSP(r, n) || I2OSP(s, n) directly — no reformatting needed.
        Ok(sig.as_ref().to_vec())
    }
}
