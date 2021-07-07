//! TPM implementation for cryptography

use std::{cell::RefCell, convert::TryInto};

use openssl::hash::MessageDigest;
use tss_esapi::{
    constants::{
        self as tpm_constants,
        response_code::{FormatOneResponseCode, Tss2ResponseCode},
    },
    handles::KeyHandle,
    interface_types::algorithm::HashingAlgorithm,
    tss2_esys::{TPMT_PUBLIC, TPMT_SIG_SCHEME, TPMT_TK_HASHCHECK},
    utils::{AsymSchemeUnion, Signature, SignatureData},
    Context, Error as tpm_error,
};

use crate::{
    crypto::{SigningPrivateKey, SigningPublicKey},
    error::COSEError,
    sign::SignatureAlgorithm,
};

const TSS2_RC_SIGNATURE: u32 = tpm_constants::tss::TPM2_RC_SIGNATURE
    | tpm_constants::tss::TPM2_RC_2
    | tpm_constants::tss::TPM2_RC_P;

/// A reference to a TPM key and corresponding context
pub struct TpmKey {
    context: RefCell<Context>,
    key_handle: KeyHandle,

    parameters: (SignatureAlgorithm, MessageDigest),
    hash_alg: HashingAlgorithm,
    key_length: usize,
}

impl TpmKey {
    fn public_to_parameters(
        public: TPMT_PUBLIC,
    ) -> Result<((SignatureAlgorithm, MessageDigest), HashingAlgorithm, usize), COSEError> {
        match public.type_ {
            tpm_constants::tss::TPM2_ALG_ECDSA => {}
            tpm_constants::tss::TPM2_ALG_ECC => {}
            type_ => {
                return Err(COSEError::UnsupportedError(format!(
                    "Key algorithm {} is not supported, only ECDSA is currently supported",
                    type_
                )))
            }
        }
        let params = unsafe { public.parameters.eccDetail };
        let (param_sig_alg, key_length) = match params.curveID {
            tpm_constants::tss::TPM2_ECC_NIST_P256 => (SignatureAlgorithm::ES256, 32),
            tpm_constants::tss::TPM2_ECC_NIST_P384 => (SignatureAlgorithm::ES384, 48),
            tpm_constants::tss::TPM2_ECC_NIST_P521 => (SignatureAlgorithm::ES512, 66),
            curve_id => {
                return Err(COSEError::UnsupportedError(format!(
                    "Key curve {} is not supported",
                    curve_id
                )))
            }
        };
        match params.scheme.scheme {
            tpm_constants::tss::TPM2_ALG_ECDSA => {}
            scheme => {
                return Err(COSEError::UnsupportedError(format!(
                    "Key scheme {} is not supported",
                    scheme
                )))
            }
        }

        let scheme = unsafe { params.scheme.details.ecdsa };
        let param_hash_alg = match scheme.hashAlg {
            tpm_constants::tss::TPM2_ALG_SHA256 => MessageDigest::sha256(),
            tpm_constants::tss::TPM2_ALG_SHA384 => MessageDigest::sha384(),
            tpm_constants::tss::TPM2_ALG_SHA512 => MessageDigest::sha512(),
            hash_alg => {
                return Err(COSEError::UnsupportedError(format!(
                    "Key hash alg {} is not supported",
                    hash_alg
                )))
            }
        };
        let hash_alg = scheme.hashAlg.try_into().map_err(|_| {
            COSEError::UnsupportedError("Unsupported hashing algorithm".to_string())
        })?;

        Ok(((param_sig_alg, param_hash_alg), hash_alg, key_length))
    }

    /// Create a new TpmKey from a TPM Context and KeyHandle
    pub fn new(mut context: Context, key_handle: KeyHandle) -> Result<TpmKey, COSEError> {
        let (key_public, _, _) = context
            .read_public(key_handle)
            .map_err(COSEError::TpmError)?;
        let (parameters, hash_alg, key_length) =
            TpmKey::public_to_parameters(key_public.publicArea)?;

        Ok(TpmKey {
            context: RefCell::new(context),
            key_handle,

            parameters,
            hash_alg,
            key_length,
        })
    }
}

impl SigningPublicKey for TpmKey {
    fn get_parameters(&self) -> Result<(SignatureAlgorithm, MessageDigest), COSEError> {
        Ok(self.parameters)
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, COSEError> {
        // Recover the R and S factors from the signature contained in the object
        let (bytes_r, bytes_s) = signature.split_at(self.key_length);

        let signature = Signature {
            scheme: AsymSchemeUnion::ECDSA(self.hash_alg),
            signature: SignatureData::EcdsaSignature {
                r: bytes_r.to_vec(),
                s: bytes_s.to_vec(),
            },
        };

        let data = data.try_into().map_err(|_| {
            COSEError::UnsupportedError("Invalid digest passed to verify".to_string())
        })?;

        let mut context = self.context.borrow_mut();

        match context.verify_signature(self.key_handle, &data, signature) {
            Ok(_) => Ok(true),
            Err(tpm_error::Tss2Error(Tss2ResponseCode::FormatOne(FormatOneResponseCode(
                TSS2_RC_SIGNATURE,
            )))) => Ok(false),
            Err(e) => Err(COSEError::TpmError(e)),
        }
    }
}

impl SigningPrivateKey for TpmKey {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, COSEError> {
        let scheme = TPMT_SIG_SCHEME {
            scheme: tpm_constants::tss::TPM2_ALG_NULL,
            details: Default::default(),
        };
        let validation = TPMT_TK_HASHCHECK {
            tag: tpm_constants::tss::TPM2_ST_HASHCHECK,
            hierarchy: tpm_constants::tss::TPM2_RH_NULL,
            digest: Default::default(),
        };

        let data = data
            .try_into()
            .map_err(|_| COSEError::UnsupportedError("Tried to sign invalid data".to_string()))?;

        let signature = {
            let mut context = self.context.borrow_mut();

            context
                .sign(
                    self.key_handle,
                    &data,
                    scheme,
                    validation.try_into().expect("Unable to convert validation"),
                )
                .map_err(COSEError::TpmError)?
        };

        let (bytes_r, bytes_s) = match signature.signature {
            SignatureData::EcdsaSignature { r, s } => (r, s),
            _ => {
                return Err(COSEError::UnsupportedError(
                    "Unsupported signature data returned".to_string(),
                ))
            }
        };

        assert!(bytes_r.len() <= self.key_length);
        assert!(bytes_s.len() <= self.key_length);

        let mut signature_bytes = vec![0u8; self.key_length * 2];

        // This is big-endian encoding so padding might be added at the start if the factor is
        // too short.
        let offset_copy = self.key_length - bytes_r.len();
        signature_bytes[offset_copy..offset_copy + bytes_r.len()].copy_from_slice(&bytes_r);

        // This is big-endian encoding so padding might be added at the start if the factor is
        // too short.
        let offset_copy = self.key_length - bytes_s.len() + self.key_length;
        signature_bytes[offset_copy..offset_copy + bytes_s.len()].copy_from_slice(&bytes_s);

        Ok(signature_bytes)
    }
}
