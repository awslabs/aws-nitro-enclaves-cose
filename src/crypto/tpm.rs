//! TPM implementation for cryptography

use std::{
    cell::RefCell,
    convert::{TryFrom, TryInto},
};

use tss_esapi::{
    constants::{
        self as tpm_constants,
        response_code::{FormatOneResponseCode, Tss2ResponseCode},
    },
    handles::KeyHandle,
    interface_types::algorithm::HashingAlgorithm,
    structures::{Digest, EccParameter, EccSignature, Signature},
    tss2_esys::{TPMT_PUBLIC, TPMT_SIG_SCHEME, TPMT_TK_HASHCHECK},
    Context, Error as tpm_error,
};

use crate::{
    crypto::{MessageDigest, SignatureAlgorithm, SigningPrivateKey, SigningPublicKey},
    error::CoseError,
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
    ) -> Result<((SignatureAlgorithm, MessageDigest), HashingAlgorithm, usize), CoseError> {
        match public.type_ {
            tpm_constants::tss::TPM2_ALG_ECDSA => {}
            tpm_constants::tss::TPM2_ALG_ECC => {}
            type_ => {
                return Err(CoseError::UnsupportedError(format!(
                    "Key algorithm {} is not supported, only ECDSA is currently supported",
                    type_
                )))
            }
        }
        // This is safe to do, because we checked the type above
        let params = unsafe { public.parameters.eccDetail };
        let (param_sig_alg, key_length) = match params.curveID {
            tpm_constants::tss::TPM2_ECC_NIST_P256 => (SignatureAlgorithm::ES256, 32),
            tpm_constants::tss::TPM2_ECC_NIST_P384 => (SignatureAlgorithm::ES384, 48),
            tpm_constants::tss::TPM2_ECC_NIST_P521 => (SignatureAlgorithm::ES512, 66),
            curve_id => {
                return Err(CoseError::UnsupportedError(format!(
                    "Key curve {} is not supported",
                    curve_id
                )))
            }
        };
        match params.scheme.scheme {
            tpm_constants::tss::TPM2_ALG_ECDSA => {}
            scheme => {
                return Err(CoseError::UnsupportedError(format!(
                    "Key scheme {} is not supported",
                    scheme
                )))
            }
        }

        let scheme = unsafe { params.scheme.details.ecdsa };
        let param_hash_alg = match scheme.hashAlg {
            tpm_constants::tss::TPM2_ALG_SHA256 => MessageDigest::Sha256,
            tpm_constants::tss::TPM2_ALG_SHA384 => MessageDigest::Sha384,
            tpm_constants::tss::TPM2_ALG_SHA512 => MessageDigest::Sha512,
            hash_alg => {
                return Err(CoseError::UnsupportedError(format!(
                    "Key hash alg {} is not supported",
                    hash_alg
                )))
            }
        };
        let hash_alg = scheme.hashAlg.try_into().map_err(|_| {
            CoseError::UnsupportedError("Unsupported hashing algorithm".to_string())
        })?;

        Ok(((param_sig_alg, param_hash_alg), hash_alg, key_length))
    }

    /// Create a new TpmKey from a TPM Context and KeyHandle
    pub fn new(mut context: Context, key_handle: KeyHandle) -> Result<TpmKey, CoseError> {
        let (key_public, _, _) = context
            .read_public(key_handle)
            .map_err(CoseError::TpmError)?;
        let (parameters, hash_alg, key_length) = TpmKey::public_to_parameters(key_public.into())?;

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
    fn get_parameters(&self) -> Result<(SignatureAlgorithm, MessageDigest), CoseError> {
        Ok(self.parameters)
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, CoseError> {
        // Recover the R and S factors from the signature contained in the object
        let (bytes_r, bytes_s) = signature.split_at(self.key_length);

        let signature = Signature::EcDsa(
            EccSignature::create(
                self.hash_alg,
                EccParameter::try_from(bytes_r.to_vec()).map_err(|_| {
                    CoseError::UnsupportedError(
                        "Unable to convert R signature component".to_string(),
                    )
                })?,
                EccParameter::try_from(bytes_s.to_vec()).map_err(|_| {
                    CoseError::UnsupportedError(
                        "Unable to convert S signature component".to_string(),
                    )
                })?,
            )
            .map_err(|_| {
                CoseError::UnsupportedError("Unable to create ECC signature".to_string())
            })?,
        );

        let data = Digest::try_from(data).map_err(|_| {
            CoseError::UnsupportedError("Invalid digest passed to verify".to_string())
        })?;

        let mut context = self.context.borrow_mut();

        match context.verify_signature(self.key_handle, data, signature) {
            Ok(_) => Ok(true),
            Err(tpm_error::Tss2Error(Tss2ResponseCode::FormatOne(FormatOneResponseCode(
                TSS2_RC_SIGNATURE,
            )))) => Ok(false),
            Err(e) => Err(CoseError::TpmError(e)),
        }
    }
}

impl SigningPrivateKey for TpmKey {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CoseError> {
        let scheme = TPMT_SIG_SCHEME {
            scheme: tpm_constants::tss::TPM2_ALG_NULL,
            details: Default::default(),
        };
        let validation = TPMT_TK_HASHCHECK {
            tag: tpm_constants::tss::TPM2_ST_HASHCHECK,
            hierarchy: tpm_constants::tss::TPM2_RH_NULL,
            digest: Default::default(),
        };

        let data = Digest::try_from(data)
            .map_err(|_| CoseError::UnsupportedError("Tried to sign invalid data".to_string()))?;

        let signature = {
            let mut context = self.context.borrow_mut();

            context
                .sign(
                    self.key_handle,
                    data,
                    scheme.try_into().map_err(|_| {
                        CoseError::UnsupportedError(
                            "Unable to convert signature scheme".to_string(),
                        )
                    })?,
                    validation.try_into().expect("Unable to convert validation"),
                )
                .map_err(CoseError::TpmError)?
        };

        match &signature {
            Signature::EcDsa(sig) => Ok(super::merge_ec_signature(
                sig.signature_r(),
                sig.signature_s(),
                self.key_length,
            )),
            _ => Err(CoseError::UnsupportedError(
                "Unsupported signature data returned".to_string(),
            )),
        }
    }
}
