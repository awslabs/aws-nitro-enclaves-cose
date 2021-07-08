//! KMS implementation for cryptography

use openssl::{
    bn::BigNum,
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    pkey::{PKey, Public},
};
use tokio::runtime::Runtime;

use aws_sdk_kms::{
    error::{VerifyError, VerifyErrorKind},
    model::{MessageType, SigningAlgorithmSpec},
    Blob, Client, SdkError,
};

use crate::{
    crypto::{ec_curve_to_parameters, SigningPrivateKey, SigningPublicKey},
    error::CoseError,
    sign::SignatureAlgorithm,
};

/// A reference to an AWS KMS key and client
pub struct KmsKey {
    client: Client,
    key_id: String,

    sig_alg: SignatureAlgorithm,

    public_key: Option<PKey<Public>>,

    runtime: Runtime,
}

impl KmsKey {
    fn new_runtime() -> Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Error creating tokio runtime")
    }

    /// Create a new KmsKey, using the specified client and key_id.
    ///
    /// The sig_alg needs to be valid for the specified key.
    /// This version will use the KMS Verify call to verify signatures.
    ///
    /// AWS Permissions required on the specified key:
    /// - Sign (for creating new signatures)
    /// - Verify (for verifying existing signatures)
    pub fn new(
        client: Client,
        key_id: String,
        sig_alg: SignatureAlgorithm,
    ) -> Result<Self, CoseError> {
        Ok(KmsKey {
            client,
            key_id,
            sig_alg,

            public_key: None,

            runtime: Self::new_runtime(),
        })
    }

    /// Create a new KmsKey, using the specified client and key_id.
    ///
    /// The sig_alg needs to be valid for the specified key.
    /// This version will use local signature verification.
    /// If no public key is passed in, the key will be retrieved with GetPublicKey.
    ///
    /// AWS Permissions required on the specified key:
    /// - Sign (for creating new signatures)
    /// - GetPublicKey (to get the public key if it wasn't passed in)
    #[cfg(feature = "key_openssl_pkey")]
    pub fn new_with_public_key(
        client: Client,
        key_id: String,
        public_key: Option<PKey<Public>>,
    ) -> Result<Self, CoseError> {
        let runtime = Self::new_runtime();
        let public_key = match public_key {
            Some(key) => key,
            None => {
                // Retrieve public key from AWS
                let request = client.get_public_key().key_id(key_id.clone()).send();

                let public_key = runtime
                    .block_on(request)
                    .map_err(CoseError::AwsGetPublicKeyError)?
                    .public_key
                    .ok_or_else(|| {
                        CoseError::UnsupportedError("No public key returned".to_string())
                    })?;

                PKey::public_key_from_der(public_key.as_ref()).map_err(CoseError::SignatureError)?
            }
        };

        let curve_name = public_key
            .ec_key()
            .map_err(|_| CoseError::UnsupportedError("Non-EC keys are not supported".to_string()))?
            .group()
            .curve_name()
            .ok_or_else(|| {
                CoseError::UnsupportedError("Anonymous EC keys are not supported".to_string())
            })?;
        let sig_alg = ec_curve_to_parameters(curve_name)?.0;

        Ok(KmsKey {
            client,
            key_id,

            sig_alg,
            public_key: Some(public_key),

            runtime,
        })
    }

    fn get_sig_alg_spec(&self) -> SigningAlgorithmSpec {
        match self.sig_alg {
            SignatureAlgorithm::ES256 => SigningAlgorithmSpec::EcdsaSha256,
            SignatureAlgorithm::ES384 => SigningAlgorithmSpec::EcdsaSha384,
            SignatureAlgorithm::ES512 => SigningAlgorithmSpec::EcdsaSha512,
        }
    }

    #[cfg(feature = "key_openssl_pkey")]
    fn verify_with_public_key(&self, data: &[u8], signature: &[u8]) -> Result<bool, CoseError> {
        self.public_key.as_ref().unwrap().verify(data, signature)
    }
}

impl SigningPublicKey for KmsKey {
    fn get_parameters(&self) -> Result<(SignatureAlgorithm, MessageDigest), CoseError> {
        Ok((self.sig_alg, self.sig_alg.suggested_message_digest()))
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, CoseError> {
        if self.public_key.is_some() {
            #[cfg(feature = "key_openssl_pkey")]
            return self.verify_with_public_key(data, signature);

            #[cfg(not(feature = "key_openssl_pkey"))]
            panic!("Would have been impossible to get public_key set");
        } else {
            // Call KMS to verify

            // Recover the R and S factors from the signature contained in the object
            let (bytes_r, bytes_s) = signature.split_at(self.sig_alg.key_length());

            let r = BigNum::from_slice(&bytes_r).map_err(CoseError::SignatureError)?;
            let s = BigNum::from_slice(&bytes_s).map_err(CoseError::SignatureError)?;

            let sig = EcdsaSig::from_private_components(r, s).map_err(CoseError::SignatureError)?;
            let sig = sig.to_der().map_err(CoseError::SignatureError)?;

            let request = self
                .client
                .verify()
                .key_id(self.key_id.clone())
                .message(Blob::new(data.to_vec()))
                .message_type(MessageType::Digest)
                .signing_algorithm(self.get_sig_alg_spec())
                .signature(Blob::new(sig))
                .send();

            let reply = self.runtime.block_on(request);

            match reply {
                Ok(v) => Ok(v.signature_valid),
                Err(SdkError::ServiceError {
                    err:
                        VerifyError {
                            kind: VerifyErrorKind::KmsInvalidSignatureException(_),
                            ..
                        },
                    ..
                }) => Ok(false),
                Err(e) => Err(CoseError::AwsVerifyError(e)),
            }
        }
    }
}

impl SigningPrivateKey for KmsKey {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CoseError> {
        let request = self
            .client
            .sign()
            .key_id(self.key_id.clone())
            .message(Blob::new(data.to_vec()))
            .message_type(MessageType::Digest)
            .signing_algorithm(self.get_sig_alg_spec())
            .send();

        let signature = self
            .runtime
            .block_on(request)
            .map_err(CoseError::AwsSignError)?
            .signature
            .ok_or_else(|| CoseError::UnsupportedError("No signature returned".to_string()))?;

        let signature =
            EcdsaSig::from_der(signature.as_ref()).map_err(CoseError::SignatureError)?;

        let key_length = self.sig_alg.key_length();

        // The spec defines the signature as:
        // Signature = I2OSP(R, n) | I2OSP(S, n), where n = ceiling(key_length / 8)
        // The Signer interface doesn't provide this, so this will use EcdsaSig interface instead
        // and concatenate R and S.
        // See https://tools.ietf.org/html/rfc8017#section-4.1 for details.
        let bytes_r = signature.r().to_vec();
        let bytes_s = signature.s().to_vec();

        // These should *never* exceed ceiling(key_length / 8)
        assert!(bytes_r.len() <= key_length);
        assert!(bytes_s.len() <= key_length);

        let mut signature_bytes = vec![0u8; key_length * 2];

        // This is big-endian encoding so padding might be added at the start if the factor is
        // too short.
        let offset_copy = key_length - bytes_r.len();
        signature_bytes[offset_copy..offset_copy + bytes_r.len()].copy_from_slice(&bytes_r);

        // This is big-endian encoding so padding might be added at the start if the factor is
        // too short.
        let offset_copy = key_length - bytes_s.len() + key_length;
        signature_bytes[offset_copy..offset_copy + bytes_s.len()].copy_from_slice(&bytes_s);

        Ok(signature_bytes)
    }
}
