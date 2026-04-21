//! KMS implementation for cryptography

use aws_sdk_kms::{
    error::SdkError, primitives::Blob, types::MessageType, types::SigningAlgorithmSpec, Client,
};

use crate::{
    crypto::{MessageDigest, SignatureAlgorithm, SigningPrivateKey, SigningPublicKey},
    error::CoseError,
};

#[cfg(any(feature = "openssl", feature = "aws-lc-rs"))]
use crate::crypto::EcPublicKey;

use tokio::runtime::Handle;

/// A reference to an AWS KMS key and client
pub struct KmsKey {
    client: Client,
    key_id: String,

    sig_alg: SignatureAlgorithm,

    #[cfg(any(feature = "openssl", feature = "aws-lc-rs"))]
    public_key: Option<EcPublicKey>,
}

impl KmsKey {
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
            #[cfg(any(feature = "openssl", feature = "aws-lc-rs"))]
            public_key: None,
        })
    }

    /// Create a new KmsKey, using the specified client and key_id.
    ///
    /// This method must be called from a Tokio context, otherwise the call panics.
    ///
    /// The sig_alg needs to be valid for the specified key.
    /// This version will use local signature verification.
    /// If no public key is passed in, the key will be retrieved with GetPublicKey.
    ///
    /// AWS Permissions required on the specified key:
    /// - Sign (for creating new signatures)
    /// - GetPublicKey (to get the public key if it wasn't passed in)
    #[cfg(any(feature = "openssl", feature = "aws-lc-rs"))]
    pub fn new_with_public_key(
        client: Client,
        key_id: String,
        public_key: Option<EcPublicKey>,
    ) -> Result<Self, CoseError> {
        let handle = Handle::current();
        let public_key = match public_key {
            Some(key) => key,
            None => {
                // Retrieve public key from AWS
                let request = client.get_public_key().key_id(key_id.clone()).send();

                let public_key = handle
                    .block_on(request)
                    .map_err(CoseError::AwsGetPublicKeyError)?
                    .public_key
                    .ok_or_else(|| {
                        CoseError::UnsupportedError("No public key returned".to_string())
                    })?;

                EcPublicKey::from_spki(public_key.as_ref())?
            }
        };

        let sig_alg = public_key.get_parameters()?.0;

        Ok(KmsKey {
            client,
            key_id,
            sig_alg,
            public_key: Some(public_key),
        })
    }

    fn get_sig_alg_spec(&self) -> SigningAlgorithmSpec {
        match self.sig_alg {
            SignatureAlgorithm::ES256 => SigningAlgorithmSpec::EcdsaSha256,
            SignatureAlgorithm::ES384 => SigningAlgorithmSpec::EcdsaSha384,
            SignatureAlgorithm::ES512 => SigningAlgorithmSpec::EcdsaSha512,
        }
    }

    // Only use local key verification when the key does not hash internally.
    // ring-like keys (aws-lc-rs) hash in their verify() call; since sign.rs
    // pre-computes the digest and passes it here, delegating to such a key
    // would double-hash and produce an incorrect result.
    #[cfg(any(feature = "openssl", feature = "aws-lc-rs"))]
    fn verify_with_public_key(&self, digest: &[u8], signature: &[u8]) -> Result<bool, CoseError> {
        self.public_key.as_ref().unwrap().verify(digest, signature)
    }
}

impl SigningPublicKey for KmsKey {
    fn get_parameters(&self) -> Result<(SignatureAlgorithm, MessageDigest), CoseError> {
        Ok((self.sig_alg, self.sig_alg.suggested_message_digest()))
    }

    /// Verifies a digital signature.
    ///
    /// If KMS is used for verification, this method must be called from a Tokio context,
    /// otherwise the call panics.
    ///
    /// # Arguments
    ///
    /// * `digest` - A byte slice containing the pre-computed digest of the data to verify
    /// * `signature` - A byte slice containing the signature to verify against the data
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - If the signature is valid for the given data
    /// * `Ok(false)` - If the signature is invalid or verification fails gracefully
    /// * `Err(CoseError)` - If an error occurs during verification
    fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<bool, CoseError> {
        #[cfg(any(feature = "openssl", feature = "aws-lc-rs"))]
        if self.public_key.is_some()
            && !self.public_key.as_ref().unwrap().hashes_internally()
        {
            return self.verify_with_public_key(digest, signature);
        }

        // Convert COSE raw R||S to DER for KMS
        let (bytes_r, bytes_s) = signature.split_at(self.sig_alg.key_length());
        let sig = super::der_util::ecdsa_sig_to_der(bytes_r, bytes_s)?;

        let request = self
            .client
            .verify()
            .key_id(self.key_id.clone())
            .message(Blob::new(digest.to_vec()))
            .message_type(MessageType::Digest)
            .signing_algorithm(self.get_sig_alg_spec())
            .signature(Blob::new(sig))
            .send();

        let handle = Handle::current();
        let reply = handle.block_on(request);

        match reply {
            Ok(v) => Ok(v.signature_valid),
            Err(SdkError::ServiceError(e)) if e.err().is_kms_invalid_signature_exception() => {
                Ok(false)
            }
            Err(e) => Err(CoseError::AwsVerifyError(e)),
        }
    }
}

impl SigningPrivateKey for KmsKey {
    /// Signs data using AWS KMS and formats the signature according to the ECDSA specification.
    ///
    /// This method must be called from a Tokio context, otherwise the call panics.
    ///
    /// # Arguments
    ///
    /// * `data` - A byte slice containing the data to be signed
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - A vector containing the formatted signature bytes
    /// * `Err(CoseError)` - If signing or signature formatting fails
    fn sign(&self, digest: &[u8]) -> Result<Vec<u8>, CoseError> {
        let request = self
            .client
            .sign()
            .key_id(self.key_id.clone())
            .message(Blob::new(digest.to_vec()))
            .message_type(MessageType::Digest)
            .signing_algorithm(self.get_sig_alg_spec())
            .send();

        let handle = Handle::current();
        let signature = handle
            .block_on(request)
            .map_err(CoseError::AwsSignError)?
            .signature
            .ok_or_else(|| CoseError::UnsupportedError("No signature returned".to_string()))?;

        // KMS returns DER-encoded ECDSA signature; convert to COSE I2OSP(r,n)||I2OSP(s,n)
        let (bytes_r, bytes_s) = super::der_util::ecdsa_sig_from_der(signature.as_ref())?;
        let key_length = self.sig_alg.key_length();
        Ok(super::der_util::merge_ec_signature(&bytes_r, &bytes_s, key_length))
    }
}
