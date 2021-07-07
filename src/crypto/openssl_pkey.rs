//! OpenSSL PKey(Ref) implementation for cryptography

use openssl::{
    bn::BigNum,
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    pkey::{HasPrivate, HasPublic, PKey, PKeyRef},
};

use crate::{
    crypto::{ec_curve_to_parameters, SigningPrivateKey, SigningPublicKey},
    error::COSEError,
    sign::SignatureAlgorithm,
};

impl<T> SigningPublicKey for PKey<T>
where
    T: HasPublic,
{
    fn get_parameters(&self) -> Result<(SignatureAlgorithm, MessageDigest), COSEError> {
        self.as_ref().get_parameters()
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, COSEError> {
        self.as_ref().verify(data, signature)
    }
}

impl<T> SigningPublicKey for PKeyRef<T>
where
    T: HasPublic,
{
    fn get_parameters(&self) -> Result<(SignatureAlgorithm, MessageDigest), COSEError> {
        let curve_name = self
            .ec_key()
            .map_err(|_| COSEError::UnsupportedError("Non-EC keys are not supported".to_string()))?
            .group()
            .curve_name()
            .ok_or_else(|| {
                COSEError::UnsupportedError("Anonymous EC keys are not supported".to_string())
            })?;

        let curve_parameters = ec_curve_to_parameters(curve_name)?;

        Ok((curve_parameters.0, curve_parameters.1))
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, COSEError> {
        let key = self.ec_key().map_err(|_| {
            COSEError::UnsupportedError("Non-EC keys are not yet supported".to_string())
        })?;

        let curve_name = key.group().curve_name().ok_or_else(|| {
            COSEError::UnsupportedError("Anonymous EC keys are not supported".to_string())
        })?;

        let (_, _, key_length) = ec_curve_to_parameters(curve_name)?;

        // Recover the R and S factors from the signature contained in the object
        let (bytes_r, bytes_s) = signature.split_at(key_length);

        let r = BigNum::from_slice(&bytes_r).map_err(COSEError::SignatureError)?;
        let s = BigNum::from_slice(&bytes_s).map_err(COSEError::SignatureError)?;

        let sig = EcdsaSig::from_private_components(r, s).map_err(COSEError::SignatureError)?;
        sig.verify(data, &key).map_err(COSEError::SignatureError)
    }
}

impl<T> SigningPrivateKey for PKey<T>
where
    T: HasPrivate,
{
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, COSEError> {
        self.as_ref().sign(data)
    }
}

impl<T> SigningPrivateKey for PKeyRef<T>
where
    T: HasPrivate,
{
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, COSEError> {
        let key = self.ec_key().map_err(|_| {
            COSEError::UnsupportedError("Non-EC keys are not yet supported".to_string())
        })?;

        let curve_name = key.group().curve_name().ok_or_else(|| {
            COSEError::UnsupportedError("Anonymous EC keys are not supported".to_string())
        })?;

        let (_, _, key_length) = ec_curve_to_parameters(curve_name)?;

        // The spec defines the signature as:
        // Signature = I2OSP(R, n) | I2OSP(S, n), where n = ceiling(key_length / 8)
        // The Signer interface doesn't provide this, so this will use EcdsaSig interface instead
        // and concatenate R and S.
        // See https://tools.ietf.org/html/rfc8017#section-4.1 for details.
        let signature = EcdsaSig::sign(data, &key).map_err(COSEError::SignatureError)?;
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
