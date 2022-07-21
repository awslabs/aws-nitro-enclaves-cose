//! PARSEC implementation for cryptography

use crate::{
    crypto::{MessageDigest, SignatureAlgorithm, SigningPrivateKey, SigningPublicKey},
    error::CoseError,
};
use parsec_client::{
    auth::Authentication,
    core::interface::{
        operations::{
            psa_algorithm::{Algorithm, AsymmetricSignature, Hash, SignHash},
            psa_key_attributes::Attributes,
        },
        requests::ResponseStatus,
    },
    error::{ClientErrorKind, Error},
    BasicClient,
};

/// A reference to a PARSEC service-backed key
pub struct ParsecKey {
    parsec_client: BasicClient,
    name: String,
    algorithm: AsymmetricSignature,
    parameters: (SignatureAlgorithm, MessageDigest),
}

impl ParsecKey {
    /// Create a new [ParsecKey] based on its name within the Parsec
    /// service.
    pub fn new(name: String, parsec_auth: Option<Authentication>) -> Result<ParsecKey, CoseError> {
        let parsec_client = match parsec_auth {
            None => BasicClient::new(None)?,
            Some(auth) => {
                let mut client = BasicClient::new_naked();
                client.set_auth_data(auth);
                client.set_default_provider()?;
                client
            }
        };

        let keys = parsec_client.list_keys()?;
        let key = keys
            .into_iter()
            .find(|key| key.name == name)
            .ok_or(Error::Client(ClientErrorKind::NotFound))?;
        let (parameters, algorithm) = attrs_to_params(&key.attributes)?;

        Ok(ParsecKey {
            parsec_client,
            name,
            algorithm,
            parameters,
        })
    }
}

fn attrs_to_params(
    attrs: &Attributes,
) -> Result<((SignatureAlgorithm, MessageDigest), AsymmetricSignature), CoseError> {
    match attrs.policy.permitted_algorithms {
        Algorithm::AsymmetricSignature(alg @ AsymmetricSignature::Ecdsa { hash_alg }) => {
            match hash_alg {
                SignHash::Specific(Hash::Sha256) => {
                    Ok(((SignatureAlgorithm::ES256, MessageDigest::Sha256), alg))
                }
                SignHash::Specific(Hash::Sha384) => {
                    Ok(((SignatureAlgorithm::ES384, MessageDigest::Sha384), alg))
                }
                SignHash::Specific(Hash::Sha512) => {
                    Ok(((SignatureAlgorithm::ES512, MessageDigest::Sha512), alg))
                }
                _ => Err(CoseError::UnsupportedError(format!(
                    "Hash algorithm {:?} is not supported",
                    hash_alg
                ))),
            }
        }
        _ => Err(CoseError::UnsupportedError(format!(
            "Key algorithm {:?} is not supported",
            attrs.policy.permitted_algorithms
        ))),
    }
}

impl SigningPublicKey for ParsecKey {
    fn get_parameters(&self) -> Result<(SignatureAlgorithm, MessageDigest), CoseError> {
        Ok(self.parameters)
    }

    fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<bool, CoseError> {
        match self
            .parsec_client
            .psa_verify_hash(&self.name, digest, self.algorithm, signature)
        {
            Ok(()) => Ok(true),
            Err(Error::Service(ResponseStatus::PsaErrorInvalidSignature)) => Ok(false),
            Err(e) => Err(CoseError::ParsecError(e)),
        }
    }
}

impl SigningPrivateKey for ParsecKey {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CoseError> {
        Ok(self
            .parsec_client
            .psa_sign_hash(&self.name, data, self.algorithm)?)
    }
}

impl From<Error> for CoseError {
    fn from(err: Error) -> CoseError {
        CoseError::ParsecError(err)
    }
}
