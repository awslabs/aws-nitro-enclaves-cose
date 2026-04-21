#[cfg(feature = "key_kms")]
use crate::error::CoseError;

#[cfg(feature = "key_kms")]
use der::{
    Decode, DecodeValue, Encode, EncodeValue, Header, Length, Reader, Sequence, Writer,
    asn1::UintRef,
};

#[cfg(feature = "key_kms")]
struct EcdsaSigRef<'a> {
    r: UintRef<'a>,
    s: UintRef<'a>,
}

#[cfg(feature = "key_kms")]
impl<'a> DecodeValue<'a> for EcdsaSigRef<'a> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        reader.read_nested(header.length, |reader| {
            let r = UintRef::decode(reader)?;
            let s = UintRef::decode(reader)?;
            Ok(Self { r, s })
        })
    }
}

#[cfg(feature = "key_kms")]
impl EncodeValue for EcdsaSigRef<'_> {
    fn value_len(&self) -> der::Result<Length> {
        self.r.encoded_len()? + self.s.encoded_len()?
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        self.r.encode(writer)?;
        self.s.encode(writer)
    }
}

#[cfg(feature = "key_kms")]
impl<'a> Sequence<'a> for EcdsaSigRef<'a> {}

#[cfg(feature = "key_kms")]
fn trim_leading_zeros(bytes: &[u8]) -> &[u8] {
    if bytes.is_empty() {
        return bytes;
    }
    match bytes.iter().position(|&b| b != 0) {
        Some(pos) => &bytes[pos..],
        None => &bytes[bytes.len() - 1..],
    }
}

/// Encode raw COSE I2OSP(r, n)||I2OSP(s, n) to DER SEQUENCE { INTEGER r, INTEGER s }.
#[cfg(feature = "key_kms")]
pub(crate) fn ecdsa_sig_to_der(r: &[u8], s: &[u8]) -> Result<Vec<u8>, CoseError> {
    let sig = EcdsaSigRef {
        r: UintRef::new(trim_leading_zeros(r))
            .map_err(|e| CoseError::SignatureError(Box::new(e)))?,
        s: UintRef::new(trim_leading_zeros(s))
            .map_err(|e| CoseError::SignatureError(Box::new(e)))?,
    };
    sig.to_der()
        .map_err(|e| CoseError::SignatureError(Box::new(e)))
}

/// Decode DER SEQUENCE { INTEGER r, INTEGER s } to raw (r_bytes, s_bytes).
#[cfg(feature = "key_kms")]
pub(crate) fn ecdsa_sig_from_der(der_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CoseError> {
    let sig = EcdsaSigRef::from_der(der_bytes)
        .map_err(|e| CoseError::SignatureError(Box::new(e)))?;
    Ok((sig.r.as_bytes().to_vec(), sig.s.as_bytes().to_vec()))
}

/// Merge raw (r, s) byte slices into fixed-length I2OSP(r, n) || I2OSP(s, n) COSE format.
#[cfg(any(feature = "openssl", feature = "key_kms", feature = "key_tpm"))]
pub(crate) fn merge_ec_signature(bytes_r: &[u8], bytes_s: &[u8], key_length: usize) -> Vec<u8> {
    assert!(bytes_r.len() <= key_length);
    assert!(bytes_s.len() <= key_length);

    let mut signature_bytes = vec![0u8; key_length * 2];

    let offset_copy = key_length - bytes_r.len();
    signature_bytes[offset_copy..offset_copy + bytes_r.len()].copy_from_slice(bytes_r);

    let offset_copy = key_length - bytes_s.len() + key_length;
    signature_bytes[offset_copy..offset_copy + bytes_s.len()].copy_from_slice(bytes_s);

    signature_bytes
}
