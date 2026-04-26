use crate::error::CoseError;
use serde::{de::DeserializeOwned, Serialize};

pub(crate) fn from_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CoseError> {
    ciborium::de::from_reader(bytes).map_err(|e| CoseError::SerializationError(Box::new(e)))
}

pub(crate) fn to_vec<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, CoseError> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf)
        .map_err(|e| CoseError::SerializationError(Box::new(e)))?;
    Ok(buf)
}
