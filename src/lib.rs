#![deny(missing_docs)]
#![deny(warnings)]

//! This library aims to provide safe Rust implementations for COSE, using
//! serde and ciborium as an encoding layer and OpenSSL as the base
//! crypto library.
//!
//! Currently only COSE Sign1 and COSE Encrypt0 are implemented.

pub(crate) mod cbor;
pub mod crypto;
pub mod encrypt;
pub mod error;
pub mod header_map;
pub mod sign;

pub use crate::encrypt::CipherConfiguration;
pub use crate::encrypt::CoseEncrypt0;
pub use crate::header_map::CborInteger;
pub use crate::header_map::CborValue;
#[doc(inline)]
pub use crate::sign::CoseSign1;
