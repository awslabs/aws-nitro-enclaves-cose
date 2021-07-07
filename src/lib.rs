#![deny(missing_docs)]
#![deny(warnings)]
// TODO: in 0.3.0 provide transitional type names and deprecate the old ones.
#![allow(clippy::upper_case_acronyms)]

//! This library aims to provide safe Rust implementations for COSE, using
//! serde and serde_cbor as an encoding layer and OpenSSL as the base
//! crypto library.
//!
//! Currently only COSE Sign1 and COSE Encrypt0 are implemented.

pub mod crypto;
pub mod encrypt;
pub mod error;
pub mod header_map;
pub mod sign;

pub use crate::encrypt::COSEEncrypt0;
pub use crate::encrypt::CipherConfiguration;
#[doc(inline)]
pub use crate::sign::COSESign1;
