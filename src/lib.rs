#![deny(missing_docs)]
#![deny(warnings)]

//! This library aims to provide safe Rust implementations for COSE, using
//! serde and serde_cbor as an encoding layer and OpenSSL as the base
//! crypto library.
//!
//! Currently only COSE Sign1 is implemented.

pub mod error;
pub mod sign;

#[doc(inline)]
pub use crate::sign::COSESign1;
