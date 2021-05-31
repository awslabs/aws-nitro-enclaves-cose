#![deny(missing_docs)]
#![deny(warnings)]
// TODO: in 0.3.0 provide transitional type names and deprecate the old ones.
#![allow(clippy::upper_case_acronyms)]

//! This library aims to provide safe Rust implementations for COSE, using
//! serde and serde_cbor as an encoding layer and OpenSSL as the base
//! crypto library.
//!
//! Currently only COSE Sign1 is implemented.

pub mod error;
pub mod sign;
pub mod header_map;

#[doc(inline)]
pub use crate::sign::COSESign1;
