//! This library aims to provide safe Rust implementations for COSE, using
//! serde and serde_cbor as an encoding layer and OpenSSL as the base
//! crypto library.
//!
//! Currently only COSE Sign1 and COSE Encrypt0 are implemented.

#![deny(missing_docs)]
#![deny(warnings)]

#[cfg(not(any(feature = "openssl", feature = "ring", feature = "aws-lc-rs")))]
compile_error!("At least one crypto backend must be selected: openssl, ring, or aws-lc-rs");
#[cfg(all(feature = "openssl", feature = "ring"))]
compile_error!("Features `openssl` and `ring` are mutually exclusive");
#[cfg(all(feature = "openssl", feature = "aws-lc-rs"))]
compile_error!("Features `openssl` and `aws-lc-rs` are mutually exclusive");
#[cfg(all(feature = "ring", feature = "aws-lc-rs"))]
compile_error!("Features `ring` and `aws-lc-rs` are mutually exclusive");
#[cfg(all(feature = "ring", feature = "key_kms"))]
compile_error!("Feature `ring` is not compatible with `key_kms`; use `aws-lc-rs` instead");

pub mod crypto;
pub mod encrypt;
pub mod error;
pub mod header_map;
pub mod sign;

pub use crate::encrypt::CipherConfiguration;
pub use crate::encrypt::CoseEncrypt0;
#[doc(inline)]
pub use crate::sign::CoseSign1;
