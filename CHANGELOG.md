
# Changelog

## 0.6.0

### Breaking changes

* The `key_openssl_pkey` Cargo feature has been renamed to `openssl`. Update your `Cargo.toml` accordingly.
* `PKey<Private>` / `PKey<Public>` are no longer accepted directly as signing keys. Use the new `EcPrivateKey` / `EcPublicKey` wrappers instead.
* `CoseSign1` signing/verification methods no longer take `<H: Hash>` or `<C: Encryption + Entropy>` / `<C: Decryption>` type parameters; the active backend is selected at compile time.

### New features

* Two new crypto backends: `ring` and `aws-lc-rs`. Exactly one of `openssl`, `ring`, or `aws-lc-rs` must be selected; the features are mutually exclusive. `openssl` remains the default.
* `key_tpm` and `key_kms` no longer force the `openssl` feature; they compile with any backend (`ring + key_tpm`, `aws-lc-rs + key_kms`, etc.).
* `ring + key_kms` is rejected at compile time with a clear error message; use `aws-lc-rs` instead.
* Crate-owned `EcPrivateKey` / `EcPublicKey` wrappers with a consistent public API across all three backends.

### Limitations of the `ring` backend

* ES512 / P-521 signing and verification is not supported; use `aws-lc-rs` or `openssl`.
* AES-192-GCM encryption is not supported; use `aws-lc-rs` or `openssl`.

### API notes

* `EcPrivateKey::from_pem` and `EcPublicKey::from_pem` are available on all backends but require the `pem` feature flag.

## 0.5.3
* Bumped `aws-sdk-kms` to 1.22
* Bumped MSRV to 1.71
* Updated docstrings to mention the need in Tokio runtime for non-local key
use-cases

## 0.5.2
* Bumped `serde_with` to 3.3
* Bumped `tss-esapi` to 7.5
* Bumped `aws-sdk-kms` to 1.20
* Bumped MSRV to 1.68

## 0.5.1
* Fixed serde build errors after update

## 0.5.0
* Support signing with an AWS KMS private key via the `key_kms` feature. (thank you @puiterwijk)
* Abstract Openssl operations (thank you @raoulstrackx)
* Update and declare MSRV to 1.58

## 0.4.0
* Abstract signing support: provide traits to abstract private and public keys.
* Support signing with a TPM-backed private key via the `key_tpm` feature.

## 0.3.0

* **Breaking change**: Use upper case acronyms as advised by clippy
* **New Feature**: COSE encryption is now available. Thank you @runcom for the patches.
* Allow access to CoseSign1 headers, to allow algorithms to use read and set them. Thank you @puiterwijk.
* Minor fixes and version bumps.

## 0.2.0

* Bump `serde_with` version.
* CBOR tags support: can add and verify tags on COSESign1.
* Use PKey instead of EcKey. Just an interface change, RSA not supported yet. (thanks @puiterwijk)
This will likely change again in the future to support https://github.com/awslabs/aws-nitro-enclaves-cose/issues/5.
* Implement std::error::Error for COSEError (thanks @puiterwijk)

## 0.1.0

Initial Release
