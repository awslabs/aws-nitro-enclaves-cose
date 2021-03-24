
# Changelog

## 0.2.0

* Bump `serde_with` version.
* CBOR tags support: can add and verify tags on COSESign1.
* Use PKey instead of EcKey. Just an interface change, RSA not supported yet. (thanks @puiterwijk)
This will likely change again in the future to support https://github.com/awslabs/aws-nitro-enclaves-cose/issues/5.
* Implement std::error::Error for COSEError (thanks @puiterwijk)

## 0.1.0

Initial Release
