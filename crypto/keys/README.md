# Keys

This crate provides a generic API for interacting with asymmetric key systems for performing key exchange and digital signing operations. It provides a hierarchical set of traits which support:

* Public Keys
   * Pubkeys for Key-Exchange
   * Pubkeys for Digital Signing
* Private Keys
    * Privkeys for Key-Exchange
        * Privkeys for Ephemeral Key-Exchange
        * Privkeys for Reusable Key-Exchange
    * Key-pairs for Digital Signing
* Secure Hashing
* Distinguished Encoding (DER serialization)
* Fingerprinting (human-readable hash output)
* A `KeyExSystem` trait used to describe all the relevant types used .

The over-arching design borrows from the RustCrypto model of a "trait crate" and separate implementation crates for various algorithms. The design of the individual traits themselves borrows from the dalek model of removing cryptographic foot-guns from places they do not need to exist by leaning heavily on the type system.

This crate provides `KeyExSystem`-related implementations for X25519 and Ristretto key-exchange, and `SigningSystem`-related implementations for the Ed25519 EDDSA signature scheme. All of the actual cryptographic primitives live in dalek crates, this simply provides a syntactic sugar on top of them to support algorithm-independent implementations.

## Future Work

The most direct work which is required is deprecating the signing system in favor of the RustCrypto `signature` traits, splitting the X, Ed, and Ristretto types into separate crates, and bringing them all together by submitting this work to RustCrypto for eventual inclusion. This is intended to do two things:

1. Improve the rust cryptographic ecosystem
1. Reduce MobileCoin's burden as it relates to cryptography-related code maintenance.
