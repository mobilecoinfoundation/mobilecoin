ECIES
=====

Provides a simple rust interface for doing asymmetric key cryptography,
using the ECIES encryption scheme.

Uses the `curve25519_dalek` types as keys (`Scalar` and `RistrettoPoint`).

This crate is `no_std`.

`encrypt(rng: RngCore::Rng, key: CurvePoint , plaintext: &[u8]) -> Vec<u8>`
`decrypt(key: CurveScalar, ciphertext: &[u8]) -> Result<Vec<u8>, ()>`

In order to work, the decryption key `a` must match the encryption key `A` via
`A = a * G`, as in everything else. Any key generation mechanism consistent
with this is fine.

Implementation
--------------

At present revision we are implementing the interface using ECIES scheme:
- During encryption we perform DH against the public key (creating a Pubkey of
  our own), followed by a KDF of the resulting shared secret, to get input to
  the AES block cipher. The public key that we generated, and the block cipher
  output, form the ciphertext.
- During decryption we read the pub key first, use the private key to recover
  the shared secret, and then decrypt the block cipher output.

It's possible that we should actually be using x25519 crate directly.
However, it seems to me that that would require using MontgomeryPoint instead of
RistrettoPoint, and we seem to be trying to use RistrettoPoint in most places,
e.g. for cryptonote. So I'm trying to follow that lead.
