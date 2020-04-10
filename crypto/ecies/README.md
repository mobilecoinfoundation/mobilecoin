ECIES
=====

Provides a simple rust interface for doing asymmetric key cryptography,
using the ECIES encryption scheme.

- Ristretto elliptic curve (`curve25519-dalek` crate) for key exchange
- HKDF<Blake2b> for the KDF step
- aes-gcm for authenticated encryption

The API is meant to be not too different from the rust `aead` crate, but it can't
be exactly the same as that, for several reasons.

- The API requires to implement low-level functions`encrypt_in_place_detached`
  and `decrypt_in_place_detached`: https://docs.rs/aead/0.2.0/aead/trait.Aead.html#required-methods
- These take the plaintext as a mutable buffer and transform it in-place to the ciphertext
- The message authentication code requires additional space in the "actual" ciphertext payload,
  so it gets returned as a "detached" byte buffer from the `encrypt` function, and the `decrypt`
  function requires a reference to it.
- High-level helpers are implemented in terms of this, which create a wire-format where this tag
  just gets stuck at the end of the ciphertext buffer.

There are a couple of major differences in our setting:
- ECIES is public key cryptography -- the encrypt function must take a public key, and the
  encrypt function must take a private key. We could abstract this using the `keys` crate but
  at present revision we haven't gotten around to that.
- The aes nonce is derived from the shared secret using the KDF, it's not an input from the user.

Otherwise, it can implement almost the same API as the `aead` crate, just with the public/private keys
instead of the nonce.

We also made a decision that since `encrypt` algorithms don't fail, they should not return a `Result`
type -- the only errors that can actually happen are buffer-size mismatch errors that should be caught
at build time using `generic_array`. ECIES encryption at a high-level only requires, ephemeral key generation,
key exchange, running a KDF, and running something like aes-gcm, and none of those algorithms has the possibility
of failure. So if the final API incidates the possbility of failure, that seems to be accidental complexity.
