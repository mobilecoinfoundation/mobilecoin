McCryptoBox
===========

Provides a simple rust interface for doing authenticated asymmetric key cryptography,
using the Ristretto group.

Quick Start
-----------

To use, first instantiate the `VersionedCryptoBox` object.

If possible, when encrypting, negotiate a version
using `VersionedCryptoBox::select_version`, to ensure compatibility with the recipient.
Otherwise you can `default()` to the latest version.

To encrypt or decrypt, use the `CryptoBox` trait and exercise the `encrypt` or
`decrypt` APIs or their variations. (You need Ristretto curve points for the default object.)

Encryption takes an rng, a public key, and a message, and produces a "cryptogram",
which includes the ciphertext, an ephemeral public key, an aes mac value, and a small versioning tag.

Decryption takes the private key and the cryptogram and repoduces the message.

Properties
----------

The `VersionedCryptoBox` object aims for semantic security at at least 128-bit security level,
and non-malleability of the cryptograms. The primitives used at current version are:

- Ristretto elliptic curve (`curve25519-dalek` crate) for key exchange
- HKDF + Blake2b for the KDF step
- AES-256-GCM for authenticated encryption

The wire-format is intended to be stable, with forwards and backwards compatibility
if we must change the primitives.

Extensibility
-------------

Although `VersionedCryptoBox` uses specific primitives, the traits and components
in this crate could be used to instantiate any variation of Cryptobox.

- `CryptoBox` trait is generic over a `Kex` and supports any footer size
- The `HkdfBox` object is generic over a `Kex`, a `Digest`, and an `Aead`.

Thus, you could easily use this to assemble your own CryptoBox-like scheme, with
different elliptic curves and ciphers, or to write code that is generic against
such a scheme.

The security statement for this assembly is roughly as follows:
- If the `Kex` is well-chosen, then the shared secret that results is hard for
  an adversary to predict, or even, distinguish from a random nonce.
- If `Digest` is well-chosen, then `Hkdf<Digest>` 
  and derives from the shared secret, a key and IV that are hard to distinguish
  from uniformly random bytes.
- If the key and IV are such, then a suitable `Aead` provides confidentiality and
  integrity of the message.

The security parameter here will be the weakest of the components that are used.

Comparison to related schemes
-----------------------------

This can be compared with many "hybrid public key encryption" systems that have
been proposed in the literature or exist in established cryptographic libraries:

- DHIES (Abdalla, Bellare, Rogaway, 2001) [1]
- ECIES (SECG-Sec1 v2.0, 2009, IEEE P1363a published 2004-09-02 withdrawn 2019-11-07) [2]
- NaCl Cryptobox (Daniel J. Bernstein, Tanja Lange, Peter Schwabe, latest 2019) [3]

(This list is not exhaustive. Skip to the bottom for links to these and other references.)

All these schemes have in common that there is a Diffie-Hellman key-exchange element,
followed by a KDF-step extracting suitable key material from the shared secret, followed by an
AEAD implementation.

The current version of McCryptoBox conforms quite closely to the diagram and explanation
of ECIES in Svetlin Nakov's [7] "Practical Cryptography for Developers":
https://cryptobook.nakov.com/asymmetric-key-ciphers/ecies-public-key-encryption

However, none of the standardization efforts related to ECIES have specified Ristretto
as an elliptic curve that could be used in the scheme. All of these standardization
efforts are much older than the Ristretto group.

NaCl cryptobox is specified [3] as `curve25519xsalsa20poly1305`, that is, to use
curve25519 + salsa20 + poly1305. However, it is mentioned as a TODO to also implement
`crypto_box_nistp256aes256gcm`, that is, using the nistp256 curve and
AES-256-GCM for authenticated encryption.

In "Cryptography in NaCl" [4] it is explained that in the current version of cryptobox, curve25519
is used for key exchange, then Hsalsa20 is used to extract entropy from the shared secret.
Hsalsa20 is then used as a CSPRNG and this pseudorandom sequence is xor'd with the plaintext
to achieve encryption. Poly1305 is used to produce a MAC.

So, `mc-crypto-box` can be viewed as a variation on NaCl cryptobox.
For technical reasons, it is a requirement in Mobilecoin to have a version of
cryptobox based on the Ristretto group.

Choice to use random nonces derived from key exchange
-----------------------------------------------------

In NaCl cryptobox, the nonce used to drive authenticated encryption is NOT derived
exclusively from the shared secret, as it was in all previous IES designs. Instead,
there is a nonce value which is input from the user, and users are expected to choose
nonces such that a nonce is never reused when sending to a particular recipient.

NaCl cryptobox documentation specifies that randomly generated nonces have negligible
chance of collision, but that counter-based nonces work also in their design and can
moreover prevent replay attacks.

It is explained in "The security impact of a new cryptographic library"[5] that part of
the idea with the nonces is that if Alice wants to send a massive payload to Bob
using NaCl cryptobox, she would do key exchange once (using the two-step cryptobox
API), then break her payload into 4k-sized chunks (depending on transport layer),
and apply cryptobox to each of these chunks, counting up the nonce in sequence.
This ensures that each packet that Bob recieves has its own mac -- there is not one
mac value for the entire payload, and it ensures that we don't have to do an elliptic
curve operation once for each packet, which is what a naive implementation would do.

In our use-cases right now, we have no need for sending very large messages this way,
and it would present operational difficulties to establish and preserve information
about these nonces.

Choosing exclusively random nonces derived from key exchange avoids these practical
operational concerns and simplifies the API.

In a future revision, we may wish to
extend the API to support the two-step construction + user-provided nonce idea.

Comparison to `aead` crate
--------------------------

The API is meant to be not too different from the rust `aead` crate [8], but it can't
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
- CryptoBox is public key cryptography -- the encrypt function must take a public key, and the
  encrypt function must take a private key.
- The nonce is derived from the shared secret using the KDF, it's not an input from the user.
- The AEAD trait emits only the MAC value from `encrypt_in_place_detached`. CryptoBox must
  emit the ephemeral public key and the MAC value. We choose to concatenate these
  into a "footer" of fixed size with a fixed format. This is okay because the cryptogram is meant
  to be opaque to the user anyways.

References
----------

1. DHIES (Abdalla, Bellare, Rogaway, 2001): https://web.cs.ucdavis.edu/~rogaway/papers/dhies.pdf
2. SECG-Sec1 v2.0 (Certicom Research, 2009): http://www.secg.org/sec1-v2.pdf
3. NaCl Cryptobox (Bernstien, Lange, Schwabe, 2019): https://nacl.cr.yp.to/box.html
4. Cryptography in Nacl (Bernstein, 2009): https://cr.yp.to/highspeed/naclcrypto-20090310.pdf
5. The security impact of a new cryptographic library: (Bernstein, Lange, Schwabe, 2012): https://cr.yp.to/highspeed/coolnacl-20120725.pdf
6. Authenticated Encryption in the Public-Key Setting (Jee Hea An, 2001): https://eprint.iacr.org/2001/079
7. Practical Cryptography for Developers (Svetlin Nakov, 2018): https://cryptobook.nakov.com/asymmetric-key-ciphers/ecies-public-key-encryption
8. Rust Aead crate: https://docs.rs/aead/0.2.0/aead/
9. Uses of EC integrated encryption scheme in practice: https://crypto.stackexchange.com/questions/51203/is-ec-integrated-encryption-scheme-used-in-practice
