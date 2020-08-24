mc-crypto-sig
=============

This crate provides digital signatures using the Ristretto elliptic curve points
in a manner that meets our needs, wrapping the Schnorrkel API, and using
types compatible with the keys crate.

NOTE: The code in this crate still needs more review.

The API is roughly:

```
sign_message(signing_context: &[u8], private_key: &RistrettoPrivate, message: &[u8]) -> Signature
verify_signature(signing_context: &[u8], public_key: &RistrettoPublic, message: &[u8], sig: &Signature) -> bool
```

Putting this low-level code in its own module makes it easier to reuse
and to audit, and hides sensitive cryptographic details from the users of the API.

The main differences are:

- The signature is completely deterministic, like RFC6979 and ed25519, and `sign_message`
  does not take an RNG as it does in Schnorrkel. Instead, in order to use Schnorrkel without
  patching it, we create a seeded RNG using a seed derived in a manner similar to the nonce
  in RFC6979 and ed25519.
  -  This is very important for MobileCoin because we want for the public address to be
     completely deterministic from the private account key, so that we can detect malicious
     tampering easily.
- We do not use the "minisecret key" or the "minisecret key expansion" from Schnorrkel.
  - This will create serious problems for MobileCoin, because we want to be able to use
    exactly the public keys that are already in the public address to verify the signatures.
    Otherwise it significantly increases the size of the public address.
  - We believe that the "minisecret key expansion" in Schnorrkel is not strictly necessary.
    We think that deriving the nonce for the signature in a pseudorandom manner from the private
    key and the message, meets all the security requirements.

Security statement
------------------

Classical Schnorr signatures are known to be secure when the *commitment* that the prover
makes (also called "nonce" in the literature) is truly random every time.
However, if a nonce is ever reused, the private signing key is immediately revealed to the
adversary. This caused many high profile security breaks, when the PRNG used for the nonces
didn't produce truly random nonces.

In [RFC6979](https://tools.ietf.org/html/rfc6979), [ed25519](http://ed25519.cr.yp.to/ed25519-20110926.pdf),
and much later work, the idea was that the signature should be *deterministic*,
and the nonce should be *pseudorandomly generated* from the message and the private key.
If a PRF is used to compute the nonce, then the nonce is hard to distinguish from random even if
the messages that are signed are adversarially chosen.

For this generation, we can think of the private key as a source of entropy for a *secret seed* to the PRF.
We note that when secret entropy like this is available, then PRFs exist under weak assumptions, and do not require the "random oracle model" for hash functions.
(See for instance [Chapter 3.8 in Pass "A Course in Cryptography"](https://www.cs.cornell.edu/courses/cs4830/2010fa/lecnotes.pdf)
It is known that PRFs of this form exist if cryptographic Pseudorandom Generators (PRGs) exist. [Hastad, Impagliazzo, Levin and Luby famously showed](http://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.185.988)
that PRG's exist if and only if one-way functions exist. This is a necessary assumption for semantically-secure symmetric key cryptography.)

In the `sign` function in this crate, we take as an assumption that a Merlin Transcript's [`challenge_bytes`](https://docs.rs/merlin/1.0.3/merlin/struct.Transcript.html#method.challenge_bytes) method is a PRF.

The [ed25519 manuscript]((http://ed25519.cr.yp.to/ed25519-20110926.pdf)) from 2011-09-26 has remarks in the section "pseudorandom generation of r", where
`r` is the nonce, which support this idea:

> This idea of generating random signatures in a secretly deterministic way, in particular obtaining
> pseudorandomness by hashing a long-term secret key together with the input message, was proposed by
> Barwood in [9]; independently by Wigley in [79]; a few months later in a patent application [57]
> by Naccache, M’Ra ̈ıhi, and  Levy-dit-Vehel; later  by M’Ra ̈ıhi, Naccache, Pointcheval, and Vaudenay
> in [55]; and much later by Katz and Wang in [47]. The patent application was abandoned in 2003.
>
> Standard PRF hypotheses imply that this pseudorandom session key `r` is indistinguishable from a
> truly random string generated independently for each `M`, so there is no loss of security.
> Well-known length-extension properties prevent secret-prefix SHA-512 from being a PRF, but also do
> not threaten the securityof Ed25519-SHA-512, since `r` is not visible to the attacker. All remaining
> SHA-3 candidates are explicitly designed to be PRFs, and we will not hesitate to recommend
> `Ed25519-SHA-3` after SHA-3 is standardized. It would of course also be safe to generate `r` with
> a cipher such as AES, combined with standard PRF-stretching mechanisms to support a long input;
> but we prefer to reuse `H` to save area in hardware implementations.

We point out that Merlin Transcripts implement a subset of the STROBE protocol, which states in [STROBE Protocol Framework](https://strobe.sourceforge.io/),

>  Strobe is based on SHA-3, or rather Keccak-f and cSHAKE (draft NIST SP 800-185).

We prefer using Merlin transcripts to produce the nonce here, instead of a cryptographic hash function. Schnorrkel already relies on Merlin -- it has several benefits, like automatic domain separation and framing. By using this here instead of a hash function like SHA3, we can reduce the total number of cryptographic assumptions underpinning this signature scheme.

When using Merlin for this, instead of assuming that a hash function has the secret-prefix-PRF property, we assume that the following pseudo-rust function does, for any particular merlin transcript, where the private_key argument is identified with the secret prefix:

```
fn produce_nonce(transcript, private_key, message) -> [u8; 32]
    transcript.append_message("private", private_key);
    transcript.append_message("message", message);
    let mut nonce = [0u8; 32];
    transcript.challenge_bytes("nonce", &mut nonce);
    nonce
}
```

This assumption can be justified if we believe that the STROBE "PRF" operation functions as a PRF once STROBE has been keyed. We refer the reader to https://strobe.sourceforge.io/papers/strobe-20170130.pdf for a discussion of the usage and security properties of STROBE. For more discussion, see also the documentation around Merlin: https://merlin.cool/transcript/ops.html.

With this assumption in hand, we can say that signatures created this way are hard to distinguish from signatures created where the nonce is truly uniformly random, even if the messages that are signed are adversarially chosen. So, if Schnorrkel is secure when the nonces are truly random and the RNG is the OS-RNG, or, when the nonce is created using the mini-secret-key expansion, then this should also be secure.

Rng required by Schnorrkel
--------------------------

Schnorrkel API deviates from RFC6979 and ed25519 in requiring the signer to provide a CSPRNG, which they
generally want to be the OS rng (although it can perhaps be a different RNG via the `attach_rng` API).
Other Schnorr signature implementations do not require an RNG at all -- deterministic signatures generally means that all the entropy for the
signature comes from the private key.

Because it is a requirement for us to have actually deterministic signatures,
we produce this RNG from a seed, using the nonce. We use `rand_hc` which is a cryptographic RNG,
and so we can conceal this detail from the caller. Thus, the API that this crate provides is closer to
RFC6979 and ed25519.
