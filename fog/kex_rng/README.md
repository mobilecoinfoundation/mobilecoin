## fog-kex-rng

This crate provides a convenient interface for creating PRNG's seeded by a shared secret, using a key exchange algorithm.
It also allows for wire-stable formats representing the ephemeral key that is sent (`KexRngPubkey`), and the `KexRng` itself (`StoredRng`).

The lowest level trait provided is `KexRngCore`, and the highest level is `KexRng`.

These traits are fully generic over the Kex algorithm. The versioning strategy is flexible enough to allow that
different RNG algorithms and differently sized outputs can be used within one `VersionedKexRng`.

The paradigm here is that the client has a static public key, and the server creates a private key
and produces a shared secret and counter which are used with a PRF to create the random sequence.
The server also publishes a KexRngPubkey that the client can use with their private key to reproduce the RNG.

The client generally uses `VersionedKexRng` which has a high-level API, allows for versioning of the RNG algorithm, and serialization of the RNGs.
The server has a more stripped down representation, where the shared secret is separated from the counter, because this greatly
reduces storage overheads in the server if the server's private key can be reused.


### Quickstart

The basic usage works like this.
- Client has a public key and sends it to a server (by some means)
- Server creates a private key. Server creates a shared secret by key exchange.
- Server chooses a `KexRngCore` implementation, and gets outputs by passing it the shared secret and a counter value.
  (This low-level interface is used to reduce storage pressure on the server to just the counter.)
- Server publishes a `KexRngPubkey`, containing the public key corresponding to server's private key, and the version number of `KexRngCore` implementation.
- Client recieves `KexRngPubkey` and uses `VersionedKexRng::try_from_kex_nonce` to produce the RNG object from the `KexRngPubkey` and their private key.
  This RNG will then produce the same sequence of outputs that the server produced, and it is hard for anyone who doesn't have the Client's private key to achieve this.

The `KexRngPubkey` records are durable, versioned, and can be stored indefinitely. As long the client retains their private key,
they will be able to reconstruct the `VersionedKexRng` objects correctly.

The server should usually pick a specific version like `KexRng20201124`, so that new versions can be added without immediately creating
a breaking change. Then the clients can have a chance to upgrade before the server moves to the new version.

### Properties

For an adversary who doesn't know the shared secret, the output of the KexRng is expected to be
computationally indistinguishable from a sequence of uniformly random 16-byte values, at a 128-bit security level.

#### LatestKexRng

LatestKexRngCore(KexRng20201124) uses Blake2b to hash the shared secret together with the counter value.
A domain separating prefix is also used.
Then we truncate the output to 16 bytes.

Here, we are assuming that Blake2b has the "secret-prefix PRF" property.

This property means that if we choose a secret key `k` and give an adversary black box access
to `f(x) := Blake2b(k, x)` it is hard for them to distinguish this black box from a truly random function,
even if they can make query the function at an adversarially chosen sequence of adaptive queries `x`.

(We note that for our purposes, we don't need to allow the inputs to be chosen arbitrarily, it's
enough to consider only consecutive inputs counting up from 0.)

For more discusison of this PRF hypothesis, see the `mc-crypto-sig` crate documentation, and quoted
paragraph from ed25519 manuscript [9] with the heading "pseudorandom generation of r".

We point out that Blake2b was one of the SHA-3 finalists, all of which are expected to have this property.

### Design considerations

We chose to build KexRng around a PRF with a fixed-size output.

Alternative approaches might include:
- Use a MAC, since the security property of a MAC is the same as the security property of a PRF.
- Use a block cipher like AES128, which should model an ideal block cipher, and also yield a PRF if the secret is used as the key.

The main drawback of these two approaches is that usually, a MAC or a block cipher requires a key that is uniformly distributed,
but our shared secret is an elliptic curve point. The standard way to deal with that is to put the shared secret through something
like HKDF to "smooth it out" and make it uniformly distributed. But then you are hashing the shared secret twice just to get there.
At that point it's not clear why you don't just use the hash and skip the MAC / block cipher. That's what we do in present revision.

#### Why not use a standard CSPRNG like ChaCha20?

We could have tried to use a traditional CSPRNG like ChaCha20 [6, 7].
We also could have tried to use a KDF chain like described in [1, 2].

The drawbacks of these versions are that they require a larger memory footprint in the server
for a similarly good CSPRNG period and 128 bit security level.
ChaCha20 requires 64 bytes, and a KDF chain would require 32 bytes.
A construction based on sponge functions would also require 32 bytes, according
to analysis in [8].

The PRF version, when using a static private key for the server, requires only 8 bytes per RNG supported,
since we can reconstruct the shared secret every time we have to use the RNG in our intended use-cases.

Basically, we are optimizing for small memory footprint on the server instead of bytes/cycle performance.
The reason this makes sense is that in intended use case, the counters are stored in an oblivious RAM table,
and the performance of that is the bottleneck, so reducing the footprint of the RNG's is the best thing for
overall performance.

### References

[1] "A model and architecture for pseudo-random generation with applications to /dev/random." (Barak, Halevi 2005) http://eprint.iacr.org/2005/029
[2] The Double Ratchet Algorithm (Marlinspike, 2016): https://signal.org/docs/specifications/doubleratchet/
[3] Cryptography in Nacl (Bernstein, 2009): https://cr.yp.to/highspeed/naclcrypto-20090310.pdf
[4] RFC7693 - Blake2 (J-P. Aumasson, 2015): https://tools.ietf.org/html/rfc7693
[5] RFC5869 - HKDF (Krawczyk, Eronen, 2010): https://tools.ietf.org/html/rfc5869
[6] RFC7539 - ChaCha20 and Poly1305 (Nir & Langley citing Bernstein, 2015): https://tools.ietf.org/rfc/rfc7539.txt
[7] rand_chacha, standard rust implementation of ChaChaRng: https://docs.rs/rand_chacha/0.2.2/rand_chacha/struct.ChaCha20Core.html
[8] The sponge and duplex constructions (Team Keccak - 2011): https://keccak.team/sponge_duplex.html
[9] ed25519 manuscript 2011-09-26: http://ed25519.cr.yp.to/ed25519-20110926.pdf
