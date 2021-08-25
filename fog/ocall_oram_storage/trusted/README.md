fog-ocall-oram-storage-trusted
=======================

This crate implements an `ORAMStorage` object which mediates the exchange of
memory blocks from the enclave to untrusted.

This is an alternative to setting the enclave heap very large to allow it to
store more data, and may avoid any drawbacks to the way that Intel's memory engine
works with linux paging. For instance, the untrusted side may try to bypass the OS
and do DMA reads and writes.

Trusted-side functionality
--------------------

The trusted side is required to *encrypt* data blocks that leave, and *authenticate*
them when they return.

- Each data block (4096 bytes) comes with a small metadata block (~64 bytes).
- Both data and metadata are encrypted using AES 256.
- Each data block holds "extended metadata" including a counter, and the hashes
  of its left and right children.
- The ciphertexts are hashed (see below for details) together with extended metadata
  to compute the hash for this block.
- When blocks return from untrusted, the hashes stored with parents are checked with
  the hashes computed with the children, and we panic if this check fails.
- The top level blocks stored with untrusted have their hashes stored in the trusted memory,
  and these must also be checked during checkout and updated during checkin. We panic
  if this check fails.

An important optimization is used:
- If the ciphertext metadata from untrusted is all zeroes, then we assume this is
  the first time we access the block, and pass all zero metadata and data back
  to the Oblivious RAM. Effectively, we lazily zero the data segments in blocks
  living untrusted memory memory, and dont require that we write encryptions of
  zeros to every memory cell at initialization.

Authentication design
---------------------

Authenticating the blocks that return to ORAM is nontrivial when an *active adversary* is considered
and replay attacks must be defeated.

Authenticated encryption which is semantically secure against an active adversary requires a nonce.
For background, see [Rogaway](https://web.cs.ucdavis.edu/~rogaway/papers/nonce.pdf).
When using AES, this nonce (also called "initialization vector") need not be uniformly random, but must never repeat for a given key.
If two different messages are encrypted with the same key and nonce, the adversary can learn the XOR of the plaintexts.

Typically, when two parties create an encrypted channel, the AES key is extracted from a shared secret
resulting from key exchange. Then the nonce is a counter which counts up from zero with each message sent over the channel,
ensuring that nonce reuse does not occur. The nonce might also be sent in the clear with the ciphertext,
so that if the adversary recieves messages out-of-order they can still decrypt them. If the nonce is sent in the clear with the message,
however, rather than being deduced by the recipient, then replay attacks become possible.

In our setting, the blocks of memory on which the ORAM algorithm is operating are fixed-size blocks
arranged as a binary tree. The algorithm loads a *branch* of the tree, manipulates the values in the tree,
and then stores them. This tree might be quite large, e.g. many GB. As an optimization, the top portion
of the tree may be stored in the heap in the enclave -- this is called "treetop-caching". The bottom portion
of the tree must be stored in untrusted memory. This important optimization is performed in [ZeroTrace](https://eprint.iacr.org/2017/549.pdf) for example.

In this context, replay attacks means, untrusted replaying old blocks when the enclave asks for data,
in an attempt to try to reset the state of the ORAM. The ZeroTrace paper points out that for recursive ORAMs (like we have), integrity verification
and preventing of replay attacks is important not only for guaranteeing integrity of data returned to the client, but also to protecting *the privacy of the query*.
A full replay attack against the entire state of the ORAM would allow an attacker to make a query and measure access patterns,
and compare with access patterns made in response to an earlier user query.

Concievably, the nonces (counters) for each block stored with untrusted could be kept in the enclave's trusted memory and not stored with the ciphertexts.
The main drawback of this is that as we make larger and larger ORAMs overall, we require more and more of the enclave's heap to do this. This is contrary
to the goal of a scheme like this, where we would like to have a bounded footprint in the SGX heap and use arbitrarily large untrusted memory without exceeding the limit.
But, if the nonces are not in trusted memory, and are instead stored with untrusted, they cannot be (themselves) encrypted, and must somehow be protected against tampering.

A series of works by Ren, Yu, Fletcher, van Dijk, and Devadas, considered this particular design question in connection to Path ORAM in secure processors.

- [Design Space Exploration and Optimization of Path Oblivious RAM in Secure Processors 2013](https://eprint.iacr.org/2013/076.pdf)
- [Integrity Verification for Path Oblivious RAM 2013](https://people.csail.mit.edu/devadas/pubs/integrity-hpec13.pdf)
- [Freecursive ORAM 2015](https://people.csail.mit.edu/devadas/pubs/freecursive.pdf)

They observe that since PathORAM always accesses its storage by loading an entire branch in a binary tree, a straightforward approach to integrity verification
is to view this tree like a Merkle-tree and compute a Merkle root hash to perform validation. These hashes can be computed over the ciphertexts to verify them
before anything else happens. Then, authenticated encryption is unnecessary, and we don't need
to use an AEAD like AES-GCM. They proceed from this idea to invent increasingly sophisticated and optimized designs, specifically for the secure processor setting.

However, for secure processors, they envision ORAMs with data items of size 64 bytes. When using something like SGX,
it makes much more sense to have ORAMs where the page size is like 4096 bytes. For them,
spending another 64 bytes per element to store Merkle hashes of children represents intolerable overhead,
and they go to great lengths to mitigate this.

In our regime, we aren't interested in having ORAMs with 64 bytes of data per item, we rather have blocks of size 4096.
We already have built-in metadata sizes of ~64 bytes (storing the identity of each value in the block and its destination leaf).
For us, an overhead of 64 bytes is completely acceptable, representing less than 2% overhead.
So we prefer to implement the "naive" Merkle tree idea and leave sophisticated optimizations to later work.

A more recent work of Sasy, Gorbunov and Fletcher, also reconsidered this, focusing directly on SGX. They described [ZeroTrace](https://eprint.iacr.org/2017/549.pdf)
in a paper and implemented it. They also chose to implement the Merkle tree integrity verification.

Their paper does not specify the precise details of how they hash blocks, but their open-source code can be [examined](https://github.com/sshsshy/ZeroTrace/blob/master/ZT_Enclave/ORAMTree.cpp#L46).
They are using AES for encryption, via the interfaces provided by Intel's SGX SDK, which will use the AESNI instructions, and they are using SHA256 as the hash function
to construct the Merkle tree.
Below, we describe in detail something which is similar in spirit, which meets the security goals described, and which uses
cryptographic primitives that Mobilecoin already relies on.

Cryptographic details
---------------------

For ORAM storage which must store a binary tree of `count` many data items of size `DataSize` and corresponding metadata items
of size `MetaSize`, we store in trusted memory:

- A 16 byte secret "aes_key"
- A 16 byte secret "hash_key"
- A "heap" ORAM storage object for the "top portion" of the tree, up to some "treetop caching limit" which is configurable.
  This heap ORAM storage object has the data and metadata parameters that our caller gave us
- A handle to untrusted storage for the "bottom portion" of the tree.
  This storage has data items of the same size, and metadata items of size `MetaSize + ExtraMeta`.
  The `ExtraMeta` provides space for us to place counters and merkle hashes needed for authentication.
- An array of 16-byte merkle hashes, associated to the (two children of) the leaves of the "top portion" of the tree.
  These are used to validate paths that are loaded from untrusted, and updated when a path is stored.

Some terms:

- The "block index", as in cited works, refers to the index of a particular block within the tree.
  This is also the number the user of this API uses to refer to a particular block.
- The "block counter", as in cited works, refers to a counter associated to each block, which we increment
  whenever we load and subsequently store the block. This is used to form the nonce used when encrypting.
  This ensures that the ciphertexts change from the adversary's point of view even when we don't change the plaintext.

When a block

--------  ------------
| data |  | metadata |
--------  ------------

is checked back in, and previous block counter value was `block_ctr`,
we compute a 16 byte `aes_nonce` by concatenating two 64-bit numbers:

```
block_idx || block_ctr
```

to obtain an IV suitable for AES 128.

Then we encrypt `data || metadata` using AES-ctr with key `aes_key` and nonce `aes_nonce`,
obtaining `e_data` and `e_metadata` in place.


The data sent to untrusted for storage is `e_data`, and `extended_metadata`, where the `extended_metadata`
has the layout:

---------------------------------------------------------------
| e_metadata | block_ctr | left_child_hash | right_child_hash |
---------------------------------------------------------------

That is, `block_ctr`, `left_child_hash`, and `right_child_hash` are not encrypted,
but are under the merkle hash.
These values are deducible by the untrusted adversary anyways based on information they can see.

The hashes `left_child_hash`, `right_child_hash` are computed by hashing

```
"domain-sep" || hash_key || e_data || block_idx || extended_metadata
```

These hashes are 16 bytes. The reasoning here is, this is the same as the mac length for
Aes128Gcm -- we don't need to have a stronger security parameter than our encryption.
With 16 byte hashes, we don't expect collisions due to birthday paradox, until roughly
the same time that an 8 byte integer overflows, which matches when the `block_ctr` would
overflow.

We compute these hashes using `blake2b`. A future revision may use `blake2bp` to take advantage
of instruction-level parallelism, once a good rust implementation of this exists.

For nodes that are leaves and have no children, `left_child_hash` and `right_child_hash`
are taken as the all-zeroes strings.

For internal nodes, if the left or right child is not yet initialized, the all-zeroes
string is taken as its hash.

Blocks are always checked back in in a bottom-up fashion so that the `hash_..._child` fields
can be updated when writing the parent.

When a block is checked out,

----------  ---------------------
| e_data |  | extended_metadata |
----------  ---------------------

first, if we previously checked out its left or right child, we check (in constant-time)
if the corresponding field in `extended_metadata` matches the hash we compute for that data,
and if not, we reject.

If this block is a block on the boundary of the "treetop", then we compute the appropriate
hash of its `e_data` and `extended_metadata` and validate that against expected merkle root,
testing in constant time and rejecting a mismatch.

If not rejected, we first check if the `extended_metadata` bytes are all zeroes. If so,
then untrusted is telling us this is the first time we checked this out, so we take
`data` and `metadata` to decrypt as zeroes, and proceed without actually decrypting anything.

Otherwise, compute `aes-nonce` for this block and decrypt `e_data` and `e_metadata` in-place.
We store `block_ctr, left_child_hash, right_child_hash` on the side, until check-in occurs, and make
appropriate changes to these values at that time, before storing them with untrusted.

Security analysis:
------------------

The hash computed for a block contains both the `e_data`, the `e_metadata`, and the `block_id`,
and the `block_ctr`, and the hashes of the two children. These are all fixed-size fields, so
there is no avenue for malleability, and the adversary cannot change any of these fields without
detection if the hash function is collision resistant. The trusted merkle roots are stored in trusted
memory, so those cannot be modified (or even accessed) unless SGX is compromised.

Because the `block_ctr` is incremented each time, and it is under the hash, replay attacks are impossible,
as replaying an old ciphertext would require that the parent records the hash of the old ciphertext in its
extended metadata, and chanigng this would change the hash of it, requiring updates to its parent, etc.

Keyed blake2b is [intended by its authors](https://blake2.net/) to be used as a MAC or a PRF.
Being able to supply a secret key that untrusted never sees means that this hash may be collision-resistant
even if unkeyed blake2b is not.

Because the aes-nonce is `block_idx || block_ctr`, the nonce will never be the same for different blocks, and for a single block,
it can only repeat if `block_ctr` overflows, which is a 64-bit number.

In the algorithm as described, we decrypt a block using `aes-ctr` before checking its hash against that of the parent.
When the data are variable-sized, in general this can open up problems, like a padding oracle attack. However, in our case, all our
data are fixed size, there is no padding up to a block-size, and we can assume that the `aes-ctr` implementation is constant-time -- our code will actually use AESNI
instructions in the enclave.

Future Directions:
------------------

In review, it was suggested that instead of implementing this with separate primitives for encryption (AES) and authentication (Blake2b),
we should try to use an AEAD here, ideally AES-GCM or a variant.

In what follows we use terminology for AEAD's matching the [API description in the rust aead crate](https://docs.rs/aead/0.3.2/aead/trait.AeadInPlace.html).

In this version of the scheme:
- The nonce would be as before `block_idx || block_ctr`.
- The buffer which is encrypted / decrypted is `data || metadata`, that is, the client-provided data and metadata.
- The aad (additional associated data) is the `block_ctr || left_child_hash || right_child_hash`, that is, the portion of `extended_metadata` which is not encrypted.
- The mac produced by AES-GCM is treated as the hash that we were computing earlier. `left_child_hash` and `right_child_hash` and `trusted_merkle_root` would refer to these mac values. The `hash_key` variable goes away.

It is somewhat unconventional to build a Merkle tree where the hashes are actually MAC values from an AEAD, but since the security requirement of a MAC requires it to function as a PRF,
it is suitable for this purpose.

This AEAD-based ORAM memory interface idea seems novel and elegant, somewhat reducing the number of cryptographic components in the described design.

The two major implementation difficulties with the AEAD approach are are:
- While the AES IV is 16 bytes, the AES-GCM IV is only 12 bytes. Neither of the values `block_idx` and `block_ctr` can be comfortably restricted to 4 bytes.
  - An implementation might split the difference and truncate to 6 bytes, which might be okay.
  - Alternatively, the implementation might hash `block_idx || block_ctr` down from 16 bytes to 12 bytes.
    In this case the `hash_key` variable would likely come back.
  - Another approach is to use `AES-GCM-SIV`, so that the initialization vector depends on the nonce, message, and aad.
    Since `block_ctr` is part of the aad, it could be shortened to 4 bytes, only when calculating the nonce for SIV. This runs against guidance in
    [RFC 8452](https://tools.ietf.org/html/rfc8452#page-10) which is to use SIV as a defense-in-depth against nonce reuse, rather than rely on it.
  Of these options, the hash-to-nonce approach seems least flawed, but it brings back some of the complexity which one would hope to eliminate with the AEAD in the first place.
  A simpler approach might be to use an AEAD with a 16 byte nonce, rather than AES-GCM. Some authors consider the 12-byte nonce to be a design flaw in AES-GCM.
  Unfortunately there are not any alternative AEAD's like this available in `RustCrypto` right now -- we really want one based on AES so that we can use AESNI instructions
  in the enclave, which will be much faster than the alternatives.
  We further comment that `AES-GCM-SIV` seems poorly suited to this use-case. SIV is designed to handle situations when multiple parties are encrypting using the same key.
  Nonces can be chosen randomly, but due to concurrency the possibility of nonce reuse cannot be completely eliminated. Our situation doesn't have this property -- only one
  particular enclave is encrypting and decrypting here, and all these operations are strictly serialized. SIV is also slower than straight `AES-GCM`, because it requires scanning
  across the data an additional time in order to fold it into the nonce.
- The rust AEAD interface requires that the buffer that is encrypted be contiguous in memory, so, `data || metadata` must be copied into a temporary position on the stack where they are adjacent in memory.
  However, `data` is very large and a performant implementation of the encrypted memory interface must avoid copying `data` unnecessarily.
  - To fix this, we would have to patch the `aes-gcm` crate and offer a new lower-level API in place of `encrypt_in_place_detached` and `decrypt_in_place_detached`, which
    does not require the buffer to be contiguous in memory, and instead takes e.g. `Iterator<Item = &[u8]>` or similar.
  - Alternatively, we could invoke the AEAD interface twice, encrypt `data` and `metadata` separately, producing twice as many macs and requiring twice as many nonces.
    But this complicates the implementation, essentially doubling the amount of code and the number of serialized data items, doubling our overheads,
    and makes the whole thing harder to think about, and harder to maintain. So this seems like a poor direction.
  It is worth noting that `AES-GCM` is likely faster than separated AES and Blake2b, because an optimized AES-GCM implementation is [supposed](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
  to interleave the AES computations with the GCM computations and avoid stalling the pipeline. However, the rust version [doesn't do this right now](https://github.com/RustCrypto/AEADs/blob/master/aes-gcm/src/lib.rs#L242).

We note that the AEAD-based design doesn't have any additional security properties that the earlier design doesn't have,
and the earlier design doesn't use any cryptographic primitives that we don't already rely on.

Patching `aes-gcm` right now is prohibitive in terms of engineering resources, so we don't implement this alternative version of the scheme.
However, we could implement it anyways, with the copy, and benchmark it against the version based on the `Blake2b` Merkle tree.
It's possible that it may be faster despite the copy, depending on quality of implementation.

We note that the alternative implementation could in the future be dropped in without changing any of the APIs -- it would not change the result from the ORAMStorage user's point of view,
nor does it require an API change at the trusted-untrusted boundary, since untrusted doesn't participate in any of the encryption or validation.

Hopefully this discussion clarifies the features of the earlier, non-AEAD approach.
