digestible
==========

`Digestible` is a trait that can be used to specify how an object can be cryptographically
hashed in a secure way.

Specifically, this means, I have a structured object e.g. a Block in my blockchain, which
I want to compute a Sha256 hash of. Naively, I could serialize it and then hash the result,
but this involves copying a lot of bytes around. I could derive `std::hash::Hash`,
but `Hash` only supports an output of `u64` and not a full Sha256 output. Moreover, `Hash`
doesn't include any domain separation or protection against length extension attacks.

Background
----------

For background, the following discussions explain why `Hash` is not adequate / should not be
extended to try to cover this use-case:

> https://github.com/RustCrypto/traits/issues/13
>
> https://github.com/RustCrypto/hashes/issues/29
>
> https://github.com/RustCrypto/utils/issues/2
>
> https://crates.io/crates/digest-hash
>
> As it stands now, the current recommendation from the RFC you mentioned boils down to "use STROBE", which is also not algorithm agnostic.

We built `Digestible` because we think it's the simplest thing that meets our needs.

We use the `Digest` trait from the `digest` crate which has been embaced by `RustCrypto`
to model a generic cryptographic hash function.

Goals
-----

`Digestible` is a trait that can be derived on your structs.

`Digestible` attempts to ensure that if you use a secure hash function (implementing trait `Digest`),
then an attacker will not be able to produce an instance of a struct in your program that has the same hash
as another instance of a struct in your program unless they are identical. (Because some padding bytes will
be different if they are not the same type, and all of the bytes of the struct will be used.)

(Here, we are really only interested in structs that form the basis of a protocol or serialization format.
We're not interested in adding magic to hashes of [u8; 32] or making sure that a [u8; 32] doesn't have the
same hash as GenericArray<u8; U32>.)

`Digestible` attempts to ensure that digests are endian agnostic.

`Digestible` introduces little-to-no performance penalty, and does not make dynamic memory allocations.

`Digestible` is `no_std` compatible, and has optional integration with `alloc` crate.

Differences with `digest-hash`
------------------------------

Our crate is similar at a glance to `digest-hash` but it has a few major differences

(1) We insert bytes depending on the struct name and between members, `digest-hash` does not,
    so it doesn't achieve our goals.
(2) `digest-hash` does not provide a derive macro. But implementing the trait is sensitive,
    and if implemented by hand, probably requires review by a cryptographer. By providing
    `derive(Digestible)`, we reduce the opportunity for mistakes and make it less onerous to use
     in a large team.
(3) `digest-hash` supports configurable endianness, but we don't want or need this.
(4) `digest-hash` doesn't support a bunch of core types that we need like `Vec<T>`, `Option<T>`,
    and so we would need to patch or wrap everything in newtypes, and then ourselves add things like
    "hash the length of the vec" in order to proect against length extension attacks.

Finally we think the long term goal of basing `digest-hash` on `serde` is not a great idea, as `serde` is
extremely complicated, and we are not actually interested in serialization, just hashing.
It's far simpler to just write our own proc macro that does the thing that we need -- `digestible_derive`
is only about one hundred lines of code at time of writing, and with no dependence on `serde`, we are free
to uprev serialization libs without worrying about any interaction with `digestible` trait, and to e.g. build
our SGX enclave without any dependency on `serde`.
