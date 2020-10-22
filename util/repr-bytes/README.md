mc-util-repr-bytes
==================

`mc-util-repr-bytes` provides a low-level trait representing an object which
has a fixed-width canonical representation as bytes. This is intended to abstract
the differences between different kinds of cryptographic keys.

For instance, a public key from `x25519-dalek` crate can implement `AsRef<[u8]>`
via its `as_bytes()` function [4], but a `RistrettoPoint` from `curve25519-dalek`
cannot -- only `CompressedRistretto` has `as_bytes()`. The `RistrettoPoint` must be
"compressed" before the bytes can be accessed, and then it cannot return a reference
to the slice, because that would be a reference to a temporary [3]. Because compressing
and decompressing Ristretto points involves finite field operations, this is expensive
and cannot be done constantly.

In crates like `mc-crypto-keys` we want to create generic interfaces for
key exchange [5]. This can be used as a building block for crates like `mc-crypto-noise` [7],
and `mc-crypto-box` [8], which can in principle be implemented for any elliptic curve.

Using generic implementations of cryptographic algorithms has numerous advantages:
- Separating the sensitive, cryptographic parts, from the parts which are
  just shuffling bytes around. This can make auditing a lot easier. See for instance
  the design of the rust aead crate, where you implement the low level, required bits,
  and get the fancier high-level APIs for free, opting into extra dependencies by
  turning on features.
- Making it easy to migrate your code if you must change cryptographic primitives.
- Allowing to share this code across projects as much as possible, to reduce barrier
  to entry and also build confidence in the correctness of the shared code.

Design goals:
-------------

- Provide a generic way to convert the type to bytes, and to try to recover it from bytes.
- Provide an in-place API for when copying the bytes on the stack would be unacceptable.
- The API should be implementable in a nice way for both `x25519-dalek` public keys and
  `Ristretto` public keys.
- Don't create a hard dependency on anything outside of rust core.
  No global allocator requirements.
- Use `generic_array`, or at least `typenum`, to track the size of the fixed-width representation.
  This is in keeping with other examples like `aead` and `digest` [1,2], it is consumed in some
  downstream crates like `mc-crypto-box` [8] which must assemble a Kex algorithm and an Aead together.
  `typenum` is pretty much a requirement in low-level core-only code
  until so-called "const generics" are stable in rustlang [10].

As bonuses which support our use-cases, we provide, via opt-in macros, many "suggested implementations"
for types which implement `ReprBytes`.
- `serde::{Deserialize, Serialize}`
- `prost::Message`
- `Into<Vec<u8>>`

We also provide an opt-in macro that *implements* `ReprBytes` given the fixed size,
in terms of `AsRef<[u8]>` and `TryFrom<&[u8]>`. For types that are not like `RistrettoPoint`
this should generally be the way to go.

Discussion:
-----------

1. Why isn't the whole thing based on the core `TryFrom` and `TryInto` traits?

   Unfortunately, `Into` and `TryInto` consume `self`. We could have tried to implement
   e.g. `From<Key> for GenericArray<...>` but this will become very cumbersome to use
   and express in trait bounds. If we accept that there should be a function of the form
   `to_bytes(&self) -> Bytes` or something like this, then there will have to be a new trait.
   We might as well put the stuff we need there.

   We also need to know the Size in bytes statically -- this means it has to be an
   associated type or an associated const of the trait. If we want to be able to use
   this easily in things like `mc-crypto-box` that have to work with `aead` which uses
   `generic_array`, then it needs to be a `typenum` and not just a `const` [8].

   We don't allow that `to_bytes` can fail because it doesn't have any possibility of
   failure for real-world cryptographic key implementations.

   We have tried to leverage as much as possible the existing core traits and implementations,
   see the `derive_repr_bytes_from_as_ref_and_try_from` macro.

1. `to_bytes` is copying the bytes onto the stack, but that is a pessimization for
   some kinds of keys.

   When actually using these key types in generic code, you need to be able to get
   the canonical bytes and feed them into some other cryptographic primitive, that
   generally takes either `&[u8]` or `AsRef<[u8]>`, (but possibly a
   `&GenericArray<u8, ...::KeySize>` or similar).

   Anyways, it's really very convenient to be able to return *something* that implements
   `AsRef<[u8]>`, and that will work even for `RistrettoPoint`. Many optimizing compilers
   like llvm are good at things like "Return Value Optimization" where unnecessary copies
   of things on the stack are found and eliminated, and have been for many years [9].

   For other examples where fixed-size buffers (generic arrays) are returned on the stack,
   see the RustCrypto aead trait which, in the lowest level API, returns the `tag` bytes [1].

   There is an "in-place" API via `ReprBytes::map_bytes` which takes a closure and completely
   avoids this copy when possible to do so. This has the following signature:

   ```
   fn map_bytes<F, T>(&self, f: F) -> T
   where
       F: FnOnce(&[u8]) -> T
   ```

   So in code, this might look like:

   ```
   pubkey.map_bytes(|bytes| digest.input(bytes));
   ```

   where `bytes` has type `&[u8]`.

1. What if `to_bytes` return type were an associated type so that it can return `&[u8]`?

   To my knowledge, this is impossible, because the associated type must have a fixed lifetime,
   but the lifetime of the reference from `to_bytes` would have to depend on `&self`. I could
   not find any solutions like this that did not make `ReprBytes` into a generic trait, which then
   make it a lot harder to use.

   I also could not get rustc to compile `to_bytes(&self) -> impl AsRef<[u8]>`, `impl` in
   return type is not (yet?) permitted in traits.

   I now believe that this issue is exactly the issue of "Generic Associated Types", and
   the motivating example for that RFC is essentially the same [11].

1. What if `to_bytes` had signature `to_bytes(&'a self) -> Cow<'a, GenericArray<u8, ...>>`?

   This avoids the copy, but it creates an enum (runtime state) that conveys whether the
   value is a copy or a reference. Also, `Cow` API is cumbersome and this makes the trait
   harder to use. This `Cow` object does not actually implement `AsRef<[u8]>`, it is
   two steps away from `&[u8]`.

   Just using a closure via `map_bytes` sidesteps all of these annoying lifetime problems.
   The temporary buffer, if needed, lives on the stack before the closure is entered.
   If not, the whole thing should be inlined.

   Rust has been designed so that `map`-like APIs which use closures are idiomatic,
   and many rust developers seem to like working with the core `Option` type which
   leans on this pattern heavily. By contrast, APIs using `Cow` are not as common.

1. The closure-based API can be implemented in terms of the `Cow` API, but the reverse is not true, so `Cow` is better.

   This is true, but not always a good way of thinking about APIs. It is better to think about what are
   the requirements, and what are the use-cases. Right now, no APIs involving cryptographic
   libraries or serialization libraries consume bytes via `Cow` types. They typically consume slices,
   and the visitor pattern is used extensively in e.g. Serde to change "who is in the driver's seat"
   at any step of the process. Since nothing is consuming `Cow` types, nothing needs them either.

   If in the future someone really needs to work with types that are like `Cow<bytes>`, then they
   can implement a `ToCowBytes` trait on the keys that they need to work with.

1. I still don't believe that there's no way to do this without Cow or closures.

   There is a way to do it without these things, but it involves aggressive use of
   HRTB's and it's not clear that it's better at the end of the day:

   First, there needs to be a trait, parameterized over a lifetime, that expresses
   "two levels of indirection away from T". We can call this `AsAsRef`:

   ```
   pub trait AsAsRef<'a, T> {
       type Output: AsRef<T>;
       fn as_as_ref(&'a self) -> Self::Output;
   }
   ```

   A type like `CompressedRistretto` can `impl` this, for all `'a`, with `Output = &'a [u8]`.
   A type like `RistrettoPoint` can `impl` this, for all `'a`, with `Output = [u8; 32]`.

   Then, `ReprBytes` can be defined using HRTB's like so:

   ```
   pub trait ReprBytes: for <'a> AsAsRef<'a, [u8]> + for <'a> TryFrom<&'a [u8]> {
       type Size: ArrayLength<u8>;
       fn size() -> usize { Self::Size::USIZE }
   }
   ```

   We would still need to be able to get a typenum corresponding to the size for things like
   `CryptoBox` which have an API defined in terms of `GenericArray`, where the sizes are sums of typenums [8].
   Potentially we could drop the `Size` typenum, and force users of those API's to supply the typenums
   at the time that they use those things. In `Digest` trait, this is done via the `BlockInput`
   marker trait.

   As a proof-of-concept for the viability of `AsAsRef`, these sample implementations were built
   and tested, at rustc version 1.41.0:

    ```
    use alloc::vec::Vec;
    impl <'a> AsAsRef<'a, [u8]> for Vec<Vec<u8>> {
        type Output = Vec<u8>;
        fn as_as_ref(&self) -> Vec<u8> {
            let mut result = Vec::new();
            for slice in self.iter() { result.extend(slice) }
            result
        }
    }

    impl <'a> AsAsRef<'a, [u8]> for Vec<u8> {
        type Output = &'a[u8];
        fn as_as_ref(&'a self) -> &'a[u8] {
            &self[..]
        }
    }
    ```

   Usage examples for `ReprBytes`:

   Recall that `Hkdf` has an API like `Hkdf::<Digest>::extract(Option<&[u8]>, &[u8])`.

   With the `AsAsRef` API, extracting key material from a public key looks like:
   ```
   Hkdf::<Sha256>::extract(None, pubkey.as_as_ref().as_ref())
   ```

   With the closure-based API, extracting key material looks like:
   ```
   pubkey.map_bytes(|bytes| Hkdf::<Sha256>::extract(None, bytes))
   ```

   Recall that `Digest` `Input` trait uses the following signature:
   ```
   fn input<B: AsRef<[u8]>>(&mut self, data: B)
   ```

   With the `AsAsRef` API, hashing the bytes of a public key looks like:

   ```
   digest.input(pubkey.as_as_ref());
   ```

   With the closure API, this looks like

   ```
   pubkey.map_bytes(|bytes| digest.input(bytes));
   ```

   where `bytes` has type `&[u8]`.

   Both APIs work, but it's a matter of opinion which feels more natural and idiomatic.
   It is worth pointing out that the `map_bytes` API can be implemented in terms of `AsAsRef`.

References
----------

1. RustCrypto aead trait: https://github.com/RustCrypto/traits/blob/e020ecfd83c5d1f5d19b674d071b858ea1369088/aead/src/lib.rs#L76
2. RustCrypto digest trait: https://github.com/RustCrypto/traits/blob/e020ecfd83c5d1f5d19b674d071b858ea1369088/digest/src/digest.rs#L9
3. Dalek-cryptography curve25519 RistrettoPoint: https://github.com/dalek-cryptography/curve25519-dalek/blob/409ebd94c011472cb2d24bd4f957448d52065ab6/src/ristretto.rs#L227
4. Dalek-cryptography x25519 implementation: https://github.com/dalek-cryptography/x25519-dalek/blob/be82bcb15b57ed6a07e92a0643b8355bd8d653a3/src/x25519.rs#L46
5. Mobilecoin keys and Kex traits: https://github.com/mobilecoinfoundation/mobilecoin/blob/a13fa2246c8df4054ef5bad69f0566c0161be8cb/crypto/keys/src/traits.rs#L195
6. Mobilecoin transaction TxOut structure, showing use of Prost with Ristretto wrappers: https://github.com/mobilecoinfoundation/mobilecoin/blob/a13fa2246c8df4054ef5bad69f0566c0161be8cb/transaction/core/src/tx.rs#L234
7. Mobilecoin noise implementation: https://github.com/mobilecoinfoundation/mobilecoin/blob/a13fa2246c8df4054ef5bad69f0566c0161be8cb/crypto/ake/mcnoise/src/handshake_state.rs#L128
8. Mobilecoin cryptobox implementation: https://github.com/mobilecoinfoundation/mobilecoin/pull/74
9. Return value optimization in compilers: https://en.wikipedia.org/wiki/Copy_elision
    (This is a discussion of C++, but this has been a major focus of work in the optimizing
     backends such as llvm as well, for many years.)
10. RFC `const_generics`: https://github.com/rust-lang/rfcs/blob/master/text/2000-const-generics.md
11. RFC `generic_associated_types`: https://github.com/rust-lang/rfcs/pull/1598/files
