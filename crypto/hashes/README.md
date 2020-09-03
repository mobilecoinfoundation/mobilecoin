mc-crypto-hashes
======

This crate contains a wrapper of Blake2b that produces a 32 byte digest, instead
of 64 byte, for convenience.

Similar objects can be placed here.

PseudoMerlin
---------

`PseudoMerlin` is an adaptor that allows to emulate the `append_message` API of
a `Merlin` transcript, using any cryptographic digest. The purpose of this is
to use it with `Digestible` crate.

The idea is that `append_message(label, data)` should be implemented as

```
self.digest.update((label.len() as u32).to_le_bytes());
self.digest.update(label);
self.digest.update((data.len() as u32).to_le_bytes());
self.digest.update(data);
```

This creates a prefix-free encoding of `(label, data)` pairs, so when the digest
is ultimately extracted, we know that if an adversary can find two different
sequences of `(label, data)` pairs that cause `PseudoMerlin` to give the same hash
it means that the adversary can also find a nontrivial collision in the underlying digest function.

If the digest function is collision resistant in the classical sense, this means that
PseudoMerlin has the same security property that `Digestible` crate needs of `Merlin`.

Even though this is available, it is recommended not to use this and to use `Merlin` instead
if possible. This exists to support any niche cases where data must be digested into a particular
hasher in order to be compatible with a particular API.
