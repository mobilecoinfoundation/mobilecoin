mc-crypto-rand
======

`mcrand` crate provides an rng type which is:
(1) no_std compatible
(2) uses RDRAND when available, in and out of the enclave on sgx servers,
(3) uses something like rand::ThreadRng on any other platforms

`mc-crypto-rand` does not require any cargo feature configuration to be used correctly,
which simplifies the build

When `+rdrand` rustc target feature is enabled, we use x86 intrinsics directly to
do rdrand correctly, and do not pull in getrandom or any other library.

when this target feature is not enabled, we do something that is almost the same as
`rand::ThreadRng`, but we use the nightly `#[thread_local]` api instead of `std::thread_local!`
macro. In fact we rely on rand for the implementation details, but we turn of `std` feature of rand.

Example usage:

```
use mc_crypto_rand::{RdRandRng, RngCore}

pub fn my_func() -> (u64, u64) {
    let mut rng = RdRandRng{};
    let k0 = rng.next_u64();
    let k1 = rng.next_u64();
    (k0, k1)
}
```
