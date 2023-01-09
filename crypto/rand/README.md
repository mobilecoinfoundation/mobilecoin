mc-crypto-rand
======

`mc-crypto-rand` crate provides an rng type which is:
(1) no_std compatible
(2) uses RDRAND when available, in and out of the enclave on sgx servers,
(3) uses something like rand::ThreadRng on any other platforms

`mc-crypto-rand` does not require any cargo feature configuration to be used correctly,
which simplifies the build.

When `+rdrand` rustc target feature is enabled, we use x86 intrinsics directly to
do rdrand correctly, and do not pull in getrandom or any other library.

When this target feature is not enabled, we use `rand::ThreadRng` on targets with `std`, and on WASM or `no_std` targets we use `rand::OsRng`.

Example usage:

```
use mc_crypto_rand::{McRng, RngCore}

pub fn my_func() -> (u64, u64) {
    let mut rng = McRng{};
    let k0 = rng.next_u64();
    let k1 = rng.next_u64();
    (k0, k1)
}
```
