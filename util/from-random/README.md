A trait for constructing an object from a random number generator.

This provides a common API for types which can be initialized from random number generators.

# Example

```rust
use mc_util_from_random::FromRandom;
use rand_core::{CryptoRng, RngCore};

struct MyStruct {
    pub bytes: [u8; 32],
}

impl FromRandom for MyStruct {
    fn from_random<R: CryptoRng + RngCore>(csprng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        csprng.fill_bytes(&bytes);
        MyStruct {
            bytes,
        }
    }
}
```
