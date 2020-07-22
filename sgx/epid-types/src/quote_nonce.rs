// Copyright (c) 2018-2020 MobileCoin Inc.

//! Quote nonce wrapper

use mc_sgx_core_types::impl_ffi_wrapper;
use mc_sgx_epid_types_sys::sgx_quote_nonce_t;
use mc_util_from_random::FromRandom;
#[cfg(feature = "use_prost")]
use mc_util_repr_bytes::derive_prost_message_from_repr_bytes;
#[cfg(feature = "use_serde")]
use mc_util_repr_bytes::derive_serde_from_repr_bytes;
use mc_util_repr_bytes::typenum::U16;
use rand_core::{CryptoRng, RngCore};

/// The size of a [QuoteNonce] structure's x64 representation, in bytes.
pub const QUOTE_NONCE_SIZE: usize = 16;

/// A structure wrapping a nonce to be used in an SGX quote
///
/// # Example
///
/// ```
/// use mc_sgx_epid_types::QuoteNonce;
/// use mc_util_from_random::FromRandom;
/// use rand_core::SeedableRng;
/// use rand_hc::Hc128Rng;
///
/// // chosen by fair dice roll, or: use a real rng in real code, folks.
/// let mut csprng = Hc128Rng::seed_from_u64(0);
/// let nonce = QuoteNonce::from_random(&mut csprng);
/// let nonce_contents: &[u8] = nonce.as_ref();
/// let expected = [226u8, 30, 184, 201, 207, 62, 43, 114, 89, 4, 220, 27, 84, 79, 238, 234];
/// assert_eq!(nonce_contents, &expected[..]);
/// ```
#[derive(Default)]
#[repr(transparent)]
pub struct QuoteNonce(sgx_quote_nonce_t);

impl_ffi_wrapper! {
    QuoteNonce, sgx_quote_nonce_t, U16, rand;
}

#[cfg(feature = "use_prost")]
derive_prost_message_from_repr_bytes!(QuoteNonce);

#[cfg(feature = "use_serde")]
derive_serde_from_repr_bytes!(QuoteNonce);

impl FromRandom for QuoteNonce {
    fn from_random<R: CryptoRng + RngCore>(csprng: &mut R) -> Self {
        let mut retval = Self::default();
        csprng.fill_bytes(&mut retval.0.rand[..]);
        retval
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[cfg(feature = "use_serde")]
    use bincode::{deserialize, serialize};
    use rand_core::SeedableRng;
    use rand_hc::Hc128Rng;

    #[cfg(feature = "use_serde")]
    #[test]
    fn serde() {
        let mut csprng = Hc128Rng::seed_from_u64(0);
        let nonce = QuoteNonce::from_random(&mut csprng);
        let bytes = serialize(&nonce).expect("Could not serialize nonce");
        let nonce2 = deserialize::<QuoteNonce>(&bytes[..]).expect("Could not deserialize nonce");
        assert_eq!(nonce, nonce2);
    }
}
