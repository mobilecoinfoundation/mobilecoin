//! Quote nonce wrapper

use keys::FromRandom;
use mc_sgx_core_types::impl_ffi_wrapper;
use mc_sgx_epid_types_sys::sgx_quote_nonce_t;

/// A structure wrapping a nonce to be used in an SGX quote
///
/// # Example
///
/// ```
/// use mc_sgx_epid_types::{QuoteNonce};
/// use keys::FromRandom;
/// use rand::prelude::*;
/// use rand_hc::Hc128Rng;
///
/// // chosen by fair dice roll, or: use a real rng in real code, folks.
/// let mut csprng = Hc128Rng::seed_from_u64(0);
/// let nonce = QuoteNonce::from_random(&mut csprng).expect("Could not create nonce");
/// let nonce_contents: &[u8] = nonce.as_ref();
/// let expected = [226u8, 30, 184, 201, 207, 62, 43, 114, 89, 4, 220, 27, 84, 79, 238, 234];
/// assert_eq!(nonce_contents, &expected[..]);
/// ```
#[derive(Default)]
#[repr(transparent)]
pub struct QuoteNonce(sgx_quote_nonce_t);

impl_ffi_wrappper! {
    QuoteNonce, sgx_quote_nonce_t, QUOTE_NONCE_LENGTH, rand;
}

impl FromRandom for QuoteNonce {}
