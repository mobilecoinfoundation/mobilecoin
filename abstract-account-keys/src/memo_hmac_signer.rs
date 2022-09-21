// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::Error;
use mc_crypto_keys::{CompressedRistrettoPublic};

/// An object that can compute the appropriate hmac of a MCIP #4-style Authenticated Sender memo,
/// for spend keys which have been abstracted.
/// This generally requires the subaddress spend private key.
pub trait MemoHmacSigner {
    /// Compute the hmac which "signs" a given MCIP #4 Authenticated sender memo
    fn compute_memo_hmac_sig(&self, receiving_subaddress_view_public: &CompressedRistrettoPublic, tx_out_public_key: &CompressedRistrettoPublic, memo_type: &[u8; 2], memo_data_sans_hmac: &[u8; 48]) -> Result<[u8; 16], Error>;
}
