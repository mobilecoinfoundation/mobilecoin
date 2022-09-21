// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::Error;
use mc_crypto_keys::{CompressedRistrettoPublic};
use mc_crypto_ring_signature::KeyImage;

/// An object that can compute the key image of a TxOut, given a subset of its data and the subaddress index.
/// This generally requires the subaddress spend private key.
pub trait KeyImageComputer {
    /// Compute the key image of a TxOut given its public key, and the subaddress index on which this account owns it.
    fn compute_key_image(&self, tx_out_public_key: &CompressedRistrettoPublic, subaddress_index: u64) -> Result<KeyImage, Error>;
}
