//! Traits supporting driver (or other hardware) implementations

use core::fmt::Debug;

use mc_core_types::account::{PublicSubaddress};
use mc_crypto_keys::{RistrettoPublic, CompressedRistrettoPublic};
use mc_crypto_ring_signature::{KeyImage};


/// Transaction key image computer
pub trait KeyImageComputer {
    /// TODO
    type Error: Debug;

    /// Compute key image for a given subaddress and tx_out_public_key
    fn compute_key_image(
        &self,
        subaddress_index: u64,
        tx_out_public_key: &CompressedRistrettoPublic,
    ) -> Result<KeyImage, Self::Error>;
}

/// Memo signer for generating memo HMACs
pub trait MemoHmacSigner {
    /// TODO
    type Error: Debug;

    /// Compute the HMAC signature for the provided memo and target address
    fn compute_memo_hmac_sig(
        &mut self,
        tx_public_key: RistrettoPublic,
        target_subaddress: PublicSubaddress,
        memo_type: &[u8; 2],
        memo_data_sans_hmac: &[u8; 48],
    ) -> Result<[u8; 16], Self::Error>;
}

/// Memo encryptor for encrypting memos via shared secret 
pub trait MemoEncryptor {
    /// TODO
    type Error: Debug;

    /// Encrypt the memo payload via shared secret
    fn encrypt_memo(
        &mut self,
        tx_public_key: RistrettoPublic,
        target_subaddress: PublicSubaddress,
        memo_payload: &[u8; 64],
    ) -> Result<[u8; 16], Self::Error>;
}
