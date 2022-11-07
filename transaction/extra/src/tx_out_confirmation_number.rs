// Copyright (c) 2018-2022 The MobileCoin Foundation

use alloc::vec::Vec;
use mc_crypto_digestible::Digestible;
use mc_crypto_hashes::{Blake2b256, Digest};
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use mc_crypto_ring_signature::get_tx_out_shared_secret;
use mc_util_repr_bytes::{
    derive_prost_message_from_repr_bytes, typenum::U32, GenericArray, ReprBytes,
};
use serde::{Deserialize, Serialize};

/// Domain separator for hashing the confirmation number
pub const TXOUT_CONFIRMATION_NUMBER_DOMAIN_TAG: &str = "mc_tx_out_confirmation_number";

/// A hash of the shared secret used to confirm tx was sent
#[derive(
    Clone, Deserialize, Default, Eq, Ord, PartialEq, PartialOrd, Serialize, Debug, Digestible,
)]
pub struct TxOutConfirmationNumber([u8; 32]);

impl TxOutConfirmationNumber {
    /// Copies self into a new Vec.
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Validate a confirmation number against tx pubkey and view private key
    pub fn validate(
        &self,
        tx_pubkey: &RistrettoPublic,
        view_private_key: &RistrettoPrivate,
    ) -> bool {
        let shared_secret = get_tx_out_shared_secret(view_private_key, tx_pubkey);
        let calculated_confirmation = TxOutConfirmationNumber::from(&shared_secret);
        calculated_confirmation == *self
    }
}

impl core::convert::AsRef<[u8; 32]> for TxOutConfirmationNumber {
    #[inline]
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::convert::From<&[u8; 32]> for TxOutConfirmationNumber {
    #[inline]
    fn from(src: &[u8; 32]) -> Self {
        Self(*src)
    }
}

impl core::convert::From<[u8; 32]> for TxOutConfirmationNumber {
    #[inline]
    fn from(src: [u8; 32]) -> Self {
        Self(src)
    }
}

// Note: This is only supposed to be used with the TxOut shared secret
impl core::convert::From<&RistrettoPublic> for TxOutConfirmationNumber {
    fn from(shared_secret: &RistrettoPublic) -> Self {
        let mut hasher = Blake2b256::new();
        hasher.update(&TXOUT_CONFIRMATION_NUMBER_DOMAIN_TAG);
        hasher.update(shared_secret.to_bytes());
        Self(hasher.finalize().into())
    }
}

impl ReprBytes for TxOutConfirmationNumber {
    type Size = U32;
    type Error = &'static str;
    fn from_bytes(src: &GenericArray<u8, U32>) -> Result<Self, &'static str> {
        Ok(Self((*src).into()))
    }
    fn to_bytes(&self) -> GenericArray<u8, U32> {
        self.0.into()
    }
}

derive_prost_message_from_repr_bytes!(TxOutConfirmationNumber);
