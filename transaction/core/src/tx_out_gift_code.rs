// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Code for computing & receiving gift codes

use crate::{Amount, AmountError, MaskedAmount};
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use prost::Message;
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConstantTimeEq};

/// Object representing a TxOut that can be sent to a receiver enabling them
/// to find/uniquely identify a TxOut, un-blind the amount, and spend the TxOut
#[derive(Clone, Deserialize, Serialize, Message)]
pub struct TxOutGiftCode {
    /// The global index of the TxOut which has been gifted
    #[prost(uint64, required, tag = "1")]
    pub global_index: u64,

    /// The one-time private key which can be used to spend this TxOut
    #[prost(message, required, tag = "2")]
    pub onetime_private_key: RistrettoPrivate,

    /// The shared secret which can be used to un-blind the amount of this TxOut
    #[prost(message, required, tag = "3")]
    pub shared_secret: RistrettoPublic,
}

impl TxOutGiftCode {
    /// Create a new gift code object
    pub fn new(
        global_index: u64,
        onetime_private_key: RistrettoPrivate,
        shared_secret: RistrettoPublic,
    ) -> Self {
        Self {
            global_index,
            onetime_private_key,
            shared_secret,
        }
    }

    /// Un-blind amount given a MaskedAmount object
    pub fn unblind_amount(&self, masked_amount: MaskedAmount) -> Result<Amount, AmountError> {
        let (amount, _) = masked_amount.get_value(&self.shared_secret)?;
        Ok(amount)
    }

    /// Un-blind amount given a masked value and token id
    pub fn unblind_amount_with_masked_token_id(
        &self,
        masked_value: u64,
        masked_token_id: &[u8],
    ) -> Result<Amount, AmountError> {
        let (_, amount) =
            MaskedAmount::reconstruct(masked_value, masked_token_id, &self.shared_secret)?;
        Ok(amount)
    }
}

// Implement constant time equality for all fields given they're all sensitive
impl ConstantTimeEq for TxOutGiftCode {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.global_index.ct_eq(&other.global_index).ct_eq(
            &self.onetime_private_key.ct_eq(&other.onetime_private_key).ct_eq(
                &self.shared_secret.as_ref().ct_eq(other.shared_secret.as_ref()))
            )
    }
}

impl PartialEq for TxOutGiftCode {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for TxOutGiftCode {}
