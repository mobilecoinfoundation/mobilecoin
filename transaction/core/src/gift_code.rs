// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Code for computing & receiving gift codes

use crate::{Amount, AmountError, MaskedAmount};
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};

/// Object representing a TxOut that can be sent to a receiver enabling them
/// to find/uniquely identify a TxOut, un-blind the amount, and spend the TxOut
#[derive(Clone, Debug)]
pub struct GiftCode {
    /// The global index of the TxOut which has been gifted
    pub global_index: u64,

    /// The one-time private key which can be used to spend this TxOut
    pub onetime_private_key: RistrettoPrivate,

    /// The shared secret which can be used to un-blind the amount of this TxOut
    pub shared_secret: RistrettoPublic,
}

impl GiftCode {
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

impl PartialEq for GiftCode {
    fn eq(&self, other: &Self) -> bool {
        self.global_index == other.global_index && self.shared_secret == other.shared_secret
    }
}
