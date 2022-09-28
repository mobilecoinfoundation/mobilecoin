// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{tx::TxOut, Amount, AmountError, MaskedAmount, MaskedAmountV2, TxOutConversionError};
use alloc::vec::Vec;
use displaydoc::Display;
use mc_crypto_digestible::Digestible;
use mc_crypto_ring_signature::Scalar;
use prost::Message;
use serde::{Deserialize, Serialize};

/// A TxOut together with its amount shared secret, which can be used to reveal
/// the amount and token id and check them against the commitment data
#[derive(Clone, Digestible, PartialEq, Eq, Message, Serialize, Deserialize)]
pub struct RevealedTxOut {
    /// The TxOut which is being revealed
    #[prost(message, required, tag = "1")]
    pub tx_out: TxOut,

    /// The amount shared secret of this TxOut
    /// This should be exactly 32 bytes
    #[prost(bytes, tag = "2")]
    pub amount_shared_secret: Vec<u8>,
}

impl RevealedTxOut {
    /// Attempt to reveal the amount of this RevealedTxOut
    pub fn reveal_amount(&self) -> Result<(Amount, Scalar), RevealedTxOutError> {
        try_reveal_amount(&self.tx_out, self.amount_shared_secret.as_ref())
    }

    /// Make a new TxOut which matches this one, except with a different
    /// committed amount. The new one will still be owned by the same person
    /// and view key matching etc. will still work.
    ///
    /// Note: The masked value blinding, masked token id blinding, and
    /// commitment blinding factor will all be the same for the original
    /// TxOut and the new one. This is all checked by a debug assert in this
    /// function.
    ///
    /// # Arguments
    /// * amount that the new tx out should have.
    ///
    /// # Returns
    /// * the new tx out, or an error
    pub fn change_committed_amount(&self, new_amount: Amount) -> Result<TxOut, RevealedTxOutError> {
        let mut result = self.tx_out.clone();

        result.masked_amount = match self.tx_out.get_masked_amount()? {
            MaskedAmount::V1(_) => {
                return Err(AmountError::AmountVersionTooOldForAmountSharedSecret.into())
            }
            MaskedAmount::V2(_) => {
                let new_masked_amount = MaskedAmountV2::new_from_amount_shared_secret(
                    new_amount,
                    self.amount_shared_secret[..]
                        .try_into()
                        .map_err(|_| RevealedTxOutError::InvalidAmountSharedSecret)?,
                )?;

                // Reality check: Confirm that the new masked amount can be decoded using this
                // shared secret as expected
                debug_assert_eq!(
                    new_amount,
                    new_masked_amount
                        .get_value_from_amount_shared_secret(
                            &self.amount_shared_secret[..].try_into().unwrap()
                        )
                        .unwrap()
                        .0
                );

                Some(MaskedAmount::V2(new_masked_amount))
            }
        };

        Ok(result)
    }
}

/// Helper function which tries to reveal the amount of a TxOut given its shared
/// secret, and confirm this against the commitment data
pub fn try_reveal_amount(
    tx_out: &TxOut,
    amount_shared_secret: &[u8],
) -> Result<(Amount, Scalar), RevealedTxOutError> {
    let ss: &[u8; 32] = amount_shared_secret
        .try_into()
        .map_err(|_| RevealedTxOutError::InvalidAmountSharedSecret)?;
    Ok(tx_out
        .get_masked_amount()?
        .get_value_from_amount_shared_secret(ss)?)
}

/// An error that can occur when attempting to reveal a TxOut using its Amount
/// shared secret
#[derive(Clone, Debug, Display, Ord, PartialOrd, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum RevealedTxOutError {
    /// Invalid Amount Shared Secret
    InvalidAmountSharedSecret,
    /// TxOut conversion: {0}
    TxOutConversion(TxOutConversionError),
    /// Amount: {0}
    Amount(AmountError),
}

impl From<TxOutConversionError> for RevealedTxOutError {
    fn from(src: TxOutConversionError) -> Self {
        Self::TxOutConversion(src)
    }
}

impl From<AmountError> for RevealedTxOutError {
    fn from(src: AmountError) -> Self {
        Self::Amount(src)
    }
}
