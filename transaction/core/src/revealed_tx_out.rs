// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{tx::TxOut, Amount, AmountError, TxOutConversionError};
use alloc::{
    vec::Vec,
};
use displaydoc::Display;
use mc_crypto_digestible::Digestible;
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
    pub fn reveal_amount(&self) -> Result<Amount, RevealedTxOutError> {
        try_reveal_amount(&self.tx_out, self.amount_shared_secret.as_ref())
    }
}

/// Helper function which tries to reveal the amount of a TxOut given its shared
/// secret, and confirm this against the commitment data
pub fn try_reveal_amount(
    tx_out: &TxOut,
    amount_shared_secret: &[u8],
) -> Result<Amount, RevealedTxOutError> {
    let ss: &[u8; 32] = amount_shared_secret
        .try_into()
        .map_err(|_| RevealedTxOutError::InvalidAmountSharedSecret)?;
    let (amount, _) = tx_out
        .get_masked_amount()?
        .get_value_from_amount_shared_secret(ss)?;
    Ok(amount)
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
