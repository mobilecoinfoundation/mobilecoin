// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Input Materials is a helper struct for the transaction builder.
//! The transaction builder can get inputs either from input credentials,
//! or signed contingent inputs. In one case the input is being signed now using
//! the builder, and in the other it is already signed.
//!
//! The transaction builder is required to sort these in order of tx public key
//! of the first element of the ring being signed, then hand them off to build
//! the actual signatures. This enum makes it convenient to do this.

use crate::InputCredentials;
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_transaction_core::{
    ring_ct::InputRing, tx::TxIn, Amount, SignedContingentInput, TxOutConversionError,
};

/// Material that can be used by the transaction builder to create an input to
/// a transaction.
#[derive(Debug, Clone)]
pub enum InputMaterials {
    /// Signable input materials
    Signable(InputCredentials),
    /// Presigned input materials
    Presigned(SignedContingentInput),
}

impl From<InputCredentials> for InputMaterials {
    fn from(src: InputCredentials) -> Self {
        Self::Signable(src)
    }
}

impl From<SignedContingentInput> for InputMaterials {
    fn from(src: SignedContingentInput) -> Self {
        Self::Presigned(src)
    }
}

impl InputMaterials {
    /// Get the sort key for whichever type of input this is
    pub fn sort_key(&self) -> &CompressedRistrettoPublic {
        match self {
            InputMaterials::Signable(cred) => &cred.ring[0].public_key,
            InputMaterials::Presigned(input) => &input.tx_in.ring[0].public_key,
        }
    }

    /// Get the amount for whichever type of input this is
    pub fn amount(&self) -> Amount {
        match self {
            InputMaterials::Signable(cred) => cred.input_secret.amount,
            InputMaterials::Presigned(input) => Amount::from(&input.pseudo_output_amount),
        }
    }

    /// Get the ring size for whichever type of input this is
    pub fn ring_size(&self) -> usize {
        match self {
            InputMaterials::Signable(cred) => cred.ring.len(),
            InputMaterials::Presigned(input) => input.tx_in.ring.len(),
        }
    }
}

// Helper which converts from InputMaterials (TransactionBuilder type) to
// InputRing (rct_bulletproofs type)
impl TryFrom<InputMaterials> for InputRing {
    type Error = TxOutConversionError;
    fn try_from(src: InputMaterials) -> Result<InputRing, Self::Error> {
        Ok(match src {
            InputMaterials::Signable(creds) => InputRing::Signable(creds.try_into()?),
            InputMaterials::Presigned(input) => InputRing::Presigned(input.into()),
        })
    }
}

// Helper which converts from InputMaterials (TransactionBuilder type) to TxIn
// (blockchain type)
impl From<&InputMaterials> for TxIn {
    fn from(src: &InputMaterials) -> TxIn {
        match src {
            InputMaterials::Signable(ref creds) => creds.into(),
            InputMaterials::Presigned(input) => input.tx_in.clone(),
        }
    }
}
