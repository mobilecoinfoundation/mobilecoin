// Copyright (c) 2018-2020 MobileCoin Inc.

use crate::{
    blake2b_256::Blake2b256,
    ring_signature::KeyImage,
    tx::{TxHash, TxOut},
};
use alloc::vec::Vec;
use digestible::Digestible;
use serde::{Deserialize, Serialize};

/// A transaction that has had sensitive fields like inputs removed. It may be stored in plain text.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize, Digestible)]
pub struct RedactedTx {
    /// List of outputs from the transaction.
    pub outputs: Vec<TxOut>,

    /// Key images "spent" by this transaction.
    pub key_images: Vec<KeyImage>,
}

impl RedactedTx {
    /// # Arguments
    /// * `outputs` - List of outputs from the transaction.
    /// * `key_images` - Key images "spent" by this transaction.
    pub fn new(outputs: Vec<TxOut>, key_images: Vec<KeyImage>) -> Self {
        RedactedTx {
            outputs,
            key_images,
        }
    }
}

impl RedactedTx {
    pub fn hash(&self) -> TxHash {
        let result: [u8; 32] = self.digest_with::<Blake2b256>().into();
        TxHash::from(result)
    }
}
