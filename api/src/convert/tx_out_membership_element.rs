// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from external::TxOutMembershipElement

use crate::{external, ConversionError};
use mc_transaction_core::{
    membership_proofs::Range,
    tx::{TxOutMembershipElement, TxOutMembershipHash},
};

/// Convert TxOutMembershipElement -> external::TxOutMembershipElement
impl From<&TxOutMembershipElement> for external::TxOutMembershipElement {
    fn from(src: &TxOutMembershipElement) -> Self {
        Self {
            range: Some(external::Range {
                from: src.range.from,
                to: src.range.to,
            }),
            hash: Some(external::TxOutMembershipHash {
                data: src.hash.to_vec(),
            }),
        }
    }
}

/// Convert external::TxOutMembershipElement -> TxOutMembershipElement
impl TryFrom<&external::TxOutMembershipElement> for TxOutMembershipElement {
    type Error = ConversionError;

    fn try_from(src: &external::TxOutMembershipElement) -> Result<Self, Self::Error> {
        let default_range = Default::default();
        let src_range = src.range.as_ref().unwrap_or(&default_range);
        let range =
            Range::new(src_range.from, src_range.to).map_err(|_e| ConversionError::Other)?;

        let default_membership_hash = Default::default();
        let bytes: &[u8] = src
            .hash
            .as_ref()
            .unwrap_or(&default_membership_hash)
            .data
            .as_slice();
        let mut hash = [0u8; 32];
        if bytes.len() != hash.len() {
            return Err(ConversionError::ArrayCastError);
        }
        hash.copy_from_slice(bytes);

        Ok(TxOutMembershipElement {
            range,
            hash: TxOutMembershipHash::from(hash),
        })
    }
}
