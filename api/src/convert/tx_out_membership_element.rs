//! Convert to/from external::TxOutMembershipElement

use crate::{convert::ConversionError, external};
use mc_transaction_core::{
    membership_proofs::Range,
    tx::{TxOutMembershipElement, TxOutMembershipHash},
};
use std::convert::TryFrom;

/// Convert TxOutMembershipElement -> external::TxOutMembershipElement
impl From<&TxOutMembershipElement> for external::TxOutMembershipElement {
    fn from(src: &TxOutMembershipElement) -> Self {
        let mut dst = external::TxOutMembershipElement::new();
        dst.mut_range().set_from(src.range.from);
        dst.mut_range().set_to(src.range.to);
        dst.mut_hash().set_data(src.hash.to_vec());
        dst
    }
}

/// Convert external::TxOutMembershipElement -> TxOutMembershipElement
impl TryFrom<&external::TxOutMembershipElement> for TxOutMembershipElement {
    type Error = ConversionError;

    fn try_from(src: &external::TxOutMembershipElement) -> Result<Self, Self::Error> {
        let range = Range::new(src.get_range().get_from(), src.get_range().get_to())
            .map_err(|_e| ConversionError::Other)?;

        let bytes: &[u8] = src.get_hash().get_data();
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
