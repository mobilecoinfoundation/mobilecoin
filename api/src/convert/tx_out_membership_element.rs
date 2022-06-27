//! Convert to/from external::TxOutMembershipElement

use crate::{external, ConversionError};
use mc_transaction_core::{
    membership_proofs::Range,
    tx::{TxOutMembershipElement, TxOutMembershipHash},
};

impl From<&TxOutMembershipElement> for external::TxOutMembershipElement {
    fn from(src: &TxOutMembershipElement) -> Self {
        Self {
            range: Some((&src.range).into()),
            hash: Some((&src.hash).into()),
        }
    }
}

impl TryFrom<&external::TxOutMembershipElement> for TxOutMembershipElement {
    type Error = ConversionError;

    fn try_from(src: &external::TxOutMembershipElement) -> Result<Self, Self::Error> {
        let range = src
            .range
            .as_ref()
            .ok_or(ConversionError::ObjectMissing)?
            .try_into()?;

        let hash = src
            .hash
            .as_ref()
            .ok_or(ConversionError::ObjectMissing)?
            .try_into()?;

        Ok(TxOutMembershipElement { range, hash })
    }
}

impl From<&Range> for external::Range {
    fn from(src: &Range) -> Self {
        Self {
            from: src.from,
            to: src.to,
        }
    }
}

impl TryFrom<&external::Range> for Range {
    type Error = ConversionError;

    fn try_from(src: &external::Range) -> Result<Self, Self::Error> {
        Range::new(src.from, src.to).map_err(|_| ConversionError::Other)
    }
}

impl From<&TxOutMembershipHash> for external::TxOutMembershipHash {
    fn from(src: &TxOutMembershipHash) -> Self {
        Self { data: src.to_vec() }
    }
}

impl TryFrom<&external::TxOutMembershipHash> for TxOutMembershipHash {
    type Error = ConversionError;

    fn try_from(src: &external::TxOutMembershipHash) -> Result<Self, Self::Error> {
        let bytes: &[u8; 32] = src.data.as_slice().try_into()?;
        Ok(Self(*bytes))
    }
}
