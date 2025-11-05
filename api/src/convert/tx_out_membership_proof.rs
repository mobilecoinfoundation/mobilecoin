// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from external::TxOutMembershipProof

use crate::{external, ConversionError};
use mc_transaction_core::tx::{TxOutMembershipElement, TxOutMembershipProof};

/// Convert TxOutMembershipProof -> external::MembershipProof.
impl From<&TxOutMembershipProof> for external::TxOutMembershipProof {
    fn from(tx_out_membership_proof: &TxOutMembershipProof) -> Self {
        Self {
            index: tx_out_membership_proof.index,
            highest_index: tx_out_membership_proof.highest_index,
            elements: tx_out_membership_proof
                .elements
                .iter()
                .map(Into::into)
                .collect(),
        }
    }
}

/// Convert external::MembershipProof --> TxOutMembershipProof.
impl TryFrom<&external::TxOutMembershipProof> for TxOutMembershipProof {
    type Error = ConversionError;

    fn try_from(membership_proof: &external::TxOutMembershipProof) -> Result<Self, Self::Error> {
        let index: u64 = membership_proof.index;
        let highest_index: u64 = membership_proof.highest_index;

        let elements = membership_proof
            .elements
            .iter()
            .map(TxOutMembershipElement::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let tx_out_membership_proof = TxOutMembershipProof::new(index, highest_index, elements);
        Ok(tx_out_membership_proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_transaction_core::membership_proofs::Range;

    #[test]
    /// Convert TxOutMembershipProof -> external::TxOutMembershipProof.
    fn test_membership_proof_from() {
        let index: u64 = 128_465;
        let highest_index: u64 = 781_384_772_994;
        let hashes = vec![
            // Add some arbitrary hashes.
            TxOutMembershipElement::new(Range::new(0, 1).unwrap(), [2u8; 32]),
            TxOutMembershipElement::new(Range::new(0, 3).unwrap(), [4u8; 32]),
            TxOutMembershipElement::new(Range::new(0, 7).unwrap(), [8u8; 32]),
        ];
        let tx_out_membership_proof =
            TxOutMembershipProof::new(index, highest_index, hashes.clone());

        let membership_proof = external::TxOutMembershipProof::from(&tx_out_membership_proof);
        assert_eq!(membership_proof.index, index);
        assert_eq!(membership_proof.highest_index, highest_index);

        let elements = membership_proof.elements;
        assert_eq!(elements.len(), hashes.len());

        for (idx, element) in elements.iter().enumerate() {
            let range = Range::new(
                element.range.as_ref().unwrap().from,
                element.range.as_ref().unwrap().to,
            )
            .unwrap();
            assert_eq!(range, hashes.get(idx).unwrap().range);
            let expected_hash = &hashes.get(idx).unwrap().hash;
            let bytes = element.hash.as_ref().unwrap().data.as_slice();
            assert_eq!(bytes.len(), expected_hash.as_ref().len());
            assert_eq!(bytes, expected_hash.as_ref());
        }
    }
}
