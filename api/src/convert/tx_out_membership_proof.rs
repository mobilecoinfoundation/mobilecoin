//! Convert to/from external::TxOutMembershipProof

use crate::{external, ConversionError};
use mc_transaction_core::tx::{TxOutMembershipElement, TxOutMembershipProof};

impl From<&TxOutMembershipProof> for external::TxOutMembershipProof {
    fn from(src: &TxOutMembershipProof) -> Self {
        Self {
            index: src.index,
            highest_index: src.highest_index,
            elements: src
                .elements
                .iter()
                .map(external::TxOutMembershipElement::from)
                .collect(),
        }
    }
}

impl TryFrom<&external::TxOutMembershipProof> for TxOutMembershipProof {
    type Error = ConversionError;

    fn try_from(src: &external::TxOutMembershipProof) -> Result<Self, Self::Error> {
        let elements = src
            .elements
            .iter()
            .map(TxOutMembershipElement::try_from)
            .collect::<Result<_, _>>()?;

        Ok(TxOutMembershipProof::new(
            src.index,
            src.highest_index,
            elements,
        ))
    }
}

#[cfg(test)]
mod tests {
    use mc_transaction_core::membership_proofs::Range;

    use super::*;

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
            let range = Range::try_from(element.range.as_ref().unwrap()).unwrap();
            assert_eq!(range, hashes.get(idx).unwrap().range);
            let expected_hash = &hashes.get(idx).unwrap().hash;
            let bytes = &element.hash.as_ref().unwrap().data;
            assert_eq!(bytes, expected_hash.as_ref());
        }
    }
}
