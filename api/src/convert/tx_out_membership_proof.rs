//! Convert to/from external::TxOutMembershipProof

use crate::{convert::ConversionError, external};
use mc_transaction_core::{
    membership_proofs::Range,
    tx::{TxOutMembershipElement, TxOutMembershipProof},
};
use protobuf::RepeatedField;
use std::convert::TryFrom;

/// Convert TxOutMembershipProof -> external::MembershipProof.
impl From<&TxOutMembershipProof> for external::TxOutMembershipProof {
    fn from(tx_out_membership_proof: &TxOutMembershipProof) -> Self {
        let mut membership_proof = external::TxOutMembershipProof::new();
        membership_proof.set_index(tx_out_membership_proof.index);
        membership_proof.set_highest_index(tx_out_membership_proof.highest_index);

        let elements: Vec<external::TxOutMembershipElement> = tx_out_membership_proof
            .elements
            .iter()
            .map(external::TxOutMembershipElement::from)
            .collect();

        membership_proof.set_elements(RepeatedField::from_vec(elements));
        membership_proof
    }
}

/// Convert external::MembershipProof --> TxOutMembershipProof.
impl TryFrom<&external::TxOutMembershipProof> for TxOutMembershipProof {
    type Error = ConversionError;

    fn try_from(membership_proof: &external::TxOutMembershipProof) -> Result<Self, Self::Error> {
        let index: u64 = membership_proof.get_index();
        let highest_index: u64 = membership_proof.get_highest_index();

        let mut elements = Vec::<TxOutMembershipElement>::default();
        for element in membership_proof.get_elements() {
            let range = Range::new(element.get_range().get_from(), element.get_range().get_to())
                .map_err(|_e| ConversionError::Other)?;

            let bytes: &[u8] = element.get_hash().get_data();
            let mut hash = [0u8; 32];
            if bytes.len() != hash.len() {
                return Err(ConversionError::ArrayCastError);
            }
            hash.copy_from_slice(bytes);
            elements.push(TxOutMembershipElement::new(range, hash));
        }
        let tx_out_membership_proof = TxOutMembershipProof::new(index, highest_index, elements);
        Ok(tx_out_membership_proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// Convert TxOutMembershipProof -> external::TxOutMembershipProof.
    fn test_membership_proof_from() {
        let index: u64 = 128_465;
        let highest_index: u64 = 781_384_772_994;
        let mut hashes = Vec::<TxOutMembershipElement>::default();
        // Add some arbitrary hashes.
        hashes.push(TxOutMembershipElement::new(
            Range::new(0, 1).unwrap(),
            [2u8; 32],
        ));
        hashes.push(TxOutMembershipElement::new(
            Range::new(0, 3).unwrap(),
            [4u8; 32],
        ));
        hashes.push(TxOutMembershipElement::new(
            Range::new(0, 7).unwrap(),
            [8u8; 32],
        ));
        let tx_out_membership_proof =
            TxOutMembershipProof::new(index, highest_index, hashes.clone());

        let membership_proof = external::TxOutMembershipProof::from(&tx_out_membership_proof);
        assert_eq!(membership_proof.get_index(), index);
        assert_eq!(membership_proof.get_highest_index(), highest_index);

        let elements = membership_proof.get_elements();
        assert_eq!(elements.len(), hashes.len());

        for (idx, element) in elements.iter().enumerate() {
            let range =
                Range::new(element.get_range().get_from(), element.get_range().get_to()).unwrap();
            assert_eq!(range, hashes.get(idx).unwrap().range);
            let expected_hash = &hashes.get(idx).unwrap().hash;
            let bytes = element.get_hash().get_data();
            assert_eq!(bytes.len(), expected_hash.as_ref().len());
            assert_eq!(bytes, expected_hash.as_ref());
        }
    }
}
