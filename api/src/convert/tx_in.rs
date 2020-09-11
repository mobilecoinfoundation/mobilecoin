//! Convert to/from external::TxIn.

use crate::{convert::ConversionError, external};
use mc_transaction_core::{tx, tx::TxOutMembershipProof};
use std::convert::TryFrom;

/// Convert tx::TxIn --> external::TxIn.
impl From<&tx::TxIn> for external::TxIn {
    fn from(source: &tx::TxIn) -> Self {
        let mut tx_in = external::TxIn::new();

        let ring: Vec<external::TxOut> = source.ring.iter().map(external::TxOut::from).collect();
        tx_in.set_ring(ring.into());

        let proofs: Vec<external::TxOutMembershipProof> = source
            .proofs
            .iter()
            .map(external::TxOutMembershipProof::from)
            .collect();
        tx_in.set_proofs(proofs.into());

        tx_in
    }
}

/// Convert external::TxIn --> tx::TxIn.
impl TryFrom<&external::TxIn> for tx::TxIn {
    type Error = ConversionError;

    fn try_from(source: &external::TxIn) -> Result<Self, Self::Error> {
        let mut ring: Vec<tx::TxOut> = Vec::new();
        for out in source.get_ring() {
            let tx_out = tx::TxOut::try_from(out)?;
            ring.push(tx_out);
        }

        let mut proofs: Vec<TxOutMembershipProof> = Vec::new();
        for proof in source.get_proofs() {
            let tx_proof = TxOutMembershipProof::try_from(proof)?;
            proofs.push(tx_proof);
        }

        let tx_in = tx::TxIn { ring, proofs };
        Ok(tx_in)
    }
}
