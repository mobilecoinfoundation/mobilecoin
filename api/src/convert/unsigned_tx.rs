use mc_transaction_std::UnsignedTx;

use crate::external;

impl From<&UnsignedTx> for external::UnsignedTx {
    fn from(source: &UnsignedTx) -> Self {
        let mut unsigned_tx = external::UnsignedTx::new();
        unsigned_tx.set_tx_prefix((&source.tx_prefix).into());
        unsigned_tx.set_rings(protobuf::RepeatedField::from_vec(
            source.rings.iter().map(|input| input.into()).collect(),
        ));
        unsigned_tx.set_output_secrets(protobuf::RepeatedField::from_vec(
            source
                .output_secrets
                .iter()
                .map(|output| output.into())
                .collect(),
        ));
        unsigned_tx.set_block_version(*source.block_version);
        unsigned_tx
    }
}
