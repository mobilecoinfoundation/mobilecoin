// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from mc_transaction_std::UnsignedTx.

use crate::{external, ConversionError};
use mc_blockchain_types::BlockVersion;
use mc_transaction_std::UnsignedTx;

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

impl TryFrom<&external::UnsignedTx> for UnsignedTx {
    type Error = ConversionError;

    fn try_from(source: &external::UnsignedTx) -> Result<Self, Self::Error> {
        Ok(UnsignedTx {
            tx_prefix: source.get_tx_prefix().try_into()?,
            rings: source
                .get_rings()
                .iter()
                .map(|input| input.try_into())
                .collect::<Result<_, _>>()?,
            output_secrets: source
                .get_output_secrets()
                .iter()
                .map(|output| output.try_into())
                .collect::<Result<_, _>>()?,
            block_version: BlockVersion::try_from(source.get_block_version())?,
        })
    }
}
