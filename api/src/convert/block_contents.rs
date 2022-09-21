// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from blockchain::BlockContents

use crate::{blockchain, external, ConversionError};
use mc_blockchain_types::BlockContents;
use mc_transaction_core::{
    mint::{MintTx, ValidatedMintConfigTx},
    ring_signature::KeyImage,
    tx::TxOut,
};

impl From<&BlockContents> for blockchain::BlockContents {
    fn from(source: &BlockContents) -> Self {
        let mut block_contents = blockchain::BlockContents::new();

        let key_images = source
            .key_images
            .iter()
            .map(external::KeyImage::from)
            .collect();

        let outputs = source.outputs.iter().map(external::TxOut::from).collect();

        let validated_mint_config_txs = source
            .validated_mint_config_txs
            .iter()
            .map(external::ValidatedMintConfigTx::from)
            .collect();

        let mint_txs = source.mint_txs.iter().map(external::MintTx::from).collect();

        block_contents.set_key_images(key_images);
        block_contents.set_outputs(outputs);
        block_contents.set_validated_mint_config_txs(validated_mint_config_txs);
        block_contents.set_mint_txs(mint_txs);
        block_contents
    }
}

impl TryFrom<&blockchain::BlockContents> for BlockContents {
    type Error = ConversionError;

    fn try_from(source: &blockchain::BlockContents) -> Result<Self, Self::Error> {
        let key_images = source
            .get_key_images()
            .iter()
            .map(KeyImage::try_from)
            .collect::<Result<_, _>>()?;

        let outputs = source
            .get_outputs()
            .iter()
            .map(TxOut::try_from)
            .collect::<Result<_, _>>()?;

        let validated_mint_config_txs = source
            .get_validated_mint_config_txs()
            .iter()
            .map(ValidatedMintConfigTx::try_from)
            .collect::<Result<_, _>>()?;

        let mint_txs = source
            .get_mint_txs()
            .iter()
            .map(MintTx::try_from)
            .collect::<Result<_, _>>()?;

        // We purposefully do not ..Default::default() here so that new fields are not
        // missed.
        Ok(BlockContents {
            key_images,
            outputs,
            validated_mint_config_txs,
            mint_txs,
        })
    }
}
