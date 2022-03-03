//! Convert to/from blockchain::BlockContents

use crate::{blockchain, convert::ConversionError, external};
use mc_transaction_core::{
    mint::{MintTx, SetMintConfigTx},
    ring_signature::KeyImage,
    tx::TxOut,
    BlockContents,
};
use protobuf::RepeatedField;
use std::convert::TryFrom;

impl From<&mc_transaction_core::BlockContents> for blockchain::BlockContents {
    fn from(source: &mc_transaction_core::BlockContents) -> Self {
        let mut block_contents = blockchain::BlockContents::new();

        let key_images: Vec<external::KeyImage> = source
            .key_images
            .iter()
            .map(external::KeyImage::from)
            .collect();

        let outputs: Vec<external::TxOut> =
            source.outputs.iter().map(external::TxOut::from).collect();

        let set_mint_config_txs: Vec<_> = source
            .set_mint_config_txs
            .iter()
            .map(external::SetMintConfigTx::from)
            .collect();

        let mint_txs: Vec<_> = source.mint_txs.iter().map(external::MintTx::from).collect();

        block_contents.set_key_images(RepeatedField::from_vec(key_images));
        block_contents.set_outputs(RepeatedField::from_vec(outputs));
        block_contents.set_set_mint_config_txs(RepeatedField::from_vec(set_mint_config_txs));
        block_contents.set_mint_txs(RepeatedField::from_vec(mint_txs));
        block_contents
    }
}

impl TryFrom<&blockchain::BlockContents> for mc_transaction_core::BlockContents {
    type Error = ConversionError;

    fn try_from(source: &blockchain::BlockContents) -> Result<Self, Self::Error> {
        let key_images: Vec<KeyImage> = source
            .get_key_images()
            .iter()
            .map(KeyImage::try_from)
            .collect::<Result<_, _>>()?;

        let outputs: Vec<TxOut> = source
            .get_outputs()
            .iter()
            .map(TxOut::try_from)
            .collect::<Result<_, _>>()?;

        let set_mint_config_txs = source
            .get_set_mint_config_txs()
            .iter()
            .map(SetMintConfigTx::try_from)
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
            set_mint_config_txs,
            mint_txs,
        })
    }
}
