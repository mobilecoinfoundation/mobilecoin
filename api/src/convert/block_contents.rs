//! Convert to/from blockchain::BlockContents

use crate::{blockchain, convert::ConversionError, external};
use mc_transaction_core::{ring_signature::KeyImage, tx, BlockContents};
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

        block_contents.set_key_images(RepeatedField::from_vec(key_images));
        block_contents.set_outputs(RepeatedField::from_vec(outputs));
        block_contents
    }
}

impl TryFrom<&blockchain::BlockContents> for mc_transaction_core::BlockContents {
    type Error = ConversionError;

    fn try_from(source: &blockchain::BlockContents) -> Result<Self, Self::Error> {
        let mut key_images: Vec<KeyImage> = Vec::new();
        for key_image in source.get_key_images() {
            key_images.push(KeyImage::try_from(key_image)?);
        }

        let mut outputs: Vec<tx::TxOut> = Vec::new();
        for output in source.get_outputs() {
            outputs.push(tx::TxOut::try_from(output)?);
        }
        Ok(BlockContents::new(key_images, outputs))
    }
}
