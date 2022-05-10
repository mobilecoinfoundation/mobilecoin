// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from blockchain::BlockMetadata.

use crate::{blockchain, ConversionError};
use mc_transaction_core::{BlockMetadata, SignedBlockMetadata};
use std::convert::{TryFrom, TryInto};

impl From<&BlockMetadata> for blockchain::BlockMetadata {
    fn from(src: &BlockMetadata) -> Self {
        let mut proto = Self::new();
        proto.set_block_id(src.block_id().into());
        if let Some(qs) = src.quorum_set() {
            proto.set_quorum_set(qs.into());
        }
        if let Some(avr) = src.verification_report() {
            proto.set_verification_report(avr.into());
        }
        proto
    }
}

impl TryFrom<&blockchain::BlockMetadata> for BlockMetadata {
    type Error = ConversionError;

    fn try_from(src: &blockchain::BlockMetadata) -> Result<Self, Self::Error> {
        let block_id = src.get_block_id().try_into()?;
        let quorum_set = src.quorum_set.as_ref().map(TryInto::try_into).transpose()?;
        let report = src
            .verification_report
            .as_ref()
            .map(TryInto::try_into)
            .transpose()?;
        Ok(BlockMetadata::new(block_id, quorum_set, report))
    }
}

impl From<&SignedBlockMetadata> for blockchain::SignedBlockMetadata {
    fn from(src: &SignedBlockMetadata) -> Self {
        let mut proto = Self::new();
        proto.set_contents(src.contents().into());
        proto.set_node_key(src.node_key().into());
        proto.set_signature(src.signature().into());
        proto
    }
}

impl TryFrom<&blockchain::SignedBlockMetadata> for SignedBlockMetadata {
    type Error = ConversionError;

    fn try_from(src: &blockchain::SignedBlockMetadata) -> Result<Self, Self::Error> {
        let contents = src.get_contents().try_into()?;
        let node_key = src.get_node_key().try_into()?;
        let signature = src.get_signature().try_into()?;
        Ok(SignedBlockMetadata::new(contents, node_key, signature))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_attest_verifier_types::VerificationReport;
    use mc_consensus_scp_core::test_utils::{test_node_id_and_signer, three_node_dense_graph};
    use mc_transaction_core::Block;

    fn make_metadata() -> BlockMetadata {
        let block = Block::new_origin_block(&[]);
        let quorum_set = Some(three_node_dense_graph().0 .1);
        let verification_report = Some(VerificationReport {
            sig: vec![1u8; 32].into(),
            chain: vec![vec![1u8; 1], vec![2u8; 2], vec![3u8; 3]],
            http_body: "testing".to_owned(),
        });
        BlockMetadata::new(block.id, quorum_set, verification_report)
    }

    fn make_signed_metadata() -> SignedBlockMetadata {
        let key_pair = test_node_id_and_signer(42).1;
        SignedBlockMetadata::from_contents_and_keypair(make_metadata(), &key_pair).unwrap()
    }

    #[test]
    fn block_metadata_round_trip() {
        let source = make_metadata();

        // decode(encode(source)) should be the identity function.
        {
            let proto = blockchain::BlockMetadata::from(&source);
            let recovered = BlockMetadata::try_from(&proto).unwrap();
            assert_eq!(source, recovered);
        }
    }

    #[test]
    fn signed_block_metadata_round_trip() {
        let source = make_signed_metadata();

        // decode(encode(source)) should be the identity function.
        {
            let proto = blockchain::SignedBlockMetadata::from(&source);
            let recovered = SignedBlockMetadata::try_from(&proto).unwrap();
            assert_eq!(source, recovered);
        }
    }
}
