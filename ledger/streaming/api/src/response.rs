// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{streaming_blocks::SubscribeResponse, BlockStreamComponents, Result};
use mc_crypto_keys::{Ed25519Pair, Ed25519Public, Ed25519Signature, Signer, Verifier};
use protobuf::Message;
use std::convert::TryFrom;

pub fn make_subscribe_response(
    data: &BlockStreamComponents,
    signer: &Ed25519Pair,
) -> Result<SubscribeResponse> {
    let mut proto = SubscribeResponse::new();
    proto.set_result(data.into());

    let result_bytes = proto.get_result().write_to_bytes()?;
    let signature = signer.try_sign(&result_bytes)?;
    proto.set_result_signature((&signature).into());
    Ok(proto)
}

pub fn parse_subscribe_response(
    proto: &SubscribeResponse,
    public_key: &Ed25519Public,
) -> Result<BlockStreamComponents> {
    let result = BlockStreamComponents::try_from(proto.get_result())?;
    let result_signature = Ed25519Signature::try_from(proto.get_result_signature())?;
    // Validate result against result_signature.
    let result_bytes = proto.get_result().write_to_bytes()?;
    public_key.verify(&result_bytes, &result_signature)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    //use super::*;

    #[test]
    fn validates() {
        // TODO
    }
}
