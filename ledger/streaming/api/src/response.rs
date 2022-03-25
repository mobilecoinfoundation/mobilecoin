// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{streaming_blocks::SubscribeResponse, BlockStreamComponents, Result};
use mc_crypto_digestible::{Digestible, MerlinTranscript};
use mc_crypto_keys::{Ed25519Pair, Ed25519Public, Ed25519Signature, Signer, Verifier};
use std::convert::TryFrom;

/// Creates a signed SubscribeResponse from the given components and signer.
pub fn make_subscribe_response(
    data: &BlockStreamComponents,
    signer: &Ed25519Pair,
) -> Result<SubscribeResponse> {
    let mut proto = SubscribeResponse::new();
    proto.set_result(data.into());

    let digest = get_digest(data);
    let signature = signer.try_sign(&digest)?;
    proto.set_result_signature((&signature).into());
    Ok(proto)
}

/// Parses and validates BlockStreamComponents from a given SubscribeResponse
/// and public key.
pub fn parse_subscribe_response(
    proto: &SubscribeResponse,
    public_key: &Ed25519Public,
) -> Result<BlockStreamComponents> {
    let result = BlockStreamComponents::try_from(proto.get_result())?;
    let result_signature = Ed25519Signature::try_from(proto.get_result_signature())?;
    // Validate result against result_signature.
    let digest = get_digest(&result);
    public_key.verify(&digest, &result_signature)?;
    Ok(result)
}

fn get_digest(data: &BlockStreamComponents) -> [u8; 32] {
    data.digest32::<MerlinTranscript>(b"block_stream_components")
}

#[cfg(test)]
mod tests {
    use std::assert_matches::assert_matches;

    use super::*;
    use crate::{test_utils::make_components, Error};
    use mc_util_from_random::FromRandom;
    use rand_core::SeedableRng;
    use rand_hc::Hc128Rng;

    #[test]
    fn validate() {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);
        let signer = Ed25519Pair::from_random(&mut rng);
        let public_key = signer.public_key();
        let signer2 = Ed25519Pair::from_random(&mut rng);
        let public_key2 = signer2.public_key();

        let components = make_components(2);
        let responses: Vec<SubscribeResponse> = components
            .iter()
            .map(|c| make_subscribe_response(&c, &signer))
            .collect::<Result<Vec<_>>>()
            .expect("make_subscribe_response");

        responses
            .iter()
            .zip(components.iter())
            .for_each(|(response, components)| {
                let digest = get_digest(components);
                let signature = signer.sign(&digest);
                assert_eq!(*response.get_result_signature(), (&signature).into());

                let parsed = parse_subscribe_response(response, &public_key)
                    .expect("parse_subscribe_response");
                assert_eq!(parsed, *components);

                assert_matches!(
                    parse_subscribe_response(response, &public_key2),
                    Err(Error::Signature(_))
                );
            });
    }
}
