// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Conversions between "API types" and "domain/persistence types".
//!
//! gRPC and Protobuf provide a reduced selection of types, and so there are
//! some differences between values stored in the ledger and values transmitted
//! over the API. This module provides conversions between "equivalent" types,
//! such as `mc_api::blockchain::Block` and `mc_blockchain_types::Block`.

// blockchain
mod archive_block;
mod block;
mod block_contents;
mod block_contents_hash;
mod block_id;
mod block_metadata;
mod block_signature;

// external
mod account_key;
mod amount;
mod collateral;
mod compressed_ristretto;
mod curve_scalar;
mod dcap_evidence;
mod ed25519_multisig;
mod ed25519_signature;
mod enclave_report_data_contents;
mod input_ring;
mod input_secret;
mod key_image;
mod mint_config;
mod mint_tx;
mod node;
mod output_secret;
mod public_address;
mod quorum_set;
mod quote3;
mod reduced_tx_out;
mod ring_mlsag;
mod ristretto_private;
mod signature_rct_bulletproofs;
mod signed_contingent_input;
mod signing_data;
mod tx;
mod tx_hash;
mod tx_in;
mod tx_out;
mod tx_out_confirmation_number;
mod tx_out_membership_element;
mod tx_out_membership_proof;
mod tx_prefix;
mod unsigned_tx;
mod validated_mint_config;
mod verification_report;
mod verification_signature;
mod watcher;

// printable
mod tx_out_gift_code;

// error
mod error;
pub use error::ConversionError;

use mc_blockchain_types::BlockIndex;
use protobuf::Message as ProtoMessage;
use std::path::PathBuf;

/// Helper method for getting the suggested path/filename for a given block
/// index.
pub fn block_num_to_s3block_path(block_index: BlockIndex) -> PathBuf {
    let filename = format!("{block_index:016x}.pb");
    let mut path = PathBuf::new();
    for i in 0..7 {
        path.push(&filename[i * 2..i * 2 + 2]);
    }
    path.push(filename);
    path
}

/// Helper method for getting the suggested path/filename of a "merged block".
/// A "merged block" is a consecutive collection of blocks that were joined
/// together to speed up ledger syncing.
/// `bucket_size` specifies how many blocks are expected to be joined together.
pub fn merged_block_num_to_s3block_path(
    bucket_size: u64,
    first_block_index: BlockIndex,
) -> PathBuf {
    let base_dir = format!("merged-{bucket_size}");
    let mut path = PathBuf::new();
    path.push(base_dir);
    path.push(block_num_to_s3block_path(first_block_index));
    path
}

/// Encode a protobuf type to the protobuf representation.
///
/// This makes it easy to convert from a protobuf to a rust type by way of a
/// prost implementation. While this requires converting to a protobuf stream
/// and back again, this allows for placing most of the complex logic in the
/// `prost` implementation and keeping the local `try_from` implementations
/// simple.
///
/// For example:
/// ```ignore
///     let bytes = encode_to_protobuf_vec(proto_type)?;
///     let prost = prost::TYPENAME::decode(bytes.as_slice())?;
///     let rust_type = TYPENAME::try_from(prost)?;
/// ```
pub(crate) fn encode_to_protobuf_vec<T: ProtoMessage>(msg: &T) -> Result<Vec<u8>, ConversionError> {
    let bytes = msg.write_to_bytes().map_err(|_| ConversionError::Other)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_num_to_s3block_path() {
        assert_eq!(
            block_num_to_s3block_path(1),
            PathBuf::from("00/00/00/00/00/00/00/0000000000000001.pb"),
        );

        assert_eq!(
            block_num_to_s3block_path(0x1a2b_3c4e_5a6b_7c8d),
            PathBuf::from("1a/2b/3c/4e/5a/6b/7c/1a2b3c4e5a6b7c8d.pb"),
        );
    }
}
