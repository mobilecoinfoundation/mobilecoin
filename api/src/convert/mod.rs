// Copyright (c) 2018-2020 MobileCoin Inc.

//! Conversions between "API types" and "domain/persistence types".
//!
//! gRPC and Protobuf provide a reduced selection of types, and so there are some differences between
//! values stored in the ledger and values transmitted over the API. This module provides conversions
//! between "equivalent" types, such as `mc_api::blockchain::Block` and `mc_transaction_core::Block`.

mod error;

// blockchain
mod archive_block;
mod block;
mod block_contents;
mod block_contents_hash;
mod block_id;
mod block_signature;

// external
mod account_key;
mod amount;
mod compressed_ristretto;
mod curve_scalar;
mod ed25519_signature;
mod key_image;
mod public_address;
mod ring_mlsag;
mod ristretto_private;
mod signature_rct_bulletproofs;
mod tx;
mod tx_hash;
mod tx_in;
mod tx_out;
mod tx_out_confirmation_number;
mod tx_out_membership_element;
mod tx_out_membership_proof;
mod tx_prefix;

pub use account_key::*;
pub use amount::*;
pub use archive_block::*;
pub use block::*;
pub use block_contents::*;
pub use block_contents_hash::*;
pub use block_id::*;
pub use block_signature::*;
pub use compressed_ristretto::*;
pub use curve_scalar::*;
pub use ed25519_signature::*;
pub use error::ConversionError;
pub use key_image::*;
pub use public_address::*;
pub use ring_mlsag::*;
pub use ristretto_private::*;
pub use signature_rct_bulletproofs::*;
pub use tx::*;
pub use tx_hash::*;
pub use tx_in::*;
pub use tx_out::*;
pub use tx_out_confirmation_number::*;
pub use tx_out_membership_element::*;
pub use tx_out_membership_proof::*;
pub use tx_prefix::*;

use std::path::PathBuf;

/// Helper method for getting the suggested path/filename for a given block index.
pub fn block_num_to_s3block_path(block_index: mc_transaction_core::BlockIndex) -> PathBuf {
    let filename = format!("{:016x}.pb", block_index);
    let mut path = PathBuf::new();
    for i in 0..7 {
        path.push(&filename[i * 2..i * 2 + 2]);
    }
    path.push(filename);
    path
}

/// Helper method for getting the suggested path/filename of a "merged block".
/// A "merged block" is a consecutive collection of blocks that were joined together to speed up
/// ledger syncing.
/// `bucket_size` specifies how many blocks are expected to be joined together.
pub fn merged_block_num_to_s3block_path(
    bucket_size: u64,
    first_block_index: mc_transaction_core::BlockIndex,
) -> PathBuf {
    let base_dir = format!("merged-{}", bucket_size);
    let mut path = PathBuf::new();
    path.push(base_dir);
    path.push(block_num_to_s3block_path(first_block_index));
    path
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::From;

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
