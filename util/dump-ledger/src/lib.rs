// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A utility to dump a ledger's contents as JSON.

#![deny(missing_docs)]

mod error;

use clap::Parser;
use mc_blockchain_types::BlockIndex;
use mc_ledger_db::Ledger;
use serde_json::to_string_pretty as to_json;

pub use error::{Error, Result};

/// Parameters for [dump_ledger].
#[derive(Debug, Default, Clone, Parser)]
pub struct DumpParams {
    /// Optional first index; defaults to 0.
    #[clap(long, short, default_value = "0", env = "MC_FIRST_INDEX")]
    pub first_index: BlockIndex,
    /// Optional last index; defaults to `num_blocks - 1`.
    #[clap(long, short, env = "MC_LAST_INDEX")]
    pub last_index: Option<BlockIndex>,
}

/// Dump the blocks in the given [Ledger] to JSON.
pub fn dump_ledger(ledger: &impl Ledger, params: DumpParams) -> Result<String> {
    let last = match params.last_index {
        Some(last) => last,
        None => ledger.num_blocks()? - 1,
    };

    let blocks = (params.first_index..=last)
        .map(|block_index| Ok(ledger.get_block_data(block_index)?))
        .collect::<Result<Vec<_>>>()?;

    Ok(to_json(&blocks)?)
}

#[cfg(test)]
mod tests {
    use mc_ledger_db::test_utils::mock_ledger::get_mock_ledger_and_blocks;

    use super::*;

    #[test]
    fn without_overrides() {
        let (ledger, blocks) = get_mock_ledger_and_blocks(10);
        let json = dump_ledger(&ledger, DumpParams::default()).unwrap();
        let expected_json = to_json(&blocks).unwrap();

        assert_eq!(json, expected_json);
    }

    #[test]
    fn override_first() {
        let (ledger, blocks) = get_mock_ledger_and_blocks(10);
        let json = dump_ledger(
            &ledger,
            DumpParams {
                first_index: 2,
                last_index: None,
            },
        )
        .unwrap();
        let expected_json = to_json(&blocks[2..]).unwrap();

        assert_eq!(json, expected_json);
    }

    #[test]
    fn override_last() {
        let (ledger, blocks) = get_mock_ledger_and_blocks(10);
        let json = dump_ledger(
            &ledger,
            DumpParams {
                first_index: 0,
                last_index: Some(5),
            },
        )
        .unwrap();
        let expected_json = to_json(&blocks[..6]).unwrap();

        assert_eq!(json, expected_json);
    }

    #[test]
    fn override_both() {
        let (ledger, blocks) = get_mock_ledger_and_blocks(10);
        let json = dump_ledger(
            &ledger,
            DumpParams {
                first_index: 2,
                last_index: Some(5),
            },
        )
        .unwrap();
        let expected_json = to_json(&blocks[2..=5]).unwrap();

        assert_eq!(json, expected_json);
    }
}
