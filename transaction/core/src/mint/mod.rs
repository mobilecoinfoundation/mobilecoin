// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Minting transactions and associated data structures.

mod config;
mod tx;

pub use config::{MintConfig, SetMintConfigTx, SetMintConfigTxPrefix};
pub use tx::{MintTx, MintTxPrefix};
