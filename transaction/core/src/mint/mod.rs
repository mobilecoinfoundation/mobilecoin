// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Minting transactions and associated data structures.

mod config;
mod tx;
mod validate;

pub mod constants;

pub use config::{MintConfig, SetMintConfigTx, SetMintConfigTxPrefix};
pub use tx::{MintTx, MintTxPrefix};
pub use validate::config::{validate_set_mint_config_tx, Error as ValidateSetMintConfigTxError};
