// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Minting transactions and associated data structures.

mod config;
mod tx;
mod validation;

pub mod constants;

pub use config::{MintConfig, MintConfigTx, MintConfigTxPrefix};
pub use tx::{MintTx, MintTxPrefix};
pub use validation::{
    config::validate_mint_config_tx, error::Error as MintValidationError, tx::validate_mint_tx,
};
