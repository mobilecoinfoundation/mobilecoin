// Copyright (c) 2018-2022 The MobileCoin Foundation

use mc_crypto_digestible::Digestible;
use serde::{Deserialize, Serialize};

/// TODO
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Digestible,
)]
pub struct MintTx {
    pub amount: u64,
    pub tombstone_block: u64,
}
