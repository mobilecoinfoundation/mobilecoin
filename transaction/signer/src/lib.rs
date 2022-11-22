//! Transaction signer types, used for communication with external signer implementations

use clap::Parser;
use serde::{Serialize, Deserialize};

use mc_core::{
    keys::{TxPublic},
};
use mc_core_types::{
    helpers::{pub_key_hex, const_array_hex},
};
use mc_crypto_ring_signature::KeyImage;

pub use mc_core::account::ViewAccount;
pub use mc_transaction_extra::UnsignedTx;
pub use mc_transaction_core::tx::Tx;

/// Command enumeration for offline / detached / hardware signing
#[derive(Clone, PartialEq, Debug, Parser)]
#[non_exhaustive]
pub enum Commands {
    /// Fetch account keys
    GetAccount {
        /// SLIP-0010 index for account derivation
        #[clap(long, default_value = "0")]
        account: u32,

        /// Output file to write view account object
        #[clap(long)]
        output: String,
    },
    /// Sync TXOs, recovering key images for each txo
    SyncTxos {
        /// SLIP-0010 account index for SLIP-010 derivation
        #[clap(long, default_value = "0")]
        account: u32,

        /// Input file containing unsynced TxOuts
        #[clap(long)]
        input: String,

        /// Output file to write synced TxOuts
        #[clap(long)]
        output: String,
    },
    /// Sign offline transaction, returning a signed transaction object
    SignTx {
        /// SLIP-0010 account index for SLIP-010 derivation
        #[clap(long, default_value = "0")]
        account: u32,

        /// Input file containing transaction for signing
        #[clap(long)]
        input: String,

        /// Output file to write signed transaction
        #[clap(long)]
        output: String,
    },
}

/// Unsynced TxOut instance for resolving key images
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct TxoUnsynced {
    /// Subaddress for unsynced TxOut
    pub subaddress: u64,

    /// tx_public_key for unsynced TxOut
    #[serde(with = "pub_key_hex")]
    pub tx_public_key: TxPublic,
}

/// Synced TxOut instance, contains public key and resolved key image for owned TxOuts
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct TxoSynced {
    /// tx_public_key for synced TxOut
    #[serde(with = "pub_key_hex")]
    pub tx_public_key: TxPublic,

    /// recovered key image for synced TxOut
    #[serde(with = "const_array_hex")]
    pub key_image: KeyImage,
}
