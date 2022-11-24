//! Transaction signer types, used for communication with external signer implementations

use std::path::Path;

use clap::Parser;
use log::{debug};
use serde::{
    Serialize,
    de::DeserializeOwned,
};
use rand_core::OsRng;

use mc_core::{
    traits::{KeyImageComputer, ViewAccountProvider},
};
use mc_crypto_ring_signature_signer::{RingSigner};

pub use mc_transaction_extra::UnsignedTx;
pub use mc_transaction_core::{AccountKey, tx::Tx};

mod types;
use types::*;

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

impl Commands {

    /// Fetch account index for a given command
    pub fn account_index(&self) -> u32 {
        match self {
            Commands::GetAccount { account, .. } => *account,
            Commands::SyncTxos { account, .. } => *account,
            Commands::SignTx { account, .. } => *account,
        }
    }

    /// Fetch view account credentials
    /// 
    /// output - file to write view account information
    pub fn get_account(ctx: impl ViewAccountProvider, output: &str) -> anyhow::Result<()> {
        debug!("Loading view account keys");
        let keys: ViewAccount = match ctx.account() {
            Ok(v) => v.into(),
            Err(e) => return Err(anyhow::anyhow!("Failed to load view account keys: {:?}", e)),
        };

        debug!("Writing view account information to: {}", output);
        write_output(output, &keys)?;

        Ok(())
    }

    /// Sync TxOuts
    /// 
    /// input - file containing a list of subaddress indices and tx_out_public_keys
    /// output - file to write list of tx_out_public_keys and resolved key_images
    pub fn sync_txos(ctx: impl KeyImageComputer, input: &str, output: &str) -> anyhow::Result<()> {
        // Load unsynced txout_public_key pairs
        debug!("Reading unsynced TxOuts from '{}'", input);
        let unsynced: Vec<TxoUnsynced> = read_input(input)?;

        // Compute key images
        // Since we're provided with a subaddress index,
        // assume TxOut ownership is correct.
        let mut synced: Vec<TxoSynced> = Vec::new();
        for TxoUnsynced{subaddress, tx_out_public_key} in unsynced {

            let key_image = match ctx.compute_key_image(subaddress, &tx_out_public_key) {
                Ok(v) => v,
                Err(e) => return Err(anyhow::anyhow!("Failed to compute key image: {:?}", e)),
            };

            synced.push(TxoSynced{
                tx_out_public_key: tx_out_public_key.clone(),
                key_image,
            });
        }

        // Write matched key images
        debug!("Writing synced TxOuts to '{}'", output);
        write_output(output, &synced)?;

        Ok(())
    }


    /// Sync an unsigned transaction
    /// 
    /// input - file containing the unsigned transaction object
    /// output - file to write the signed transaction output
    pub fn sign_tx(ctx: impl RingSigner, input: &str, output: &str) -> anyhow::Result<()> {
        // Load unsigned transaction object
        debug!("Reading unsigned transaction from '{}'", input);
        let unsigned_tx: UnsignedTx = read_input(input)?;

        // Sign transaction
        let signed_tx = match unsigned_tx.sign(&ctx, None, &mut OsRng{}) {
            Ok(v) => v,
            Err(e) => {
                return Err(anyhow::anyhow!("Failed to sign transaction: {:?}", e));
            }
        };

        // Write signed transaction output
        debug!("Writing signed transaction to '{}'", output);
        write_output(output, &signed_tx)?;

        Ok(())
    }
}


/// Helper to read and deserialize input files
pub fn read_input<T: DeserializeOwned>(file_name: &str) -> anyhow::Result<T> {
    debug!("Reading input from '{}'", file_name);

    let s = std::fs::read_to_string(file_name)?;

    // Determine format from file name
    let p = Path::new(file_name);

    // Decode based on input extension
    let v = match p.extension().map(|e| e.to_str() ).flatten() {
        // Encode to JSON for `.json` files
        Some("json") => serde_json::from_str(&s)?,
        _ => return Err(anyhow::anyhow!("unsupported output file format")),
    };

    Ok(v)
}


/// Helper to serialize and write output files
pub fn write_output(file_name: &str, value: &impl Serialize) -> anyhow::Result<()> {
    debug!("Writing output to '{}'", file_name);

    // Determine format from file name
    let p = Path::new(file_name);
    match p.extension().map(|e| e.to_str() ).flatten() {
        // Encode to JSON for `.json` files
        Some("json") => {
            let s = serde_json::to_string(value)?;
            std::fs::write(p, s)?;
        },
        _ => return Err(anyhow::anyhow!("unsupported output file format")),
    }

    Ok(())
}
