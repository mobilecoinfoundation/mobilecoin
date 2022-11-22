//! Offline transaction signer implementation
//! 
//! WIP port / simplification from https://github.com/mobilecoinofficial/full-service/blob/fefe6f645d676b393ece2f607f0081304141b590/transaction-signer/src/bin/main.rs#L337

use std::path::Path;

use log::{debug, info};
use bip39::{Language, Mnemonic, MnemonicType};
use clap::Parser;
use serde::{Serialize, Deserialize, de::DeserializeOwned};
use rand_core::OsRng;

use mc_core::{
    account::{Account, ViewAccount},
    slip10::Slip10KeyGenerator,
    subaddress::Subaddress,
};
use mc_crypto_ring_signature_signer::LocalRingSigner;
use mc_transaction_core::{
    AccountKey,
    onetime_keys::recover_onetime_private_key,
    ring_signature::KeyImage,
};
use mc_transaction_signer::{
    Commands,
    TxoUnsynced,
    TxoSynced,
    UnsignedTx,
};


#[derive(Clone, PartialEq, Debug, Parser)]
struct Args {

    /// Account secrets file
    #[clap(long, short, default_value="mc_secrets.json")]
    secret_file: String,

    #[command(subcommand)]
    action: Actions,
}

#[derive(Clone, PartialEq, Debug, Parser)]
enum Actions {
    /// Create a new offline account, writing secrets to the output file
    Create {
        /// Optional account name
        #[clap(short, long)]
        name: Option<String>,

        /// File name for account secrets to be written to
        #[clap(short, long)]
        output: String,
    },
    /// Import an existing offline account via mnemonic
    Import {
        /// Optional account name
        #[clap(short, long)]
        name: Option<String>,

        /// Mnemonic for account import
        mnemonic: String,

        /// File for account secrets to be written to
        #[clap(short, long)]
        output: String,
    },

    // Implement shared signer commands
    #[command(flatten)]
    Signer(Commands),
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
struct AccountSecrets {
    name: Option<String>,
    mnemonic: String,
}

fn main() -> anyhow::Result<()> {

    // Parse command line arguments
    let args = Args::parse();
    
    // Run commands
    match &args.action {
        Actions::Create { name, output } | Actions::Import { name, output, .. } => {
            // Generate or parse mnemonic
            let mnemonic = match &args.action {
                Actions::Import{ mnemonic, .. } => Mnemonic::from_phrase(&mnemonic, Language::English).unwrap(),
                _ => Mnemonic::new(MnemonicType::Words24, Language::English),
            };

            // Generate secrets object
            let s = AccountSecrets{
                name: name.clone(),
                mnemonic: mnemonic.to_string(),
            };

            // Check we're not overwriting an existing secret file
            if Path::new(output).exists() {
                return Err(anyhow::anyhow!("creation would overwrite existing secrets file '{}'", output));
            }

            // Otherwise write out new secrets
            write_output(output, &s)?;
            info!("Account secrets written to '{}'", output);
        },
        Actions::Signer(c) => {
            // Load account secrets
            let secrets: AccountSecrets = read_input(&args.secret_file)?;
            let mnemonic = Mnemonic::from_phrase(&secrets.mnemonic, Language::English)?;

            // Perform SLIP-0010 derivation
            let index = match c {
                Commands::GetAccount{ account, .. } | Commands::SyncTxos{ account, .. } | Commands::SignTx{ account, .. } => account,
                _ => unreachable!(),
            };
            let slip10key = mnemonic.derive_slip10_key(*index);

            // Generate account from secrets
            let a = Account::from(&slip10key);

            match c {
                Commands::GetAccount { output, .. } => {
                    let v = ViewAccount::from(&a);
                    write_output(output, &v)?;
                }
                Commands::SyncTxos { input, output, .. } => {
                    // Load unsynced txout_public_key pairs
                    debug!("Reading unsynced TxOuts from '{}'", input);
                    let unsynced: Vec<TxoUnsynced> = read_input(input)?;

                    // Compute key images
                    let mut synced: Vec<TxoSynced> = Vec::new();
                    for TxoUnsynced{subaddress, tx_public_key} in unsynced {
                        // Since we're provided with a subaddress index,
                        // assume TxOut ownership is correct.
                        let s = a.subaddress(subaddress);

                        let onetime_private_key = recover_onetime_private_key(
                            tx_public_key.as_ref(),
                            a.view_private_key().as_ref(),
                            s.spend_private_key().as_ref(),
                        );

                        synced.push(TxoSynced{
                            tx_public_key: tx_public_key.clone(),
                            key_image: KeyImage::from(&onetime_private_key),
                        });
                    }

                    // Write matched key images
                    debug!("Writing synced TxOuts to '{}'", output);
                    write_output(output, &synced)?;
                },
                Commands::SignTx { input, output, .. } => {
                    // Load unsigned transactions
                    debug!("Reading unsigned transaction from '{}'", input);
                    let unsigned_tx: UnsignedTx = read_input(input)?;

                    // Setup local ring signer
                    let ring_signer = LocalRingSigner::from(&AccountKey::new(
                        a.spend_private_key().as_ref(),
                        a.view_private_key().as_ref(),
                    ));

                    // Sign transaction
                    let signed_tx = match unsigned_tx.sign(&ring_signer, None, &mut OsRng{}) {
                        Ok(v) => v,
                        Err(e) => {
                            return Err(anyhow::anyhow!("Failed to sign transaction: {:?}", e));
                        }
                    };

                    // Write signed transaction
                    debug!("Writing signed transaction to '{}'", output);
                    write_output(output, &signed_tx)?;
                },
                _ => (),
            }
        }
    }

    Ok(())
}

/// Helper to read input files where required
fn read_input<T: DeserializeOwned>(file_name: &str) -> anyhow::Result<T> {
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


/// Helper to write output files if `--output` argument is provided
fn write_output(file_name: &str, value: &impl Serialize) -> anyhow::Result<()> {
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
