//! Offline transaction signer implementation
//!
//! WIP port / simplification from https://github.com/mobilecoinofficial/full-service/blob/fefe6f645d676b393ece2f607f0081304141b590/transaction-signer/src/bin/main.rs#L337

use std::path::Path;

use bip39::{Language, Mnemonic, MnemonicType};
use clap::Parser;
use log::{debug, info};
use serde::{Deserialize, Serialize};

use mc_core::{account::Account, slip10::Slip10KeyGenerator};
use mc_crypto_ring_signature_signer::LocalRingSigner;
use mc_transaction_core::AccountKey;
use mc_transaction_signer::{read_input, write_output, Commands};

#[derive(Clone, PartialEq, Debug, Parser)]
struct Args {
    /// Account secrets file
    #[clap(long, short, default_value = "mc_secrets.json")]
    secret_file: String,

    #[command(subcommand)]
    action: Actions,
}

#[derive(Clone, PartialEq, Debug, Parser)]
enum Actions {
    /// Create a new offline account, writing secrets to the output file
    Create {
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
    mnemonic: String,
}

fn main() -> anyhow::Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Run commands
    match &args.action {
        Actions::Create { output } | Actions::Import { output, .. } => {
            // Generate or parse mnemonic
            let mnemonic = match &args.action {
                Actions::Import { mnemonic, .. } => {
                    Mnemonic::from_phrase(&mnemonic, Language::English).unwrap()
                }
                _ => Mnemonic::new(MnemonicType::Words24, Language::English),
            };

            // Generate secrets object
            let s = AccountSecrets {
                mnemonic: mnemonic.to_string(),
            };

            // Check we're not overwriting an existing secret file
            if Path::new(output).exists() {
                return Err(anyhow::anyhow!(
                    "creation would overwrite existing secrets file '{}'",
                    output
                ));
            }

            // Otherwise write out new secrets
            write_output(output, &s)?;

            info!("Account secrets written to '{}'", output);
        }
        Actions::Signer(c) => {
            // Load account secrets
            let secrets: AccountSecrets = read_input(&args.secret_file)?;
            let mnemonic = Mnemonic::from_phrase(&secrets.mnemonic, Language::English)?;

            // Perform SLIP-0010 derivation
            let account_index = c.account_index();
            let slip10key = mnemonic.derive_slip10_key(account_index);

            // Generate account from secrets
            let a = Account::from(&slip10key);

            debug!("Using account: {:?}", a);

            // Handle standard commands
            match c {
                Commands::GetAccount { output, .. } => {
                    Commands::get_account(&a, account_index, output)?
                }
                Commands::SyncTxos { input, output, .. } => Commands::sync_txos(&a, input, output)?,
                Commands::SignTx { input, output, .. } => {
                    // Setup local ring signer
                    let ring_signer = LocalRingSigner::from(&AccountKey::new(
                        a.spend_private_key().as_ref(),
                        a.view_private_key().as_ref(),
                    ));

                    // Perform transaction signing
                    Commands::sign_tx(&ring_signer, input, output)?;
                }
                _ => (),
            }
        }
    }

    Ok(())
}
