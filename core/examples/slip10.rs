// Copyright (c) 2018-2022 The MobileCoin Foundation

//! SLIP-0010 example applet

use bip39::Mnemonic;
use clap::Parser;

use mc_core::{
    account::{Account, RingCtAddress},
    slip10::Slip10KeyGenerator,
    subaddress::Subaddress,
};

/// MobileCoin SLIP-0010/BIP39 account derivation example
#[derive(Clone, Debug, Parser)]
struct Args {
    /// Mnemonic for wallet address derivation, if unspecified a random phrase
    /// will be generated
    #[clap(long)]
    pub mnemonic: Option<String>,

    /// Wallet index for SLIP-0010 derivation
    #[clap(short, long, default_value = "0")]
    pub account_index: u32,

    /// MobileCoin account subaddress index (default subaddress is 0)
    #[clap(short, long, default_value = "0")]
    pub subaddress_index: u64,
}

fn main() -> anyhow::Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Parse or derive mnemonic
    let mn = match &args.mnemonic {
        Some(v) => Mnemonic::from_phrase(v, bip39::Language::English)?,
        None => {
            println!("WARNING: generating random mnemonic, this will not be stored");
            Mnemonic::new(bip39::MnemonicType::Words24, bip39::Language::English)
        }
    };
    println!("Using mnemonic: {}", mn.phrase());

    // Generate account keys
    let slip10key = mn.derive_slip10_key(args.account_index);
    let account = Account::from(&slip10key);

    // Fetch subaddress
    let subaddr = account.subaddress(args.subaddress_index);

    println!(
        "Subaddr {}\n\tVIEW PUBLIC: {}\n\tSPEND PUBLIC: {}",
        args.subaddress_index,
        subaddr.view_public_key(),
        subaddr.spend_public_key()
    );

    Ok(())
}
