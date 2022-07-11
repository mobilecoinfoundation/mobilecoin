// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A toy application to generate a new random key and print the mnemonic phrase
//! and default public subaddress as hex.

use bip39::{Language, Mnemonic, MnemonicType};
use hex_fmt::HexFmt;
use mc_account_keys::AccountKey;
use mc_account_keys_slip10::Slip10Key;

fn main() {
    let mnemonic = Mnemonic::new(MnemonicType::Words24, Language::English);
    println!("PHRASE: {}", mnemonic.phrase());
    let slip10key = Slip10Key::from(mnemonic);
    let account_key = AccountKey::from(slip10key);
    let default_subaddress = account_key.default_subaddress();
    let view_public_bytes = default_subaddress.view_public_key().to_bytes();
    let spend_public_bytes = default_subaddress.spend_public_key().to_bytes();

    println!(
        "VIEW:   {}\nSPEND:  {}",
        HexFmt(view_public_bytes),
        HexFmt(spend_public_bytes)
    );
}
