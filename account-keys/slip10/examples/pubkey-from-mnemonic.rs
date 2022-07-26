// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A toy application to read a mnemonic phrase from standard input and output
//! the default public subaddress as hex.

use bip39::{Language, Mnemonic};
use hex_fmt::HexFmt;
use mc_account_keys::AccountKey;
use mc_account_keys_slip10::Slip10Key;
use std::io;

fn main() {
    let mut phrase = String::default();
    io::stdin()
        .read_line(&mut phrase)
        .expect("Could not read phrase from stdin");

    let mnemonic = Mnemonic::from_phrase(&phrase, Language::English)
        .expect("Given phrase was not a BIP39 mnemonic");

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
