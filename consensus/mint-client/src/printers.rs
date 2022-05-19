// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Utility functions for printing objects in a human-friendly way.

use mc_account_keys::PublicAddress;
use mc_api::printable::PrintableWrapper;
use mc_crypto_keys::{DistinguishedEncoding, Ed25519Public, Ed25519Signature};
use mc_crypto_multisig::{MultiSig, SignerSet};
use mc_transaction_core::mint::{
    MintConfig, MintConfigTx, MintConfigTxPrefix, MintTx, MintTxPrefix,
};
use pem::Pem;

const INDENT_STR: &str = "    ";
const PEM_TAG_SIGNATURE: &str = "SIGNATURE";
const PEM_TAG_PUBLIC_KEY: &str = "PUBLIC KEY";

pub fn print_mint_config_tx(tx: &MintConfigTx, indent: usize) {
    let indent_str = INDENT_STR.repeat(indent);
    println!("{}MintConfigTx:", indent_str);
    print_mint_config_tx_prefix(&tx.prefix, indent + 1);
    print_multi_sig(&tx.signature, indent + 1);
}

pub fn print_mint_config_tx_prefix(prefix: &MintConfigTxPrefix, indent: usize) {
    let mut indent_str = INDENT_STR.repeat(indent);
    println!("{}MintConfigTxPrefix:", indent_str);

    indent_str.push_str(INDENT_STR);
    println!(
        "{}Configs ({} config(s)):",
        indent_str,
        prefix.configs.len()
    );
    for config in &prefix.configs {
        print_mint_config(config, indent + 2);
    }
    println!("{}Nonce: {}", indent_str, hex::encode(&prefix.nonce));
    println!("{}Tombstone block: {}", indent_str, prefix.tombstone_block);
    println!(
        "{}Total mint limit: {}",
        indent_str, prefix.total_mint_limit
    );
}

pub fn print_mint_config(mint_config: &MintConfig, indent: usize) {
    let mut indent_str = INDENT_STR.repeat(indent);
    println!("{}MintConfig:", indent_str);

    indent_str.push_str(INDENT_STR);
    println!("{}Token id: {}", indent_str, mint_config.token_id);
    println!("{}Mint limit: {}", indent_str, mint_config.mint_limit);
    print_signer_set(&mint_config.signer_set, indent + 1);
}

pub fn print_mint_tx(tx: &MintTx, indent: usize) {
    let indent_str = INDENT_STR.repeat(indent);
    println!("{}MintTx:", indent_str);
    print_mint_tx_prefix(&tx.prefix, indent + 1);
    print_multi_sig(&tx.signature, indent + 1);
}

pub fn print_mint_tx_prefix(prefix: &MintTxPrefix, indent: usize) {
    let recipient = PublicAddress::new(&prefix.spend_public_key, &prefix.view_public_key);
    let mut wrapper = PrintableWrapper::new();
    wrapper.set_public_address((&recipient).into());
    let b58_recipient = wrapper.b58_encode().expect("failed encoding b58 address");

    let mut indent_str = INDENT_STR.repeat(indent);
    println!("{}MintTxPrefix:", indent_str);
    indent_str.push_str(INDENT_STR);
    println!("{}Token id: {}", indent_str, prefix.token_id);
    println!("{}Mint amount: {}", indent_str, prefix.amount);
    println!("{}View public key: {}", indent_str, prefix.view_public_key,);
    println!(
        "{}Spend public key: {}",
        indent_str, prefix.spend_public_key
    );
    println!("{}Recipient B58 address: {}", indent_str, b58_recipient);
    println!("{}Nonce: {}", indent_str, hex::encode(&prefix.nonce));
    println!("{}Tombstone block: {}", indent_str, prefix.tombstone_block);
}

pub fn print_signer_set(signer_set: &SignerSet<Ed25519Public>, indent: usize) {
    let mut indent_str = INDENT_STR.repeat(indent);
    println!(
        "{}Signer set ({} signer(s)):",
        indent_str,
        signer_set.signers().len()
    );
    indent_str.push_str(INDENT_STR);
    for signer in signer_set.signers() {
        print_pem(signer, PEM_TAG_PUBLIC_KEY, indent + 2);
    }
    println!("{}Threshold: {}", indent_str, signer_set.threshold());
}

pub fn print_multi_sig(multi_sig: &MultiSig<Ed25519Signature>, indent: usize) {
    let indent_str = INDENT_STR.repeat(indent);
    println!(
        "{}Multisig ({} signature(s)):",
        indent_str,
        multi_sig.signatures().len()
    );
    for sig in multi_sig.signatures() {
        print_pem(sig, PEM_TAG_SIGNATURE, indent + 2);
    }
}

pub fn print_pem(obj: &impl DistinguishedEncoding, tag: &str, indent: usize) {
    let indent_str = INDENT_STR.repeat(indent);
    let pem_str = pem::encode(&Pem {
        tag: tag.into(),
        contents: obj.to_der(),
    });
    for line in pem_str.lines() {
        println!("{}{}", indent_str, line);
    }
}
