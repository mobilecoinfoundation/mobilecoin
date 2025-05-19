// Copyright (c) 2018-2022 The MobileCoin Foundation
#![deny(missing_docs)]

//! A utility for decoding b58 strings

use clap::Parser;
use mc_account_keys::{PublicAddress, ShortAddressHash};
use mc_api::{
    external::PublicAddress as PublicAddressProto,
    printable::{printable_wrapper, PrintableWrapper},
};

#[derive(Parser)]
struct Config {
    pub b58_string: String,
}

fn main() {
    let config = Config::parse();

    match PrintableWrapper::b58_decode(config.b58_string) {
        Ok(decoded_wrapper) => match decoded_wrapper.wrapper.as_ref() {
            Some(printable_wrapper::Wrapper::PublicAddress(address)) => {
                println!("B58 decoded successfully to a PrintableWrapper with a PublicAddress");
                print_public_address(address);
            }
            Some(printable_wrapper::Wrapper::PaymentRequest(payment_request)) => {
                println!("B58 decoded successfully to a PrintableWrapper with a PaymentRequest");
                let address = payment_request
                    .public_address
                    .as_ref()
                    .expect("Missing public address");
                print_public_address(address);
                println!("Value: {}", payment_request.value);
                println!("Memo: {}", payment_request.memo);
            }
            #[allow(deprecated)]
            Some(printable_wrapper::Wrapper::TransferPayload(payload)) => {
                println!("B58 decoded successfully to a PrintableWrapper with a TransferPayload");
                println!("Root entropy: {}", hex::encode(&payload.root_entropy));
                println!(
                    "TxOut public key: {}",
                    hex::encode(
                        &payload
                            .tx_out_public_key
                            .as_ref()
                            .expect("Missing tx_out_public_key")
                            .data
                    )
                );
                println!("Memo: {}", payload.memo);
                println!("BIP39 entropy: {}", hex::encode(&payload.bip39_entropy));
            }
            _ => {
                println!("Failed decoding b58, empty PrintableWrapper");
                std::process::exit(1);
            }
        },

        Err(err) => {
            println!("Failed decoding b58 into a known object: {err}");
            std::process::exit(1);
        }
    }
}

fn print_public_address(pub_addr: &PublicAddressProto) {
    println!(
        "View public key: {}",
        hex::encode(
            &pub_addr
                .view_public_key
                .as_ref()
                .expect("Missing view public key")
                .data
        )
    );
    println!(
        "Spend public key: {}",
        hex::encode(
            &pub_addr
                .spend_public_key
                .as_ref()
                .expect("Missing spend public key")
                .data
        )
    );
    println!("Fog report URL: {}", pub_addr.fog_report_url);
    println!("Fog report id: {}", pub_addr.fog_report_id);
    println!(
        "Fog authority sig: {}",
        hex::encode(&pub_addr.fog_authority_sig)
    );

    let parse_result = PublicAddress::try_from(pub_addr);
    match parse_result {
        Ok(parsed_addr) => {
            println!("Validated: {:?}", &parsed_addr);

            let address_hash = ShortAddressHash::from(&parsed_addr);
            println!("Address hash: {}", &address_hash);
        }
        Err(err) => {
            println!("Failed to validate PublicAddress struct: {err}");
        }
    }
}
