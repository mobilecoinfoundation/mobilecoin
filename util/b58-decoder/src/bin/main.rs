// Copyright (c) 2018-2021 The MobileCoin Foundation

//! A utility for decoding b58 strings

use mc_api::{external::PublicAddress, printable::PrintableWrapper};
use structopt::StructOpt;

#[derive(StructOpt)]
struct Config {
    pub b58_string: String,
}

fn main() {
    let config = Config::from_args();

    match PrintableWrapper::b58_decode(config.b58_string) {
        Ok(printable_wrapper) => {
            if printable_wrapper.has_public_address() {
                println!("B58 decoded successfully to a PrintableWrapper with a PublicAddress");
                print_public_address(printable_wrapper.get_public_address());
            } else if printable_wrapper.has_payment_request() {
                println!("B58 decoded successfully to a PrintableWrapper with a PaymentRequest");
                print_public_address(printable_wrapper.get_payment_request().get_public_address());
                println!(
                    "Value: {}",
                    printable_wrapper.get_payment_request().get_value()
                );
                println!(
                    "Memo: {}",
                    printable_wrapper.get_payment_request().get_memo()
                );
            } else if printable_wrapper.has_transfer_payload() {
                println!("B58 decoded successfully to a PrintableWrapper with a TransferPayload");
                println!(
                    "Root entropy: {}",
                    hex::encode(printable_wrapper.get_transfer_payload().get_root_entropy())
                );
                println!(
                    "TxOut public key: {}",
                    hex::encode(
                        printable_wrapper
                            .get_transfer_payload()
                            .get_tx_out_public_key()
                            .get_data()
                    )
                );
                println!(
                    "Memo: {}",
                    printable_wrapper.get_transfer_payload().get_memo()
                );
                println!(
                    "BIP39 entropy: {}",
                    hex::encode(printable_wrapper.get_transfer_payload().get_bip39_entropy())
                );
            }
        }

        Err(err) => {
            println!("Failed decoding b58 into a known object: {}", err);
            std::process::exit(1);
        }
    }
}

fn print_public_address(pub_addr: &PublicAddress) {
    println!(
        "View public key: {}",
        hex::encode(pub_addr.get_view_public_key().get_data())
    );
    println!(
        "Spend public key: {}",
        hex::encode(pub_addr.get_spend_public_key().get_data())
    );
    println!("Fog report URL: {}", pub_addr.get_fog_report_url());
    println!("Fog report id: {}", pub_addr.get_fog_report_id());
    println!(
        "Fog authority sig: {}",
        hex::encode(pub_addr.get_fog_authority_sig())
    );
}
