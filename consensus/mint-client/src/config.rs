// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Command line configuration for the consensus mint client.

use clap::{Parser, Subcommand};
use hex::FromHex;
use mc_account_keys::PublicAddress;
use mc_api::printable::PrintableWrapper;
use mc_crypto_keys::{DistinguishedEncoding, Ed25519Private};
use mc_transaction_core::mint::constants::NONCE_LENGTH;
use mc_util_uri::ConsensusClientUri;
use std::{convert::TryFrom, fs};

#[derive(Subcommand)]
pub enum Commands {
    /// Generate and submit a MintConfigTx transaction.
    #[clap(arg_required_else_help = true)]
    GenerateAndSubmitMintConfigTx {
        /// URI of consensus node to connect to.
        #[clap(long, env = "MC_CONSENSUS_URI")]
        node: ConsensusClientUri,

        /// The key to sign the transaction with.
        #[clap(long, parse(try_from_str = load_key_from_pem), env = "MC_MINTING_SIGNING_KEY")]
        signing_key: Ed25519Private,

        /// The token id we are minting.
        #[clap(long, env = "MC_MINTING_TOKEN_ID")]
        token_id: u32,

        /// Tombstone block.
        #[clap(long, env = "MC_MINTING_TOMBSTONE")]
        tombstone: Option<u64>,

        /// Nonce.
        #[clap(long, parse(try_from_str = FromHex::from_hex), env = "MC_MINTING_NONCE")]
        nonce: Option<[u8; NONCE_LENGTH]>,
    },

    /// Generate and submit a MintTx transaction.
    #[clap(arg_required_else_help = true)]
    GenerateAndSubmitMintTx {
        /// URI of consensus node to connect to.
        #[clap(long, env = "MC_CONSENSUS_URI")]
        node: ConsensusClientUri,

        /// The key to sign the transaction with.
        #[clap(long, parse(try_from_str = load_key_from_pem), env = "MC_MINTING_SIGNING_KEY")]
        signing_key: Ed25519Private,

        /// The b58 address we are minting to.
        #[clap(long, parse(try_from_str = parse_public_address), env = "MC_MINTING_RECIPIENT")]
        recipient: PublicAddress,

        /// The token id we are minting.
        #[clap(long, env = "MC_MINTING_TOKEN_ID")]
        token_id: u32,

        /// The amount we are minting.
        #[clap(long, env = "MC_MINTING_AMOUNT")]
        amount: u64,

        /// Tombstone block.
        #[clap(long, env = "MC_MINTING_TOMBSTONE")]
        tombstone: Option<u64>,

        /// Nonce.
        #[clap(long, parse(try_from_str = FromHex::from_hex), env = "MC_MINTING_NONCE")]
        nonce: Option<[u8; NONCE_LENGTH]>,
    },
}

#[derive(Parser)]
#[clap(
    name = "mc-consensus-mint-client",
    about = "MobileCoin Consensus Mint Client"
)]
pub struct Config {
    #[clap(subcommand)]
    pub command: Commands,
}

pub fn load_key_from_pem(filename: &str) -> Result<Ed25519Private, String> {
    let bytes =
        fs::read(filename).map_err(|err| format!("Failed reading file '{}': {}", filename, err))?;

    let parsed_pem = pem::parse(&bytes)
        .map_err(|err| format!("Failed parsing PEM file '{}': {}", filename, err))?;

    Ed25519Private::try_from_der(&parsed_pem.contents[..])
        .map_err(|err| format!("Failed parsing DER from PEM file '{}': {}", filename, err))
}

fn parse_public_address(b58: &str) -> Result<PublicAddress, String> {
    let printable_wrapper = PrintableWrapper::b58_decode(b58.into())
        .map_err(|err| format!("failed parsing b58 address '{}': {}", b58, err))?;

    if printable_wrapper.has_public_address() {
        let public_address = PublicAddress::try_from(printable_wrapper.get_public_address())
            .map_err(|err| format!("failed converting b58 public address '{}': {}", b58, err))?;

        if public_address.fog_report_url().is_some() {
            return Err(format!(
                "b58 address '{}' is a fog address, which is not supported",
                b58
            ));
        }

        Ok(public_address)
    } else {
        Err(format!("b58 address '{}' is not a public address", b58))
    }
}
