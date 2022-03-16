// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Command line configuration for the consensus mint client.

use clap::{Parser, Subcommand};
use mc_crypto_keys::{DistinguishedEncoding, Ed25519Private};
use mc_util_uri::ConsensusClientUri;
use std::fs;

#[derive(Subcommand)]
pub enum Commands {
    /// Generate and submit a MintConfigTx transaction.
    #[clap(arg_required_else_help = true)]
    GenerateAndSubmitMintConfigTx {
        /// URI of consensus node to connect to.
        #[clap(long, env = "MC_CONSENSUS_URI")]
        node: ConsensusClientUri,

        /// The key to sign the transaction with.
        #[clap(long, parse(try_from_str = load_key_from_pem), env = "MC_MINTING_PRIVATE_KEY")]
        private_key: Ed25519Private,
    },

    /// Generate and submit a MintTx transaction.
    #[clap(arg_required_else_help = true)]
    GenerateAndSubmitMintTx {
        /// URI of consensus node to connect to.
        #[clap(long, env = "MC_CONSENSUS_URI")]
        node: ConsensusClientUri,

        /// The key to sign the transaction with.
        #[clap(long, parse(try_from_str = load_key_from_pem), env = "MC_MINTING_PRIVATE_KEY")]
        private_key: Ed25519Private,
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
