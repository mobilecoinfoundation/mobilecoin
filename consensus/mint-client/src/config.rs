// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Command line configuration for the consensus mint client.

use clap::{Parser, Subcommand};
use hex::FromHex;
use mc_account_keys::PublicAddress;
use mc_api::printable::PrintableWrapper;
use mc_crypto_keys::{DistinguishedEncoding, Ed25519Private, Ed25519Public};
use mc_crypto_multisig::SignerSet;
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

        /// Mint configs. Each configuration must be of the format: <mint
        /// limit>:<signing threshold>:<signer 1 public keyfile>[:<signer 2
        /// public keyfile....>]. For example:
        /// 10000:2:signer1.pem:signer2.pem:signer3.pem defines a minting
        /// configuration capable of minting up to 1000 tokens: and requiring 2
        /// out of 3 signers.
        #[clap(long = "config", parse(try_from_str = parse_mint_config), env = "MC_MINTING_CONFIGS")]
        // Tuple of (mint limit, SignerSet)
        configs: Vec<(u64, SignerSet<Ed25519Public>)>,
    },

    /// Generate and submit a MintTx transaction.
    #[clap(arg_required_else_help = true)]
    GenerateAndSubmitMintTx {
        /// URI of consensus node to connect to.
        #[clap(long, env = "MC_CONSENSUS_URI")]
        node: ConsensusClientUri,

        /// The key(s) to sign the transaction with.
        #[clap(long = "signing-key", required(true), parse(try_from_str = load_key_from_pem), env = "MC_MINTING_SIGNING_KEY")]
        signing_keys: Vec<Ed25519Private>,

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
        .map_err(|err| format!("failed parsing b58 address '{}': {}", b58, err.to_string()))?;

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

/// Parses a minting limit and signer set from a string in the format:
/// mint limit:threshold:keyfile1.pem[:keyfile2.pem...]
fn parse_mint_config(src: &str) -> Result<(u64, SignerSet<Ed25519Public>), String> {
    let parts = src.split(':').collect::<Vec<_>>();

    // At the minimum we should have 3 parts: mint limit, signing threshold, one
    // public key file
    if parts.len() < 3 {
        return Err(format!(
            "mint config '{}' is not in the correct format",
            src
        ));
    }

    // Parse the mint limit and signing theshold
    let mint_limit = parts[0]
        .parse::<u64>()
        .map_err(|err| format!("failed parsing mint limit '{}': {}", parts[0], err))?;
    let threshold = parts[1]
        .parse::<u32>()
        .map_err(|err| format!("failed parsing signing threshold '{}': {}", parts[1], err))?;

    // Load public keys
    let public_keys = parts[2..]
        .iter()
        .map(|filename| {
            let bytes = fs::read(filename)
                .map_err(|err| format!("Failed reading file '{}': {}", filename, err))?;

            let parsed_pem = pem::parse(&bytes)
                .map_err(|err| format!("Failed parsing PEM file '{}': {}", filename, err))?;

            Ed25519Public::try_from_der(&parsed_pem.contents[..])
                .map_err(|err| format!("Failed parsing DER from PEM file '{}': {}", filename, err))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Sanity check signing threshold against keys
    if threshold > public_keys.len() as u32 {
        return Err(format!(
            "signing threshold '{}' is greater than the number of public keys '{}'",
            threshold,
            public_keys.len()
        ));
    }

    // Success.
    Ok((mint_limit, SignerSet::new(public_keys, threshold)))
}
