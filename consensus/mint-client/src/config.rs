// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Command line configuration for the consensus mint client.

use clap::{Args, Parser, Subcommand};
use hex::FromHex;
use mc_account_keys::PublicAddress;
use mc_api::printable::PrintableWrapper;
use mc_crypto_keys::{DistinguishedEncoding, Ed25519Pair, Ed25519Private, Ed25519Public, Signer};
use mc_crypto_multisig::{MultiSig, SignerSet};
use mc_transaction_core::mint::{
    constants::NONCE_LENGTH, MintConfig, MintConfigTx, MintConfigTxPrefix, MintTx, MintTxPrefix,
};
use mc_util_uri::ConsensusClientUri;
use rand::{thread_rng, RngCore};
use std::{convert::TryFrom, fs, path::PathBuf};

#[derive(Args)]
pub struct MintConfigTxParams {
    /// The key(s) to sign the transaction with.
    #[clap(long = "signing-key", required =true, use_value_delimiter = true, parse(try_from_str = load_key_from_pem), env = "MC_MINTING_SIGNING_KEYS")]
    signing_keys: Vec<Ed25519Private>,

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
}

impl MintConfigTxParams {
    pub fn try_into_mint_config_tx(
        self,
        fallback_tombstone_block: impl Fn() -> u64,
    ) -> Result<MintConfigTx, String> {
        let tombstone_block = self.tombstone.unwrap_or_else(fallback_tombstone_block);
        let nonce = get_or_generate_nonce(self.nonce);
        let token_id = self.token_id;
        let prefix = MintConfigTxPrefix {
            token_id,
            configs: self
                .configs
                .into_iter()
                .map(|(mint_limit, signer_set)| MintConfig {
                    token_id,
                    mint_limit,
                    signer_set,
                })
                .collect(),
            nonce,
            tombstone_block,
        };

        let message = prefix.hash();
        let signature = MultiSig::new(
            self.signing_keys
                .into_iter()
                .map(|signer| {
                    Ed25519Pair::from(signer)
                        .try_sign(message.as_ref())
                        .map_err(|e| format!("Failed to sign MintConfigTxPrefix: {}", e))?
                })
                .collect::<Result<Vec<_>, _>()?,
        );
        Ok(MintConfigTx { prefix, signature })
    }
}

#[derive(Args)]
pub struct MintTxParams {
    /// The key(s) to sign the transaction with.
    #[clap(long = "signing-key", required =true, use_value_delimiter = true, parse(try_from_str = load_key_from_pem), env = "MC_MINTING_SIGNING_KEYS")]
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
}

impl MintTxParams {
    pub fn try_into_mint_tx(
        self,
        fallback_tombstone_block: impl Fn() -> u64,
    ) -> Result<MintTx, String> {
        let tombstone_block = self.tombstone.unwrap_or_else(fallback_tombstone_block);
        let nonce = get_or_generate_nonce(self.nonce);
        let prefix = MintTxPrefix {
            token_id: self.token_id,
            amount: self.amount,
            view_public_key: *self.recipient.view_public_key(),
            spend_public_key: *self.recipient.spend_public_key(),
            nonce,
            tombstone_block,
        };

        let message = prefix.hash();
        let signature = MultiSig::new(
            self.signing_keys
                .into_iter()
                .map(|signer| {
                    Ed25519Pair::from(signer)
                        .try_sign(message.as_ref())
                        .unwrap()
                })
                .collect(),
        );
        Ok(MintTx { prefix, signature })
    }
}

#[derive(Subcommand)]
pub enum Commands {
    /// Generate and submit a MintConfigTx transaction.
    #[clap(arg_required_else_help = true)]
    GenerateAndSubmitMintConfigTx {
        /// URI of consensus node to connect to.
        #[clap(long, env = "MC_CONSENSUS_URI")]
        node: ConsensusClientUri,

        #[clap(flatten)]
        params: MintConfigTxParams,
    },

    // Generate a MintConfigTx and write it to a JSON file.
    GenerateMintConfigTx {
        /// Filename to write the mint configuration to.
        #[clap(long, env = "MC_MINTING_OUT_FILE")]
        out: PathBuf,

        #[clap(flatten)]
        params: MintConfigTxParams,
    },

    // Submit json-encoded MintConfigTx(s). If multiple transactions are provided, signatures will
    // be merged.
    SubmitMintConfigTx {
        /// URI of consensus node to connect to.
        #[clap(long, env = "MC_CONSENSUS_URI")]
        node: ConsensusClientUri,

        /// Paths for the JSON-formatted mint configuration tx files, each
        /// containing a serde-serialized MintConfigTx object.
        #[clap(
            long = "tx",
            required = true,
            use_value_delimiter = true,
            env = "MC_MINTING_CONFIG_TXS"
        )]
        tx_filenames: Vec<PathBuf>,
    },

    /// Generate and submit a MintTx transaction.
    #[clap(arg_required_else_help = true)]
    GenerateAndSubmitMintTx {
        /// URI of consensus node to connect to.
        #[clap(long, env = "MC_CONSENSUS_URI")]
        node: ConsensusClientUri,

        #[clap(flatten)]
        params: MintTxParams,
    },

    // Generate a MintTx and write it to a JSON file.
    GenerateMintTx {
        /// Filename to write the mint configuration to.
        #[clap(long, env = "MC_MINTING_OUT_FILE")]
        out: PathBuf,

        #[clap(flatten)]
        params: MintTxParams,
    },

    // Submit json-encoded MintTx(s). If multiple transactions are provided, signatures will
    // be merged.
    SubmitMintTx {
        /// URI of consensus node to connect to.
        #[clap(long, env = "MC_CONSENSUS_URI")]
        node: ConsensusClientUri,

        /// Paths for the JSON-formatted mint tx files, each containing a
        /// serde-serialized MintTx object.
        #[clap(
            long = "tx",
            required = true,
            use_value_delimiter = true,
            env = "MC_MINTING_TXS"
        )]
        tx_filenames: Vec<PathBuf>,
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

/// Parses a minting limit and signer set from a string in the format:
/// mint limit:threshold:keyfile1.pem[:keyfile2.pem...]
fn parse_mint_config(src: &str) -> Result<(u64, SignerSet<Ed25519Public>), String> {
    let parts = src.split(':').collect::<Vec<_>>();

    // At the minimum we should have 3 parts: mint limit, signing threshold, one
    // public key file
    if parts.len() < 3 {
        return Err(format!(
            "mint config '{}' is not in the correct format. Expected format is '<mint_limit>:<signing_threshold>:keyfile1.pem[:keyfile2.pem:...]'",
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

fn get_or_generate_nonce(nonce: Option<[u8; NONCE_LENGTH]>) -> Vec<u8> {
    nonce.map(|n| n.to_vec()).unwrap_or_else(|| {
        let mut rng = thread_rng();
        let mut nonce: Vec<u8> = vec![0u8; NONCE_LENGTH];
        rng.fill_bytes(&mut nonce);
        nonce
    })
}
