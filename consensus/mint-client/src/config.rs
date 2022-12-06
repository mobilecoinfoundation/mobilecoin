// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Command line configuration for the consensus mint client.

use crate::FogContext;
use clap::{Args, Parser, Subcommand};
use mc_account_keys::PublicAddress;
use mc_api::printable::PrintableWrapper;
use mc_consensus_mint_client_types::{MintConfigTxFile, TxFile};
use mc_consensus_service_config::TokensConfig;
use mc_crypto_keys::{
    DistinguishedEncoding, Ed25519Pair, Ed25519Private, Ed25519Public, Ed25519Signature, Signer,
};
use mc_crypto_multisig::MultiSig;
use mc_sgx_css::Signature;
use mc_transaction_core::{
    mint::{constants::NONCE_LENGTH, MintConfigTx, MintConfigTxPrefix, MintTx, MintTxPrefix},
    TokenId,
};
use mc_util_parse::load_css_file;
use mc_util_uri::ConsensusClientUri;
use rand::{thread_rng, RngCore};
use std::{
    fs,
    path::{Path, PathBuf},
};

/// A private key that can be used with clap.
pub struct MintPrivateKey(Ed25519Private);

impl Clone for MintPrivateKey {
    fn clone(&self) -> Self {
        Self(
            Ed25519Private::try_from(self.0.as_ref())
                .expect("Ed25519Private to Ed25519Private should always work"),
        )
    }
}

impl From<MintPrivateKey> for Ed25519Private {
    fn from(src: MintPrivateKey) -> Self {
        src.0
    }
}

#[derive(Args)]
pub struct MintConfigTxPrefixParams {
    /// The JSON file containing the mint config tx.
    #[clap(long, value_parser = load_mint_config_tx_file_from_path, env = "MC_MINTING_MINT_CONFIG_TX_FILE")]
    pub mint_config_tx_file: MintConfigTxFile,

    /// Optional tombstone block, overriding whatever is in the JSON file.
    #[clap(long, env = "MC_MINTING_TOMBSTONE")]
    pub tombstone: Option<u64>,

    /// Optional nonce, overriding whatever is in the JSON file.
    #[clap(long, value_parser = mc_util_parse::parse_hex::<[u8; NONCE_LENGTH]>, env = "MC_MINTING_NONCE")]
    pub nonce: Option<[u8; NONCE_LENGTH]>,
}

impl MintConfigTxPrefixParams {
    pub fn try_into_mint_config_tx_prefix(
        self,
        fallback_tombstone_block: impl Fn() -> u64,
    ) -> Result<MintConfigTxPrefix, String> {
        let mut mint_config_tx_prefix = MintConfigTxPrefix::try_from(&self.mint_config_tx_file)
            .map_err(|err| format!("Failed to parse mint config tx file: {}", err))?;

        // Override tombstone block if provided.
        if let Some(tombstone) = self.tombstone {
            mint_config_tx_prefix.tombstone_block = tombstone;
        }

        // Use fallback tombstone if we are still missing one.
        if mint_config_tx_prefix.tombstone_block == 0 {
            mint_config_tx_prefix.tombstone_block = fallback_tombstone_block();
        }

        // Override nonce if provided or if we don't already have one.
        if self.nonce.is_some() || self.mint_config_tx_file.nonce.is_empty() {
            mint_config_tx_prefix.nonce = get_or_generate_nonce(self.nonce);
        }

        // Some sanity checks.
        if mint_config_tx_prefix.tombstone_block == 0 {
            return Err("Tombstone block must be non-zero".to_string());
        }

        if mint_config_tx_prefix.nonce.len() != NONCE_LENGTH {
            return Err(format!(
                "Nonce must be {} bytes, got {}",
                NONCE_LENGTH,
                mint_config_tx_prefix.nonce.len()
            ));
        }

        Ok(mint_config_tx_prefix)
    }
}

#[derive(Args)]
pub struct MintConfigTxParams {
    /// The key(s) to sign the transaction with.
    #[clap(
        long = "signing-key",
        use_value_delimiter = true,
        value_parser = load_mint_private_key_from_pem,
        env = "MC_MINTING_SIGNING_KEYS"
    )]
    signing_keys: Vec<MintPrivateKey>,

    /// Pre-generated signature(s) to use, either in hex format or a PEM file.
    #[clap(
        long = "signature",
        use_value_delimiter = true,
        value_parser = load_or_parse_ed25519_signature,
        env = "MC_MINTING_SIGNATURES"
    )]
    signatures: Vec<Ed25519Signature>,

    #[clap(flatten)]
    prefix_params: MintConfigTxPrefixParams,
}

impl MintConfigTxParams {
    pub fn try_into_mint_config_tx(
        self,
        fallback_tombstone_block: impl Fn() -> u64,
    ) -> Result<MintConfigTx, String> {
        let prefix = self
            .prefix_params
            .try_into_mint_config_tx_prefix(fallback_tombstone_block)?;
        let message = prefix.hash();

        let mut signatures = self
            .signing_keys
            .into_iter()
            .map(|signer| {
                Ed25519Pair::from(Ed25519Private::from(signer))
                    .try_sign(message.as_ref())
                    .map_err(|e| format!("Failed to sign MintConfigTxPrefix: {}", e))
            })
            .collect::<Result<Vec<_>, _>>()?;
        signatures.extend(self.signatures);

        signatures.sort();
        signatures.dedup();

        let signature = MultiSig::new(signatures);
        Ok(MintConfigTx { prefix, signature })
    }
}

#[derive(Args)]
pub struct MintTxPrefixParams {
    /// The b58 address we are minting to.
    #[clap(long, value_parser = parse_public_address, env = "MC_MINTING_RECIPIENT")]
    pub recipient: PublicAddress,

    /// The token id we are minting.
    #[clap(long, env = "MC_MINTING_TOKEN_ID")]
    pub token_id: TokenId,

    /// The amount we are minting.
    #[clap(long, env = "MC_MINTING_AMOUNT")]
    pub amount: u64,

    /// Tombstone block.
    #[clap(long, env = "MC_MINTING_TOMBSTONE")]
    pub tombstone: Option<u64>,

    /// Nonce.
    #[clap(long, value_parser = mc_util_parse::parse_hex::<[u8; NONCE_LENGTH]>, env = "MC_MINTING_NONCE")]
    pub nonce: Option<[u8; NONCE_LENGTH]>,
}

impl MintTxPrefixParams {
    pub fn try_into_mint_tx_prefix(
        self,
        fog_bits: Option<FogContext>,
        fallback_tombstone_block: impl Fn() -> u64,
    ) -> Result<MintTxPrefix, String> {
        let mut tombstone_block = self.tombstone.unwrap_or_else(fallback_tombstone_block);
        let e_fog_hint = self.recipient.fog_report_url().map(|fog_url| -> Result<_, String> {
            let fog_bits = fog_bits.ok_or_else(|| format!(
                "This recipient has a fog url, but a CSS to validate fog public keys was not supplied: '{}'",
                fog_url,
            ))?;
            let (e_fog_hint, pubkey_expiry) = fog_bits.get_e_fog_hint(&self.recipient)?;
            tombstone_block = tombstone_block.min(pubkey_expiry);
            Ok(e_fog_hint)
        }).transpose()?;
        let nonce = get_or_generate_nonce(self.nonce);
        Ok(MintTxPrefix {
            token_id: *self.token_id,
            amount: self.amount,
            view_public_key: *self.recipient.view_public_key(),
            spend_public_key: *self.recipient.spend_public_key(),
            nonce,
            tombstone_block,
            e_fog_hint,
        })
    }
}

#[derive(Args)]
pub struct MintTxParams {
    /// The key(s) to sign the transaction with.
    #[clap(
        long = "signing-key",
        use_value_delimiter = true,
        value_parser = load_mint_private_key_from_pem,
        env = "MC_MINTING_SIGNING_KEYS"
    )]
    signing_keys: Vec<MintPrivateKey>,

    /// Pre-generated signature(s) to use, either in hex format or a PEM file.
    #[clap(
        long = "signature",
        use_value_delimiter = true,
        value_parser = load_or_parse_ed25519_signature, env = "MC_MINTING_SIGNATURES"
    )]
    signatures: Vec<Ed25519Signature>,

    #[clap(flatten)]
    prefix_params: MintTxPrefixParams,
}

impl MintTxParams {
    pub fn try_into_mint_tx(
        self,
        fog_bits: Option<FogContext>,
        fallback_tombstone_block: impl Fn() -> u64,
    ) -> Result<MintTx, String> {
        let prefix = self
            .prefix_params
            .try_into_mint_tx_prefix(fog_bits, fallback_tombstone_block)?;
        let message = prefix.hash();

        let mut signatures = self
            .signing_keys
            .into_iter()
            .map(|signer| {
                Ed25519Pair::from(Ed25519Private::from(signer))
                    .try_sign(message.as_ref())
                    .map_err(|e| format!("Failed to sign MintTxPrefix: {}", e))
            })
            .collect::<Result<Vec<_>, _>>()?;
        signatures.extend(self.signatures);

        signatures.sort();
        signatures.dedup();

        let signature = MultiSig::new(signatures);
        Ok(MintTx { prefix, signature })
    }
}
#[derive(Subcommand)]
pub enum Commands {
    /// Generate and submit a MintConfigTx transaction.
    #[clap(arg_required_else_help = true)]
    GenerateAndSubmitMintConfigTx {
        /// The chain id of the network we expect to connect to
        #[clap(long, env = "MC_CHAIN_ID")]
        chain_id: String,

        /// URI of consensus node to connect to.
        #[clap(long, env = "MC_CONSENSUS_URI")]
        node: ConsensusClientUri,

        #[clap(flatten)]
        params: MintConfigTxParams,
    },

    /// Generate a MintConfigTx and write it to a JSON file.
    GenerateMintConfigTx {
        /// Filename to write the mint configuration to.
        #[clap(long, env = "MC_MINTING_OUT_FILE")]
        out: PathBuf,

        /// Optional URI of consensus node to query for current block index and
        /// calculate a default tombstone block from.
        #[clap(long, env = "MC_CONSENSUS_URI")]
        tombstone_from_node: Option<ConsensusClientUri>,

        #[clap(flatten)]
        params: MintConfigTxParams,
    },

    /// Produce a hash of a MintConfigTx transaction. This is useful for
    /// offline/HSM signing.
    HashMintConfigTx {
        #[clap(flatten)]
        params: MintConfigTxPrefixParams,
    },

    /// Produce a hash of a MintConfigTx or MintTx tranasaction from a JSON
    /// tx-file. This is useful for offline/HSM signing.
    HashTxFile {
        /// The file to load
        #[clap(long, value_parser = load_tx_file_from_path, env = "MC_MINTING_TX_FILE")]
        tx_file: TxFile,
    },

    /// Submit json-encoded MintConfigTx(s). If multiple transactions are
    /// provided, signatures will be merged.
    SubmitMintConfigTx {
        /// The chain id of the network we expect to connect to
        #[clap(long, env = "MC_CHAIN_ID")]
        chain_id: String,

        /// URI of consensus node to connect to.
        #[clap(long, env = "MC_CONSENSUS_URI")]
        node: ConsensusClientUri,

        /// Paths for the JSON-formatted mint configuration tx files, each
        /// containing a serde-serialized TxFile holding a MintConfigTx object.
        #[clap(
            long = "tx-file",
            required = true,
            use_value_delimiter = true,
            env = "MC_MINTING_CONFIG_TX_FILES"
        )]
        tx_filenames: Vec<PathBuf>,
    },

    /// Generate and submit a MintTx transaction.
    #[clap(arg_required_else_help = true)]
    GenerateAndSubmitMintTx {
        /// The chain id of the network we expect to connect to
        #[clap(long, env = "MC_CHAIN_ID")]
        chain_id: String,

        /// URI of consensus node to connect to.
        #[clap(long, env = "MC_CONSENSUS_URI")]
        node: ConsensusClientUri,

        /// Fog ingest enclave CSS file (needed in order to enable minting
        /// to fog recipients).
        #[clap(long, value_parser = load_css_file, env = "MC_FOG_INGEST_ENCLAVE_CSS")]
        fog_ingest_enclave_css: Option<Signature>,

        #[clap(flatten)]
        params: MintTxParams,
    },

    /// Generate a MintTx and write it to a JSON file.
    GenerateMintTx {
        /// Filename to write the mint configuration to.
        #[clap(long, env = "MC_MINTING_OUT_FILE")]
        out: PathBuf,

        /// Fog ingest enclave CSS file (needed in order to enable minting
        /// to fog recipients).
        #[clap(long, value_parser = load_css_file, env = "MC_FOG_INGEST_ENCLAVE_CSS", requires = "chain_id")]
        fog_ingest_enclave_css: Option<Signature>,

        /// The chain id of the network we expect to connect to. This is only
        /// needed if fog is used.
        #[clap(long, env = "MC_CHAIN_ID")]
        chain_id: Option<String>,

        /// Optional URI of consensus node to query for current block index and
        /// calculate a default tombstone block from.
        #[clap(long, env = "MC_CONSENSUS_URI")]
        tombstone_from_node: Option<ConsensusClientUri>,

        #[clap(flatten)]
        params: MintTxParams,
    },

    /// Produce a hash of a MintTx transaction. This is useful for offline/HSM
    /// signing.
    HashMintTx {
        #[clap(flatten)]
        params: MintTxPrefixParams,
    },

    /// Submit json-encoded MintTx(s). If multiple transactions are provided,
    /// signatures will be merged.
    SubmitMintTx {
        /// The chain id of the network we expect to connect to
        #[clap(long, env = "MC_CHAIN_ID")]
        chain_id: String,

        /// URI of consensus node to connect to.
        #[clap(long, env = "MC_CONSENSUS_URI")]
        node: ConsensusClientUri,

        /// Paths for the JSON-formatted mint tx files, each containing a
        /// serde-serialized TxFile holding a MintTx object.
        #[clap(
            long = "tx-file",
            required = true,
            use_value_delimiter = true,
            env = "MC_MINTING_TX_FILES"
        )]
        tx_filenames: Vec<PathBuf>,
    },

    /// Sign governors configuration from a tokens.json file.
    SignGovernors {
        /// The key to sign with.
        #[clap(long = "signing-key", value_parser = load_mint_private_key_from_pem, env = "MC_MINTING_SIGNING_KEY")]
        signing_key: MintPrivateKey,

        /// The tokens configuration file to sign (in JSON format).
        #[clap(long, value_parser = parse_tokens_file, env = "MC_MINTING_TOKENS_CONFIG")]
        tokens: TokensConfig,

        /// Optionally write a new tokens.json file containing the signature.
        #[clap(long, env = "MC_MINTING_OUTPUT_JSON")]
        output_json: Option<PathBuf>,
    },

    /// Load a previously-serialized file produced by this tool and print its
    /// contents in a human-friendly way.
    Dump {
        /// The file to load
        #[clap(long, value_parser = load_tx_file_from_path, env = "MC_MINTING_TX_FILE")]
        tx_file: TxFile,
    },

    /// Sign a transaction file produced by this tool, rewriting the file with
    /// the appended signature(s).
    Sign {
        /// The file to sign
        #[clap(long, env = "MC_MINTING_TX_FILE")]
        tx_file: PathBuf,

        /// The key(s) to sign the transaction with.
        #[clap(
            long = "signing-key",
            required_unless_present = "signatures",
            value_parser = load_mint_private_key_from_pem,
            env = "MC_MINTING_SIGNING_KEYS"
        )]
        signing_keys: Vec<MintPrivateKey>,

        /// Pre-generated signature(s) to use, either in hex format or a PEM
        /// file.
        #[clap(
            long = "signature",
            use_value_delimiter = true,
            value_parser = load_or_parse_ed25519_signature, env = "MC_MINTING_SIGNATURES"
        )]
        signatures: Vec<Ed25519Signature>,
    },

    /// Verify that the signature of a hash used the private key corresponding
    /// to the provided public-key
    CheckSig {
        /// The signature to verify
        ///
        /// can be created with `ledger-agent -e ed25519 --sign-blob <hash>
        /// <key_identifier>`
        #[clap(
            long = "signature",
            value_parser = load_or_parse_ed25519_signature, env = "MC_MINTING_SIGNATURE"
        )]
        signature: Ed25519Signature,

        /// The hash that was signed.
        ///
        /// An example hash may be created with `hash-tx-file --tx-file
        /// mintconfig.json`
        #[clap(
            long = "hash",
            value_parser = mc_util_parse::parse_hex::<[u8; 32]>, env = "MC_MINTING_HASH"
        )]
        hash: [u8; 32],

        /// The public key to verify with the signature.
        ///
        /// This pemfile can be created with `ledger-agent -e ed25519 --pemout
        /// <outfile>.pub <key_identifier>`
        #[clap(
            long = "public-key",
            value_parser = load_key_from_pem::<Ed25519Public>, env = "MC_MINTING_PUBLIC_KEY")]
        pubkey: Ed25519Public,
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

// a purpose-built pem loader for MintPrivateKey to avoid implementing
// DistinguishedEncoding trait. MintPrivateKey was needed to implement Clone
// trait for use with clap
pub fn load_mint_private_key_from_pem(filename: &str) -> Result<MintPrivateKey, String> {
    let bytes =
        fs::read(filename).map_err(|err| format!("Failed reading file '{}': {}", filename, err))?;

    let parsed_pem = pem::parse(&bytes)
        .map_err(|err| format!("Failed parsing PEM file '{}': {}", filename, err))?;

    let key = Ed25519Private::try_from_der(&parsed_pem.contents[..])
        .map_err(|err| format!("Failed parsing DER from PEM file '{}': {}", filename, err))?;
    Ok(MintPrivateKey(key))
}

pub fn load_key_from_pem<K: DistinguishedEncoding>(filename: &str) -> Result<K, String> {
    let bytes =
        fs::read(filename).map_err(|err| format!("Failed reading file '{}': {}", filename, err))?;

    let parsed_pem = pem::parse(&bytes)
        .map_err(|err| format!("Failed parsing PEM file '{}': {}", filename, err))?;

    let key = K::try_from_der(&parsed_pem.contents[..])
        .map_err(|err| format!("Failed parsing DER from PEM file '{}': {}", filename, err))?;
    Ok(key)
}

pub fn load_or_parse_ed25519_signature(
    filename_or_hex_signature: &str,
) -> Result<Ed25519Signature, String> {
    // Check if the signature provided is a filename.
    let bytes = if Path::new(filename_or_hex_signature).exists() {
        let bytes = fs::read(filename_or_hex_signature).map_err(|err| {
            format!(
                "Failed reading file '{}': {}",
                filename_or_hex_signature, err
            )
        })?;

        let parsed_pem = pem::parse(&bytes).map_err(|err| {
            format!(
                "Failed parsing PEM file '{}': {}",
                filename_or_hex_signature, err
            )
        })?;

        parsed_pem.contents
    } else if filename_or_hex_signature.len() == Ed25519Signature::BYTE_SIZE * 2 {
        // *2 due to hex encoding
        hex::decode(filename_or_hex_signature)
            .map_err(|err| format!("Failed decoding hex signature: {}", err))?
    } else {
        return Err("Signature must either be a PEM file or a hex-encoded string".to_string());
    };

    Ed25519Signature::try_from(&bytes[..])
        .map_err(|err| format!("Failed parsing Ed25519 signature: {}", err))
}

fn parse_public_address(b58: &str) -> Result<PublicAddress, String> {
    let printable_wrapper = PrintableWrapper::b58_decode(b58.into())
        .map_err(|err| format!("failed parsing b58 address '{}': {}", b58, err))?;

    if printable_wrapper.has_public_address() {
        let public_address = PublicAddress::try_from(printable_wrapper.get_public_address())
            .map_err(|err| format!("failed converting b58 public address '{}': {}", b58, err))?;

        Ok(public_address)
    } else {
        Err(format!("b58 address '{}' is not a public address", b58))
    }
}

/// Parse a tokens file from the command line
///
/// # Arguments:
/// * `path`- The command line filepath for the tokens file
fn parse_tokens_file(path: &str) -> Result<TokensConfig, mc_consensus_service_config::Error> {
    TokensConfig::load_from_path(path)
}

fn get_or_generate_nonce(nonce: Option<[u8; NONCE_LENGTH]>) -> Vec<u8> {
    nonce.map(|n| n.to_vec()).unwrap_or_else(|| {
        let mut rng = thread_rng();
        let mut nonce: Vec<u8> = vec![0u8; NONCE_LENGTH];
        rng.fill_bytes(&mut nonce);
        nonce
    })
}

fn load_tx_file_from_path(path: &str) -> Result<TxFile, String> {
    TxFile::from_json_file(path).map_err(|e| format!("failed loading file {:?}: {}", path, e))
}

fn load_mint_config_tx_file_from_path(path: &str) -> Result<MintConfigTxFile, String> {
    MintConfigTxFile::from_json_file(path)
        .map_err(|e| format!("failed loading file {:?}: {}", path, e))
}
