// Copyright (c) 2018-2021 The MobileCoin Foundation

use clap::Parser;
use hex::FromHex;
use std::{fs, path::PathBuf, string::ToString, vec::Vec};

// Hack to work around Vec special handling in clap
type VecBytes = Vec<u8>;

#[derive(Debug, Parser)]
struct Config {
    /// Fog Report URL
    #[clap(long, env = "MC_FOG_REPORT_URL")]
    pub fog_report_url: Option<String>,

    /// Fog Report ID
    #[clap(long, env = "MC_FOG_REPORT_ID")]
    pub fog_report_id: Option<String>,

    /// Fog Authority subjectPublicKeyInfo, loaded from a PEM root certificate
    #[clap(long, parse(try_from_str = load_spki_from_pemfile), env = "MC_FOG_AUTHORITY_ROOT")]
    pub fog_authority_root: Option<VecBytes>,

    /// Fog Authority subjectPublicKeyInfo, encoded in base 64
    #[clap(long, parse(try_from_str = decode_base64), env = "MC_FOG_AUTHORITY_SPKI")]
    pub fog_authority_spki: Option<VecBytes>,

    /// Number of user keys to generate.
    #[clap(short, long, default_value = "10", env = "MC_NUM")]
    pub num: usize,

    /// Output directory, defaults to ./keys
    #[clap(long, env = "MC_OUTPUT_DIR")]
    pub output_dir: Option<PathBuf>,

    // Seed to use when generating keys (e.g.
    // 1234567812345678123456781234567812345678123456781234567812345678).
    #[clap(short, long, parse(try_from_str = FromHex::from_hex), env = "MC_SEED")]
    pub seed: Option<[u8; 32]>,
}

/// Given a path as a string, read the file, parse it as PEM into DER, parse the
/// DER into x509, and extract the subjectPublicKeyInfo as bytes.
fn load_spki_from_pemfile(src: &str) -> Result<VecBytes, String> {
    x509_signature::parse_certificate(
        &pem::parse(fs::read(src).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?
            .contents,
    )
    .map_err(|e| format!("{:?}", e))
    .map(|cert| cert.subject_public_key_info().spki().to_vec())
}

/// Given the spki bytes as base64, decode them
fn decode_base64(src: &str) -> Result<VecBytes, String> {
    base64::decode(src).map_err(|e| e.to_string())
}

fn main() {
    let config = Config::parse();

    let path = config
        .output_dir
        .clone()
        .unwrap_or_else(|| std::env::current_dir().unwrap().join("keys"));

    let spki = config
        .fog_authority_root
        .as_ref()
        .or_else(|| config.fog_authority_spki.as_ref())
        .cloned();

    if config.fog_report_url.is_some() && spki.is_none() {
        panic!("Fog report url was passed, so fog is enabled, but no fog authority spki was provided. This is needed for the fog authority signature scheme. Use --fog-authority-root to pass a .pem file or --fog-authority-spki to pass base64 encoded bytes specifying this")
    }

    println!("Writing {} keys to {:?}", config.num, path);

    mc_util_keyfile::keygen::write_default_keyfiles(
        path,
        config.num,
        config.fog_report_url.as_deref(),
        config.fog_report_id.as_deref(),
        spki.as_deref(),
        config.seed.unwrap_or(mc_util_keyfile::keygen::DEFAULT_SEED),
    )
    .unwrap();
}
