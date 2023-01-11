// Copyright (c) 2018-2022 The MobileCoin Foundation
//! Configuration parameters for generating key files for a new user identity
use clap::Parser;
use std::{fs, path::PathBuf};

// Hack to work around Vec special handling in clap
type VecBytes = Vec<u8>;
/// Configuration for generating key files for a new user identity
#[derive(Debug, Parser)]
pub struct KeyConfig {
    /// Fog Report URL
    #[clap(long, env = "MC_FOG_REPORT_URL")]
    pub fog_report_url: Option<String>,

    /// Fog Report ID
    #[clap(long, env = "MC_FOG_REPORT_ID", default_value = "")]
    pub fog_report_id: String,

    /// Fog Authority subjectPublicKeyInfo, loaded from a PEM root certificate
    #[clap(long, value_parser = load_spki_from_pemfile, env = "MC_FOG_AUTHORITY_ROOT")]
    pub fog_authority_root: Option<VecBytes>,

    /// Fog Authority subjectPublicKeyInfo, encoded in base 64
    #[clap(long, value_parser = decode_base64, env = "MC_FOG_AUTHORITY_SPKI")]
    pub fog_authority_spki: Option<VecBytes>,

    /// Output directory, defaults to current directory.
    #[clap(long, env = "MC_OUTPUT_DIR")]
    pub output_dir: Option<PathBuf>,

    /// Seed to use when generating keys (e.g.
    /// 1234567812345678123456781234567812345678123456781234567812345678).
    #[clap(short, long, value_parser = mc_util_parse::parse_hex::<[u8; 32]>, env = "MC_SEED", default_value = "0101010101010101010101010101010101010101010101010101010101010101")]
    pub seed: [u8; 32],
}

/// Given a path as a string, read the file, parse it as PEM into DER, parse the
/// DER into x509, and extract the subjectPublicKeyInfo as bytes.
fn load_spki_from_pemfile(src: &str) -> Result<Vec<u8>, String> {
    x509_signature::parse_certificate(
        &pem::parse(fs::read(src).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?
            .contents,
    )
    .map_err(|e| format!("{e:?}"))
    .map(|cert| cert.subject_public_key_info().spki().to_vec())
}

/// Given the spki bytes as base64, decode them
fn decode_base64(src: &str) -> Result<VecBytes, String> {
    base64::decode(src).map_err(|e| e.to_string())
}
