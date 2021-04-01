// Copyright (c) 2018-2021 The MobileCoin Foundation

mod json_format;
mod mnemonic_acct;

pub mod config;
pub mod keygen;

use crate::mnemonic_acct::UncheckedMnemonicAccount;
use bip39::Mnemonic;
use json_format::RootIdentityJson;
use mc_account_keys::{AccountKey, PublicAddress, RootIdentity};
use std::{fs::File, io::prelude::*, path::Path};

/// Write user root identity to disk
pub fn write_keyfile<P: AsRef<Path>>(
    path: P,
    mnemonic: &Mnemonic,
    account_index: u32,
    fog_report_url: &str,
    fog_report_id: &str,
    fog_authority_spki: &[u8],
) -> Result<(), std::io::Error> {
    let fog_report_url = if fog_report_url.is_empty() {
        None
    } else {
        Some(fog_report_url.to_owned())
    };
    let fog_report_id = if fog_report_id.is_empty() {
        None
    } else {
        Some(fog_report_id.to_owned())
    };
    let fog_authority_spki = if fog_authority_spki.is_empty() {
        None
    } else {
        Some(fog_authority_spki.to_owned())
    };

    let json = UncheckedMnemonicAccount {
        mnemonic: Some(mnemonic.clone().into_phrase()),
        account_index: Some(account_index),
        fog_report_url,
        fog_report_id,
        fog_authority_spki,
    };
    File::create(path)?.write_all(&serde_json::to_vec(&json).map_err(to_io_error)?)?;
    Ok(())
}

/// Read user root identity from disk
pub fn read_keyfile<P: AsRef<Path>>(path: P) -> Result<RootIdentity, std::io::Error> {
    read_keyfile_data(&mut File::open(path)?)
}

/// Read user root identity from any implementor of `Read`
pub fn read_keyfile_data<R: std::io::Read>(buffer: &mut R) -> Result<AccountKey, std::io::Error> {
    let data = {
        let mut data = Vec::new();
        buffer.read_to_end(&mut data)?;
        data
    };
    Ok(serde_json::from_slice::<UncheckedMnemonicAccount>(&data).map_err())
    let result: RootIdentityJson = serde_json::from_slice(&data).map_err(to_io_error)?;
    Ok(RootIdentity::from(result))
}

/// Write user public address to disk
pub fn write_pubfile<P: AsRef<Path>>(path: P, addr: &PublicAddress) -> Result<(), std::io::Error> {
    File::create(path)?.write_all(&mc_util_serial::encode(addr))?;
    Ok(())
}

/// Read user public address from disk
pub fn read_pubfile<P: AsRef<Path>>(path: P) -> Result<PublicAddress, std::io::Error> {
    read_pubfile_data(&mut File::open(path)?)
}

/// Read user pubfile from any implementor of `Read`
pub fn read_pubfile_data<R: std::io::Read>(
    buffer: &mut R,
) -> Result<PublicAddress, std::io::Error> {
    let data = {
        let mut data = Vec::new();
        buffer.read_to_end(&mut data)?;
        data
    };
    let result: PublicAddress = mc_util_serial::decode(&data).map_err(prost_to_io_error)?;
    Ok(result)
}

fn to_io_error(err: serde_json::error::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, Box::new(err))
}

fn prost_to_io_error(err: mc_util_serial::DecodeError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, Box::new(ProstError { err }))
}

// Helper boilerplate mapping prost::DecodeError to io::Error
#[derive(Debug)]
struct ProstError {
    pub err: mc_util_serial::DecodeError,
}

impl std::fmt::Display for ProstError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(fmt, "prost deserialization failed: {}", self.err)
    }
}

impl std::error::Error for ProstError {
    fn description(&self) -> &str {
        "prost deserialization failed"
    }

    fn cause(&self) -> Option<&dyn std::error::Error> {
        // Generic error, underlying cause isn't tracked.
        None
    }
}

#[cfg(test)]
mod testing {
    use super::*;

    use mc_account_keys::AccountKey;
    use mc_util_from_random::FromRandom;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn test_keyfile() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let dir = tempfile::tempdir();

        {
            let entropy = RootIdentity::from_random(&mut rng);
            let f1 = dir.path().join("f1");
            write_keyfile(&f1, &entropy).unwrap();
            let result = read_keyfile(&f1).unwrap();
            assert_eq!(entropy, result);
        }

        {
            let entropy = RootIdentity::random_with_fog(
                &mut rng,
                "fog://foobar.com",
                "",
                &[9u8, 9u8, 9u8, 9u8],
            );
            let f1 = dir.path().join("f0");
            write_keyfile(&f1, &entropy).unwrap();
            let result = read_keyfile(&f1).unwrap();
            assert_eq!(entropy, result);
        }
    }

    #[test]
    fn test_pubfile() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let dir = tempfile::tempdir();

        {
            let acct_key = AccountKey::random(&mut rng);
            let pubaddr = acct_key.default_subaddress();
            let f2 = dir.path().join("f2");
            write_pubfile(&f2, &pubaddr).unwrap();
            let result = read_pubfile(&f2).unwrap();
            assert_eq!(pubaddr, result);
        }

        {
            let acct_key = AccountKey::random_with_fog(&mut rng);
            let pubaddr = acct_key.default_subaddress();
            let f3 = dir.path().join("f3");
            write_pubfile(&f3, &pubaddr).unwrap();
            let result = read_pubfile(&f3).unwrap();
            assert_eq!(pubaddr, result);
        }
    }
}
