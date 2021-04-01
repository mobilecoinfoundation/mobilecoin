// Copyright (c) 2018-2021 The MobileCoin Foundation

pub mod config;
pub mod keygen;

mod error;
mod json_format;
mod mnemonic_acct;

use crate::{error::Error, json_format::RootIdentityJson, mnemonic_acct::UncheckedMnemonicAccount};
use bip39::Mnemonic;
use mc_account_keys::{AccountKey, PublicAddress, RootIdentity};
use prost::Message;
use std::{convert::TryInto, fs, fs::File, io, path::Path};

/// Write a user's account details to disk
pub fn write_keyfile<P: AsRef<Path>>(
    path: P,
    mnemonic: &Mnemonic,
    account_index: u32,
    fog_report_url: Option<&str>,
    fog_report_id: Option<&str>,
    fog_authority_spki: Option<&[u8]>,
) -> Result<(), Error> {
    let json = UncheckedMnemonicAccount {
        mnemonic: Some(mnemonic.clone().into_phrase()),
        account_index: Some(account_index),
        fog_report_url: fog_report_url.map(ToOwned::to_owned),
        fog_report_id: fog_report_id.map(ToOwned::to_owned),
        fog_authority_spki: fog_authority_spki.map(ToOwned::to_owned),
    };
    Ok(serde_json::to_writer(File::create(path)?, &json)?)
}

/// Read a keyfile intended for use with the legacy `RootEntropy`
/// key-derivation method.
pub fn read_root_entropy_keyfile<P: AsRef<Path>>(path: P) -> Result<RootIdentity, Error> {
    read_root_entropy_keyfile_data(File::open(path)?)
}

/// Read keyfile data from the given buffer into a legacy `RootIdentity`
/// structure
pub fn read_root_entropy_keyfile_data<R: io::Read>(buffer: R) -> Result<RootIdentity, Error> {
    Ok(serde_json::from_reader::<R, RootIdentityJson>(buffer)?.into())
}

/// Read user root identity from disk
pub fn read_keyfile<P: AsRef<Path>>(path: P) -> Result<AccountKey, Error> {
    read_keyfile_data(File::open(path)?)
}

/// Read user root identity from any implementor of `Read`
pub fn read_keyfile_data<R: io::Read>(buffer: R) -> Result<AccountKey, Error> {
    Ok(serde_json::from_reader::<R, UncheckedMnemonicAccount>(buffer)?.try_into()?)
}

/// Write user public address to disk
pub fn write_pubfile<P: AsRef<Path>>(path: P, addr: &PublicAddress) -> Result<(), Error> {
    let mut buf = Vec::with_capacity(addr.encoded_len());
    addr.encode(&mut buf)?;
    fs::write(path, buf)?;
    Ok(())
}

/// Read user public address from disk
pub fn read_pubfile<P: AsRef<Path>>(path: P) -> Result<PublicAddress, Error> {
    Ok(PublicAddress::decode(fs::read(path)?.as_slice())?)
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
