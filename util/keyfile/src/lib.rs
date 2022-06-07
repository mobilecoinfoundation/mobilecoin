// Copyright (c) 2018-2022 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

mod error;
mod json_format;
mod mnemonic_acct;
pub use json_format::RootIdentityJson;
pub use mnemonic_acct::UncheckedMnemonicAccount;
pub mod config;
pub mod keygen;

use crate::error::Error;
use bip39::Mnemonic;
use mc_account_keys::{AccountKey, PublicAddress, RootIdentity};
use mc_api::printable::PrintableWrapper;
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

/// Write a user's account details to disk
pub fn write_keyfile<P: AsRef<Path>>(
    path: P,
    mnemonic: &Mnemonic,
    account_index: u32,
    fog_report_url: Option<&str>,
    fog_report_id: &str,
    fog_authority_spki: Option<&[u8]>,
) -> Result<(), Error> {
    let json = UncheckedMnemonicAccount {
        mnemonic: Some(mnemonic.clone().into_phrase()),
        account_index: Some(account_index),
        fog_report_url: fog_report_url.map(ToOwned::to_owned),
        fog_report_id: Some(fog_report_id.to_owned()),
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
pub fn read_root_entropy_keyfile_data<R: Read>(buffer: R) -> Result<RootIdentity, Error> {
    Ok(serde_json::from_reader::<R, RootIdentityJson>(buffer)?.into())
}

/// Read user mnemonic from disk
pub fn read_mnemonic_keyfile<P: AsRef<Path>>(path: P) -> Result<AccountKey, Error> {
    read_mnemonic_keyfile_data(File::open(path)?)
}

/// Read user root identity from any implementor of `Read`
pub fn read_mnemonic_keyfile_data<R: Read>(buffer: R) -> Result<AccountKey, Error> {
    Ok(serde_json::from_reader::<R, UncheckedMnemonicAccount>(buffer)?.try_into()?)
}

/// Read an account either in the RootIdentity format or the mnemonic format
/// from disk
pub fn read_keyfile<P: AsRef<Path>>(path: P) -> Result<AccountKey, Error> {
    read_keyfile_data(File::open(path)?)
}

/// Read an account key file in either format
pub fn read_keyfile_data<R: Read>(buffer: R) -> Result<AccountKey, Error> {
    let value = serde_json::from_reader::<R, serde_json::Value>(buffer)?;
    let obj = value
        .as_object()
        .ok_or_else(|| Error::Json("Expected json object".to_string()))?;
    if obj.contains_key("root_entropy") {
        let root_identity_json: RootIdentityJson = serde_json::from_value(value)?;
        let root_id = RootIdentity::from(root_identity_json);
        Ok(AccountKey::from(&root_id))
    } else {
        let mnemonic_json: UncheckedMnemonicAccount = serde_json::from_value(value)?;
        Ok(AccountKey::try_from(mnemonic_json)?)
    }
}

/// Write user public address to disk
pub fn write_pubfile<P: AsRef<Path>>(path: P, addr: &PublicAddress) -> Result<(), Error> {
    File::create(path)?.write_all(&mc_util_serial::encode(addr))?;
    Ok(())
}
/// Read user public address from disk
pub fn read_pubfile<P: AsRef<Path>>(path: P) -> Result<PublicAddress, Error> {
    read_pubfile_data(&mut File::open(path)?)
}

/// Read user pubfile from any implementor of `Read`
pub fn read_pubfile_data<R: Read>(buffer: &mut R) -> Result<PublicAddress, Error> {
    let data = {
        let mut data = Vec::new();
        buffer.read_to_end(&mut data)?;
        data
    };
    let result: PublicAddress = mc_util_serial::decode(&data)?;
    Ok(result)
}

/// Write user b58 public address to disk
pub fn write_b58pubfile<P: AsRef<Path>>(
    path: P,
    addr: &PublicAddress,
) -> Result<(), std::io::Error> {
    let mut wrapper = PrintableWrapper::new();
    wrapper.set_public_address(addr.into());

    let data = wrapper.b58_encode().map_err(to_io_error)?;

    File::create(path)?.write_all(data.as_ref())?;
    Ok(())
}

/// Read user b58 public address from disk
pub fn read_b58pubfile<P: AsRef<Path>>(path: P) -> Result<PublicAddress, std::io::Error> {
    read_b58pubfile_data(&mut File::open(path)?)
}

/// Read user b58 pubfile from any implementor of `Read`
pub fn read_b58pubfile_data<R: Read>(buffer: &mut R) -> Result<PublicAddress, std::io::Error> {
    let data = {
        let mut data = String::new();
        buffer.read_to_string(&mut data)?;
        data
    };

    let wrapper = PrintableWrapper::b58_decode(data).map_err(to_io_error)?;

    if !wrapper.has_public_address() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Printable Wrapper did not contain public address",
        ));
    }
    wrapper.get_public_address().try_into().map_err(to_io_error)
}

fn to_io_error<E: 'static + std::error::Error + Send + Sync>(err: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, Box::new(err))
}

#[cfg(test)]
mod testing {

    use super::*;
    use bip39::{Language, MnemonicType};
    use mc_account_keys::AccountKey;
    use mc_account_keys_slip10::{Slip10Key, Slip10KeyGenerator};
    use mc_util_test_utils::tempdir;

    /// Test that round-tripping through a keyfile without fog gets the same
    /// result as creating the key directly.
    #[test]
    fn keyfile_roundtrip_no_fog() {
        let dir = tempdir();
        let mnemonic = Mnemonic::new(MnemonicType::Words24, Language::English);
        let path = dir.path().join("no_fog");
        write_keyfile(&path, &mnemonic, 0, None, "", None).expect("Could not write keyfile");
        let expected = AccountKey::from(mnemonic.derive_slip10_key(0));
        let actual = read_keyfile(&path).expect("Could not read keyfile");
        assert_eq!(expected, actual);
    }

    /// Test that round-tripping through a keyfile with fog gets the same result
    /// as creating the key directly.
    #[test]
    fn keyfile_roundtrip_with_fog() {
        let fog_report_url = "fog://unittest.mobilecoin.com";
        let fog_report_id = "1";
        let der_bytes = pem::parse(mc_crypto_x509_test_vectors::ok_rsa_head())
            .expect("Could not parse DER bytes from PEM certificate file")
            .contents;
        let fog_authority_spki = x509_signature::parse_certificate(&der_bytes)
            .expect("Could not parse X509 certificate from DER bytes")
            .subject_public_key_info()
            .spki();

        let dir = tempdir();
        let mnemonic = Mnemonic::new(MnemonicType::Words24, Language::English);

        let path = dir.path().join("with_fog");
        write_keyfile(
            &path,
            &mnemonic,
            0,
            Some(fog_report_url),
            fog_report_id,
            Some(fog_authority_spki),
        )
        .expect("Could not write keyfile");

        let expected = mnemonic
            .derive_slip10_key(0)
            .try_into_account_key(fog_report_url, fog_report_id, fog_authority_spki)
            .expect("Could not create expected account key");
        let actual = read_keyfile(&path).expect("Could not read keyfile");
        assert_eq!(expected, actual);
    }

    /// Test that writing a [`PublicAddress`](mc_account_keys::PublicAddress)
    /// and reading it back without fog details gets the same results.
    #[test]
    fn pubfile_roundtrip_no_fog() {
        let expected = AccountKey::from(Slip10Key::from(Mnemonic::new(
            MnemonicType::Words24,
            Language::English,
        )))
        .default_subaddress();

        let dir = tempdir();
        let path = dir.path().join("pubfile_no_fog");
        write_pubfile(&path, &expected).expect("Could not write pubfile");
        let actual = read_pubfile(&path).expect("Could not read back pubfile");
        assert_eq!(expected, actual);
    }

    /// Test that writing a [`PublicAddress`](mc_account_keys::PublicAddress)
    /// and reading it back with fog details gets the same results.
    #[test]
    fn pubfile_roundtrip_with_fog() {
        let fog_report_url = "fog://unittest.mobilecoin.com";
        let fog_report_id = "1";
        let der_bytes = pem::parse(mc_crypto_x509_test_vectors::ok_rsa_head())
            .expect("Could not parse DER bytes from PEM certificate file")
            .contents;
        let fog_authority_spki = x509_signature::parse_certificate(&der_bytes)
            .expect("Could not parse X509 certificate from DER bytes")
            .subject_public_key_info()
            .spki();
        let expected = Slip10Key::from(Mnemonic::new(MnemonicType::Words24, Language::English))
            .try_into_account_key(fog_report_url, fog_report_id, fog_authority_spki)
            .expect("Could not create expected account key")
            .default_subaddress();

        let dir = tempdir();
        let path = dir.path().join("pubfile_with_fog");
        write_pubfile(&path, &expected).expect("Could not write fog pubfile");
        let actual = read_pubfile(&path).expect("Could not read back fog pubfile");
        assert_eq!(expected, actual);
    }
}
