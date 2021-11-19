// Copyright (c) 2018-2021 The MobileCoin Foundation

mod json_format;
pub use json_format::Slip10IdentityJson;

pub mod config;
pub mod keygen;

use mc_account_keys::PublicAddress;
use mc_api::printable::PrintableWrapper;
use std::{convert::TryInto, fs::File, io::prelude::*, path::Path};

/// Write user root identity to disk
pub fn write_keyfile<P: AsRef<Path>>(
    path: P,
    id: &Slip10IdentityJson,
) -> Result<(), std::io::Error> {
    File::create(path)?.write_all(&serde_json::to_vec(&id).map_err(to_io_error)?)?;
    Ok(())
}

/// Read user root identity from disk
pub fn read_keyfile<P: AsRef<Path>>(path: P) -> Result<Slip10IdentityJson, std::io::Error> {
    read_keyfile_data(&mut File::open(path)?)
}

/// Read user root identity from any implementor of `Read`
pub fn read_keyfile_data<R: std::io::Read>(
    buffer: &mut R,
) -> Result<Slip10IdentityJson, std::io::Error> {
    let data = {
        let mut data = Vec::new();
        buffer.read_to_end(&mut data)?;
        data
    };
    let result: Slip10IdentityJson = serde_json::from_slice(&data).map_err(to_io_error)?;
    Ok(result)
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
pub fn read_b58pubfile_data<R: std::io::Read>(
    buffer: &mut R,
) -> Result<PublicAddress, std::io::Error> {
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
    use rand::{rngs::StdRng, SeedableRng};
    use tempdir::TempDir;

    #[test]
    fn test_keyfile() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let dir = TempDir::new("test").unwrap();

        {
            let entropy = Slip10IdentityJson::random(&mut rng);
            let f1 = dir.path().join("f1");
            write_keyfile(&f1, &entropy).unwrap();
            let result = read_keyfile(&f1).unwrap();
            assert_eq!(entropy, result);
        }

        {
            let entropy = Slip10IdentityJson::random_with_fog(
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
        let dir = TempDir::new("test").unwrap();

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
