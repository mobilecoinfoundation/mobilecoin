// Copyright (c) 2018-2020 MobileCoin Inc.

//! A tool for writing .json file and .pub file to disk, corresponding to
//! `transaction::account_keys::AccountKey` root entropy, and `transaction::account_keys::PublicAddress`
//! respectively.

use crate::{read_keyfile, read_pubfile, write_keyfile, write_pubfile};
use rand::SeedableRng;
use rand_hc::Hc128Rng as FixedRng;
use std::{fs, path::Path};
use transaction::account_keys::{AccountKey, PublicAddress};
use transaction_std::identity::RootIdentity;

pub const DEFAULT_SEED: [u8; 32] = [1; 32];

// Write a single pair of keyfiles using a given name and data
pub fn write_keyfiles<P: AsRef<Path>>(
    path: P,
    name: &str,
    root_id: &RootIdentity,
) -> Result<(), std::io::Error> {
    let acct_key = AccountKey::from(root_id);

    fs::create_dir_all(&path)?;

    write_keyfile(path.as_ref().join(name).with_extension("json"), &root_id)?;
    write_pubfile(
        path.as_ref().join(name).with_extension("pub"),
        &acct_key.default_subaddress(),
    )?;
    Ok(())
}

// These functions help when implementing bootstrap / initialization / tests

// Helper: Make i'th user's keyfiles' names
fn keyfile_name(i: usize) -> String {
    format!("account_keys_{}", i)
}

// Write the sequence of default user key files used in tests and demos
pub fn write_default_keyfiles<P: AsRef<Path>>(
    path: P,
    num_accounts: usize,
    fog_url: Option<&str>,
    seed: [u8; 32],
) -> Result<(), std::io::Error> {
    let mut keys_rng: FixedRng = SeedableRng::from_seed(seed);

    // Generate user keys
    for i in 0..num_accounts {
        let root_id = RootIdentity::random(&mut keys_rng, fog_url);

        write_keyfiles(path.as_ref(), &keyfile_name(i), &root_id)?;
    }
    Ok(())
}

// Read default pubkeys used in tests and demos
pub fn read_default_pubfiles<P: AsRef<Path>>(
    path: P,
) -> Result<Vec<PublicAddress>, std::io::Error> {
    let mut result = Vec::new();
    loop {
        let name = keyfile_name(result.len());
        let file = path.as_ref().join(name).with_extension("pub");
        if !file.exists() {
            break;
        }
        result.push(read_pubfile(file)?);
    }
    Ok(result)
}

// Read default root entropies
pub fn read_default_root_entropies<P: AsRef<Path>>(
    path: P,
) -> Result<Vec<RootIdentity>, std::io::Error> {
    let mut result = Vec::new();
    loop {
        let name = keyfile_name(result.len());
        let file = path.as_ref().join(name).with_extension("json");
        if !file.exists() {
            break;
        }
        result.push(read_keyfile(file)?);
    }
    Ok(result)
}

#[cfg(test)]
mod testing {
    use super::*;
    use tempdir::TempDir;

    #[test]
    fn test_default_generation() {
        let dir1 = TempDir::new("test").unwrap();
        let dir2 = TempDir::new("test").unwrap();

        let fqdn = "example.com".to_string();
        write_default_keyfiles(&dir1, 10, Some(&fqdn), DEFAULT_SEED).unwrap();
        write_default_keyfiles(&dir2, 10, Some(&fqdn), DEFAULT_SEED).unwrap();

        {
            let pub1 = read_default_pubfiles(&dir1).unwrap();
            let pub2 = read_default_pubfiles(&dir2).unwrap();

            assert_eq!(pub1.len(), 10);
            assert_eq!(pub2.len(), 10);
            assert_eq!(&pub1[..], &pub2[..]);
        }
        {
            let bin1 = read_default_root_entropies(&dir1).unwrap();
            let bin2 = read_default_root_entropies(&dir2).unwrap();

            assert_eq!(bin1.len(), 10);
            assert_eq!(bin2.len(), 10);
            assert_eq!(&bin1[..], &bin2[..]);
        }
    }

    #[test]
    fn test_default_generation_no_acct() {
        let dir1 = TempDir::new("test").unwrap();
        let dir2 = TempDir::new("test").unwrap();

        write_default_keyfiles(&dir1, 10, None, DEFAULT_SEED).unwrap();
        write_default_keyfiles(&dir2, 10, None, DEFAULT_SEED).unwrap();

        {
            let pub1 = read_default_pubfiles(&dir1).unwrap();
            let pub2 = read_default_pubfiles(&dir2).unwrap();

            assert_eq!(pub1.len(), 10);
            assert_eq!(pub2.len(), 10);
            assert_eq!(&pub1[..], &pub2[..]);
        }
        {
            let bin1 = read_default_root_entropies(&dir1).unwrap();
            let bin2 = read_default_root_entropies(&dir2).unwrap();

            assert_eq!(bin1.len(), 10);
            assert_eq!(bin2.len(), 10);
            assert_eq!(&bin1[..], &bin2[..]);
        }
    }

    #[test]
    fn test_hard_coded_root_entropy() {
        let dir1 = TempDir::new("test").unwrap();

        write_default_keyfiles(&dir1, 10, None, DEFAULT_SEED).unwrap();

        {
            let bin1 = read_default_root_entropies(&dir1).unwrap();
            assert_eq!(bin1.len(), 10);
            assert_eq!(
                bin1[0],
                RootIdentity {
                    root_entropy: [
                        2, 154, 47, 57, 69, 168, 246, 187, 31, 181, 177, 26, 84, 40, 58, 64, 82,
                        109, 40, 35, 89, 36, 57, 5, 241, 163, 13, 184, 42, 158, 89, 124
                    ],
                    fog_url: None
                }
            );
        }
    }
}
