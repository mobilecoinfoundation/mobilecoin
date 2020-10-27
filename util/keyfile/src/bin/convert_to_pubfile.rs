// Copyright (c) 2018-2020 MobileCoin Inc.

//! Processees pubkeys to file format understood by ingest add_user.
//!
//! This tool can be followed up by a call to add_user, e.g. with
//! `cargo run fog-ingest-client -- --uri fog-ingest://fog-ingest.NETWORKNAME.mobilecoin.com:443 add-users --keys-path ./fog_keys`

use mc_account_keys::PublicAddress;
use mc_api::external;
use mc_util_keyfile::write_pubfile;
use protobuf::parse_from_bytes;
use std::{convert::TryFrom, fs, path::PathBuf};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct Config {
    /// Path to input pubfile dir
    ///
    /// Note: Pubfile format is expected to be a the hex-encoded protobuf bytes.
    #[structopt(long)]
    pub pubfile_in_dir: PathBuf,

    /// Path to output pubfile dir
    #[structopt(long)]
    pub pubfile_out_dir: PathBuf,
}

fn read_to_pubkeys(
    pubfile_in_dir: PathBuf,
) -> Result<Vec<(PublicAddress, PathBuf)>, std::io::Error> {
    let mut pub_addrs: Vec<(PublicAddress, PathBuf)> = Vec::new();
    for entry in fs::read_dir(pubfile_in_dir)? {
        let entry_path = entry?.path();
        let pub_str = fs::read_to_string(entry_path.clone())?;
        let pub_string: String = pub_str.split_whitespace().collect();
        let data = hex::decode(pub_string).expect("Could not hex decode public address string");
        let pub_addr_proto: external::PublicAddress =
            parse_from_bytes(&data).expect("Could not parse public address from bytes");
        let pub_addr = PublicAddress::try_from(&pub_addr_proto)
            .expect("Could not convert public address proto to PublicAddress");
        pub_addrs.push((pub_addr, entry_path));
    }
    Ok(pub_addrs)
}

fn main() {
    let config = Config::from_args();

    let pub_addrs = read_to_pubkeys(config.pubfile_in_dir).expect("Could not read to pubkeys");

    for (pub_addr, entry) in pub_addrs {
        let outpath = config
            .pubfile_out_dir
            .join(entry.file_stem().expect("Could not create outpath"));
        write_pubfile(outpath.with_extension("pub"), &pub_addr).expect("Could not write pubfile");
    }
}

#[cfg(test)]
mod convert_pubkeys_tests {

    use super::*;
    use mc_crypto_keys::RistrettoPublic;
    use std::{collections::HashSet, iter::FromIterator};

    #[test]
    fn test_convert() {
        let pubkeys = read_to_pubkeys(PathBuf::from("./test_data")).unwrap();
        assert_eq!(pubkeys.len(), 2);

        // Convert to HashSet so that order doesn't matter
        let found: HashSet<PublicAddress> = HashSet::from_iter(pubkeys.iter().map(|x| x.0.clone()));

        let expected0 = PublicAddress::new_with_fog(
            &RistrettoPublic::try_from(&[
                84, 8, 242, 215, 119, 170, 238, 63, 57, 46, 4, 168, 28, 201, 156, 46, 114, 61, 85,
                21, 218, 17, 135, 246, 16, 113, 84, 157, 45, 63, 197, 110,
            ])
            .unwrap(),
            &RistrettoPublic::try_from(&[
                86, 38, 107, 45, 17, 228, 38, 13, 155, 222, 101, 63, 179, 33, 193, 57, 92, 99, 15,
                104, 205, 149, 145, 120, 100, 38, 209, 5, 89, 211, 123, 57,
            ])
            .unwrap(),
            "fog-view://discovery.alpha.mobilecoin.com:443",
            "".to_string(),
            vec![],
        );
        let expected1 = PublicAddress::new_with_fog(
            &RistrettoPublic::try_from(&[
                78, 228, 112, 209, 204, 62, 75, 223, 135, 90, 181, 224, 152, 179, 128, 17, 86, 72,
                181, 128, 209, 210, 20, 232, 254, 7, 90, 168, 38, 178, 164, 41,
            ])
            .unwrap(),
            &RistrettoPublic::try_from(&[
                162, 16, 115, 250, 161, 55, 163, 163, 174, 8, 198, 22, 95, 191, 166, 27, 13, 101,
                229, 8, 50, 27, 227, 123, 200, 237, 240, 205, 194, 234, 148, 73,
            ])
            .unwrap(),
            "fog-view://discovery.alpha.mobilecoin.com:443",
            "".to_string(),
            vec![],
        );
        let expected: HashSet<PublicAddress> = HashSet::from_iter(vec![expected0, expected1]);
        assert_eq!(expected, found);
    }
}
