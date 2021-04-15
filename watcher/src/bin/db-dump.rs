// Copyright (c) 2018-2021 The MobileCoin Foundation

//! A utility for examining the contents of a given watcher db.

use mc_attest_core::VerificationReportData;
use mc_common::logger::{create_app_logger, o};
use mc_crypto_keys::Ed25519Public;
use mc_util_repr_bytes::ReprBytes;
use mc_watcher::{error::WatcherDBError, watcher_db::WatcherDB};
use std::{convert::TryFrom, path::PathBuf};
use structopt::StructOpt;
use url::Url;

/// Command line configuration.
#[derive(Debug, StructOpt)]
#[structopt(
    name = "mc-watcher-db-dump",
    about = "A utility for examining the contents of a given watcher db"
)]
pub struct Config {
    /// Path to watcher db (lmdb).
    #[structopt(long, default_value = "/tmp/watcher-db", parse(from_os_str))]
    pub watcher_db: PathBuf,
}

fn main() {
    let (logger, _global_logger_guard) = create_app_logger(o!());

    let config = Config::from_args();
    let watcher_db =
        WatcherDB::open_ro(&config.watcher_db, logger).expect("Failed opening watcher db");

    let last_synced_blocks = watcher_db
        .last_synced_blocks()
        .expect("last_synced_blocks failed");
    if last_synced_blocks.is_empty() {
        println!("Last synced blocks is empty - aborting");
        return;
    }

    let max_url_len = last_synced_blocks
        .iter()
        .map(|(url, _block_index)| url.as_str().len())
        .max()
        .unwrap_or(0);

    println!("Last synced blocks:");
    for (url, block_index) in last_synced_blocks.iter() {
        println!("{:width$}: {:?}", url, block_index, width = max_url_len);
    }
    println!();

    println!("Signers:");
    for (tx_src_url, max_block_index) in last_synced_blocks.iter() {
        let max_block_count = max_block_index.map(|idx| idx + 1).unwrap_or(0);

        // Construct a list of ranges, where each range is mapped to the signer that
        // signed the range, assuming that information is available.
        let mut ranges = Vec::new();
        let mut cur_start_index = 0;
        let mut cur_end_index = 0;
        let mut cur_signer = None;
        for block_index in 0..max_block_count {
            let signer = match watcher_db.get_block_data(tx_src_url, block_index) {
                Ok(block_data) => block_data.signature().clone().map(|sig| *sig.signer()),
                Err(WatcherDBError::NotFound) => None,
                Err(err) => {
                    panic!(
                        "Failed getting block {}@{}: {}",
                        tx_src_url, cur_start_index, err
                    );
                }
            };

            if signer == cur_signer {
                cur_end_index += 1;
            } else {
                ranges.push(((cur_start_index, cur_end_index), cur_signer.take()));
                cur_start_index = block_index;
                cur_end_index = block_index;
                cur_signer = signer;
            }
        }
        ranges.push(((cur_start_index, cur_end_index), cur_signer.take()));

        println!("{}", tx_src_url);
        for ((start, end), signer) in ranges.iter() {
            let report_status = display_report_status(&watcher_db, tx_src_url, signer);

            println!(
                " - {} - {}: {:?} ({})",
                start,
                end,
                signer.map(|s| hex::encode(s.to_bytes())),
                report_status,
            );
        }
        println!();
    }
}

fn display_report_status(
    watcher_db: &WatcherDB,
    tx_src_url: &Url,
    signer: &Option<Ed25519Public>,
) -> String {
    if signer.is_none() {
        return "no signature".to_owned();
    }

    let signer = signer.unwrap();

    let reports = watcher_db
        .get_verification_reports_for_signer(&signer)
        .expect("get_verification_reports_for_signer failed");

    // Should only have one URL associated with this signer
    match reports.len() {
        0 => "no reports".to_owned(),
        1 => match reports.get(tx_src_url) {
            Some(reports) => {
                // Should only have one report associated with the signer+url pair
                match reports.len() {
                    0 => "no reports".to_owned(),
                    1 => match &reports[0] {
                        Some(report) => {
                            let report_data = VerificationReportData::try_from(report)
                                .expect("failed constructing verification report data");
                            format!(
                                "report available, id {} generated at {}",
                                report_data.id, report_data.timestamp
                            )
                        }
                        None => "no report".to_owned(),
                    },
                    _ => "MULTIPLE REPORTS AVAILABLE".to_owned(),
                }
            }
            None => format!(
                "Signer reported for a different URL ({})!",
                reports.keys().next().unwrap()
            ),
        },
        _ => "MULTIPLE REPORTS".to_owned(),
    }
}
