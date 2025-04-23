use clap::Parser;
use mc_api::blockchain::ArchiveBlock;
use mc_attest_core::EvidenceKind;
use mc_common::logger::{create_app_logger, o};
use mc_watcher::watcher_db::WatcherDB;
use std::{fs::File, io::Read, path::PathBuf};

use protobuf::Message;

/// Command line configuration.
#[derive(Debug, Parser)]
#[clap(
    name = "mc-watcher-db-compare-to-pb",
    about = "A utility for getting an AVR report by signer from a watcher db"
)]
pub struct Config {
    /// Path to watcher db (lmdb).
    #[clap(long, default_value = "/tmp/watcher-db", env = "MC_WATCHER_DB")]
    pub watcher_db: PathBuf,

    /// hash of the report
    #[clap(long, default_value = "", env = "MC_PB_FILE")]
    pub pb_file: PathBuf,

    /// hash of the report
    #[clap(long, default_value = "", env = "MC_REPORT_HASH")]
    pub report_hash: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (logger, _global_logger_guard) = create_app_logger(o!());
    let config = Config::parse();

    let mut file = File::open(config.pb_file)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;

    let archive_block = ArchiveBlock::parse_from_bytes(&buf)?;

    let pb_protobuf_dcap_evidence = archive_block
        .get_v1()
        .get_metadata()
        .get_contents()
        .get_dcap_evidence();

    let pb_dcap_evidence: mc_attest_verifier_types::prost::DcapEvidence =
        mc_attest_verifier_types::prost::DcapEvidence::try_from(pb_protobuf_dcap_evidence).unwrap();

    println!("PB DCAP evidence found");
    println!("{:?}", pb_dcap_evidence);

    let watcher_db = WatcherDB::open_ro(&config.watcher_db, logger).expect(
        "Failed opening
    watcher db",
    );

    let report_hash = hex::decode(&config.report_hash).expect(
        "failed to parse report hash from
    hex",
    );

    let report = watcher_db
        .get_attestation_evidence_by_hash(&report_hash)
        .expect("get_attestation_evidence failed");

    let mut db_prost_dcap_evidence = mc_attest_verifier_types::prost::DcapEvidence::default();

    match report {
        Some(report) => match report {
            // It seem that there isn't any epid report in this subdir in the db
            EvidenceKind::Epid(_) => {
                println!("DB EPID report available");
                // println!("{}", report);
            }
            EvidenceKind::Dcap(evidence) => {
                println!("DB DCAP evidence available");
                db_prost_dcap_evidence = evidence.clone();
                println!("{:?}", evidence);
            }
        },
        None => {
            println!("no report available");
        }
    }

    if db_prost_dcap_evidence == pb_dcap_evidence {
        println!("DB and protobuf dcap evidence are equal");
    } else {
        println!("DB and protobuf dcap evidence are NOT equal");
    }

    Ok(())
}
