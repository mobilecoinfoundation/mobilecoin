// Copyright (c) 2018-2021 The MobileCoin Foundation

use mc_attest_net::{Client as AttestClient, RaClient};
use mc_common::{
    logger::{o, Logger},
    ResponderId,
};
use mc_crypto_keys::{Ed25519Pair, RistrettoPublic};
use mc_fog_ingest_server::{
    server::{IngestServer, IngestServerConfig},
    state_file::StateFile,
};
use mc_fog_sql_recovery_db::SqlRecoveryDb;
use mc_fog_test_infra::get_enclave_path;
use mc_fog_uri::{FogIngestUri, IngestPeerUri};
use mc_ledger_db::{Ledger, LedgerDB};
use mc_transaction_core::{
    encrypted_fog_hint::EncryptedFogHint,
    membership_proofs::Range,
    ring_signature::KeyImage,
    tx::{TxOut, TxOutMembershipElement, TxOutMembershipHash},
    Amount, Block, BlockContents, BlockData, BlockSignature, BLOCK_VERSION,
};
use mc_util_from_random::FromRandom;
use mc_watcher::watcher_db::WatcherDB;
use rand_core::{CryptoRng, RngCore};
use std::{
    collections::BTreeSet,
    path::Path,
    str::FromStr,
    time::{Duration, SystemTime},
};
use tempdir::TempDir;
use url::Url;

const OMAP_CAPACITY: u64 = 4096;
const BASE_PORT: u16 = 4997;

// Helper which makes URIs and responder id for i'th server
pub fn make_uris(idx: u16) -> (ResponderId, FogIngestUri, IngestPeerUri) {
    let base_port = BASE_PORT + 10 * idx;

    let local_node_id = ResponderId::from_str(&format!("0.0.0.0:{}", base_port + 5)).unwrap();
    let client_listen_uri =
        FogIngestUri::from_str(&format!("insecure-fog-ingest://0.0.0.0:{}/", base_port + 4))
            .unwrap();
    let peer_listen_uri =
        IngestPeerUri::from_str(&format!("insecure-igp://0.0.0.0:{}/", base_port + 5)).unwrap();

    (local_node_id, client_listen_uri, peer_listen_uri)
}

// Helper which makes i'th server and temp dir for its stuff (deleted when
// objects are dropped)
pub fn make_node(
    idx: u16,
    peer_idxs: impl Iterator<Item = u16>,
    db: SqlRecoveryDb,
    watcher_path: &Path,
    ledger_db_path: &Path,
    logger: Logger,
) -> (
    IngestServer<AttestClient, SqlRecoveryDb>,
    TempDir,
    FogIngestUri,
) {
    let logger = logger.new(o!("mc.node_id" => idx.to_string()));

    let (local_node_id, client_listen_uri, peer_listen_uri) = make_uris(idx);

    let peers: BTreeSet<IngestPeerUri> = peer_idxs.map(|idx| make_uris(idx).2).collect();

    let state_tmp = TempDir::new("ingest_state").expect("Could not make tempdir for ingest state");
    let state_file = state_tmp.path().join(format!("mc-ingest-state-{}", idx));

    let config = IngestServerConfig {
        ias_spid: Default::default(),
        local_node_id,
        peer_listen_uri,
        peers,
        fog_report_id: Default::default(),
        client_listen_uri: client_listen_uri.clone(),
        max_transactions: 10_000,
        pubkey_expiry_window: 10,
        peer_checkup_period: Some(Duration::from_secs(5)),
        watcher_timeout: Duration::from_secs(5),
        state_file: Some(StateFile::new(state_file)),
        enclave_path: get_enclave_path(mc_fog_ingest_enclave::ENCLAVE_FILE),
        omap_capacity: OMAP_CAPACITY,
    };

    // Open the Watcher DB
    let watcher = WatcherDB::open_ro(watcher_path, logger.clone()).unwrap();

    // Open the ledger db
    let ledger_db = LedgerDB::open(ledger_db_path).unwrap();

    let ra_client = AttestClient::new("").expect("Could not create IAS client");
    let mut node = IngestServer::new(config, ra_client, db, watcher, ledger_db, logger);
    node.start().expect("couldn't start node");

    (node, state_tmp, client_listen_uri)
}

// Add an arbitrary block to ledger and a timestamp for it
pub fn add_test_block<T: RngCore + CryptoRng>(
    ledger: &mut LedgerDB,
    watcher: &WatcherDB,
    rng: &mut T,
) {
    // Make the new block and append to database
    let num_blocks = ledger.num_blocks().expect("Could not compute num_blocks");
    assert_ne!(0, num_blocks);
    let tx_source_url = Url::from_str("https://localhost").unwrap();

    let last_block = ledger
        .get_block(num_blocks - 1)
        .expect("Could not get last block");

    let key_images = vec![KeyImage::from(rng.next_u64())];

    let block_contents = BlockContents::new(key_images, random_output(rng));

    // Fake proofs
    let root_element = TxOutMembershipElement {
        range: Range::new(0, num_blocks as u64).unwrap(),
        hash: TxOutMembershipHash::from([0u8; 32]),
    };

    let block = Block::new_with_parent(BLOCK_VERSION, &last_block, &root_element, &block_contents);

    let signer = Ed25519Pair::from_random(rng);

    let mut block_sig = BlockSignature::from_block_and_keypair(&block, &signer).unwrap();
    block_sig.set_signed_at(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    );

    ledger
        .append_block(&block, &block_contents, None)
        .expect("Could not append block");

    let block_data = BlockData::new(block, block_contents, Some(block_sig.clone()));

    watcher
        .add_block_data(&tx_source_url, &block_data)
        .expect("Could not add block data to watcher");

    watcher
        .add_block_signature(&tx_source_url, num_blocks, block_sig, "archive".to_string())
        .expect("Could not add block signature to watcher");
}

// Make a random output for a block
pub fn random_output<T: RngCore + CryptoRng>(rng: &mut T) -> Vec<TxOut> {
    vec![TxOut {
        amount: Amount::default(),
        target_key: RistrettoPublic::from_random(rng).into(),
        public_key: RistrettoPublic::from_random(rng).into(),
        e_fog_hint: EncryptedFogHint::default(),
        e_memo: None,
    }]
}
