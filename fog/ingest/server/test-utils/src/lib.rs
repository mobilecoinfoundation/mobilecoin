// Copyright (c) 2018-2022 The MobileCoin Foundation

use mc_attest_net::{Client as AttestClient, RaClient};
use mc_common::logger::{log, o, Logger};
use mc_crypto_keys::{CompressedRistrettoPublic, Ed25519Pair, RistrettoPublic};
use mc_fog_ingest_server::{
    server::{IngestServer, IngestServerConfig},
    state_file::StateFile,
};
use mc_fog_recovery_db_iface::RecoveryDb;
use mc_fog_sql_recovery_db::{test_utils::SqlRecoveryDbTestContext, SqlRecoveryDb};
use mc_fog_test_infra::get_enclave_path;
use mc_fog_uri::{ConnectionUri, FogIngestUri, IngestPeerUri};
use mc_ledger_db::{Ledger, LedgerDB};
use mc_transaction_core::{
    encrypted_fog_hint::EncryptedFogHint,
    membership_proofs::Range,
    ring_signature::KeyImage,
    tx::{TxOut, TxOutMembershipElement, TxOutMembershipHash},
    Block, BlockContents, BlockData, BlockSignature, BlockVersion, MaskedAmount,
};
use mc_util_from_random::FromRandom;
use mc_watcher::watcher_db::WatcherDB;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use rand_hc::Hc128Rng;
use std::{
    collections::BTreeSet,
    convert::TryInto,
    ops::{Deref, DerefMut},
    path::PathBuf,
    str::FromStr,
    sync::Arc,
    thread::sleep,
    time::{Duration, Instant, SystemTime},
};
use tempdir::TempDir;
use url::Url;

const OMAP_CAPACITY: u64 = 4096;

// Helper which makes URIs and responder id for i'th server
fn make_uris(base_port: u16, idx: u8) -> (FogIngestUri, IngestPeerUri) {
    let port = base_port + 5 * (idx as u16 + 1);
    let client_listen_uri =
        FogIngestUri::from_str(&format!("insecure-fog-ingest://0.0.0.0:{}/", port)).unwrap();
    let peer_listen_uri =
        IngestPeerUri::from_str(&format!("insecure-igp://0.0.0.0:{}/", port + 1)).unwrap();

    (client_listen_uri, peer_listen_uri)
}

/// Test helper wrapping an IngestServer, tracking its state file path, and
/// client and peer listen URIs.
pub struct TestIngestNode {
    pub server: IngestServer<AttestClient, SqlRecoveryDb>,
    pub state_file_path: PathBuf,
    pub client_listen_uri: FogIngestUri,
    pub peer_listen_uri: IngestPeerUri,
}

impl TestIngestNode {
    /// Helper to fetch and parse the ingress pubkey for this node.
    pub fn get_ingress_key(&self) -> CompressedRistrettoPublic {
        self.get_ingest_summary()
            .get_ingress_pubkey()
            .try_into()
            .unwrap()
    }

    pub fn wait_for_ingest(&self, height: u64) {
        let timeout = Duration::from_secs(60);
        let start = Instant::now();
        loop {
            let summary = self.get_ingest_summary();
            let ingest_height = summary.next_block_index;
            if ingest_height >= height {
                break;
            }
            assert!(
                start.elapsed() <= timeout,
                "Timed out waiting for ingest node to process blocks; ingested {} blocks, target is {}",
                ingest_height,
                height,
            );
            sleep(Duration::from_millis(100));
        }
    }
}

// Impl Deref and DerefMut so that tests can call IngestServer methods.
impl Deref for TestIngestNode {
    type Target = IngestServer<AttestClient, SqlRecoveryDb>;
    fn deref(&self) -> &Self::Target {
        &self.server
    }
}
impl DerefMut for TestIngestNode {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.server
    }
}

/// Test helper encapsulating the shared state across ingest server invocations.
pub struct IngestServerTestHelper {
    pub base_port: u16,
    pub ledger: LedgerDB,
    pub ledger_db_path: PathBuf,
    pub watcher: WatcherDB,
    pub watcher_db_path: PathBuf,
    pub db_test_context: Arc<SqlRecoveryDbTestContext>,
    pub recovery_db: SqlRecoveryDb,
    pub rng: Hc128Rng,
    pub logger: Logger,
}

impl IngestServerTestHelper {
    /// Set up a new [LedgerDB], [WatcherDB], and [SqlRecoveryDbTestContext].
    pub fn new(base_port: u16, logger: Logger) -> Self {
        Self::from_existing(base_port, None, None, None, logger)
    }

    /// Set up with optional pre-existing  [LedgerDB], [WatcherDB], and
    /// [SqlRecoveryDbTestContext]. Pass [None] to instantiate each of those.
    pub fn from_existing(
        base_port: u16,
        ledger_db_path: impl Into<Option<PathBuf>>,
        watcher_db_path: impl Into<Option<PathBuf>>,
        db_test_context: impl Into<Option<Arc<SqlRecoveryDbTestContext>>>,
        logger: Logger,
    ) -> Self {
        let blockchain_path = TempDir::new("blockchain")
            .expect("Could not make tempdir for blockchain state")
            .into_path();

        let watcher_db_path = watcher_db_path.into().unwrap_or_else(|| {
            // Set up the Watcher db.
            let watcher_db_path = blockchain_path.join("watcher");
            std::fs::create_dir(&watcher_db_path).expect("failed to create watcher dir");
            WatcherDB::create(&watcher_db_path).expect("failed to create WarcherDB");
            watcher_db_path
        });

        // Set up an empty ledger db.
        let ledger_db_path = ledger_db_path.into().unwrap_or_else(|| {
            let ledger_db_path = blockchain_path.join("ledger_db");
            std::fs::create_dir(&ledger_db_path).expect("failed to create ledger dir");
            LedgerDB::create(&ledger_db_path).expect("failed to create LedgerDB");
            ledger_db_path
        });

        let db_test_context = db_test_context
            .into()
            .unwrap_or_else(|| Arc::new(SqlRecoveryDbTestContext::new(logger.clone())));
        let recovery_db = db_test_context.get_db_instance();

        let rng = Hc128Rng::from_seed([42u8; 32]);
        let ledger = LedgerDB::open(&ledger_db_path).unwrap();
        let tx_source_url = Url::from_str("https://localhost").unwrap();
        let watcher = WatcherDB::open_rw(&watcher_db_path, &[tx_source_url], logger.clone())
            .expect("Could not create watcher_db");
        IngestServerTestHelper {
            base_port,
            ledger,
            ledger_db_path,
            watcher,
            watcher_db_path,
            db_test_context,
            recovery_db,
            rng,
            logger,
        }
    }

    /// Add an origin block with 2 random outputs to the local [LedgerDB].
    pub fn add_origin_block(&mut self) {
        let outputs = vec![self.random_output(), self.random_output()];
        let origin_block = Block::new_origin_block(&outputs);
        let origin_contents = BlockContents {
            outputs,
            ..Default::default()
        };
        self.ledger
            .append_block(&origin_block, &origin_contents, None)
            .expect("failed writing initial block");
    }

    /// Helper to create and start several nodes.
    pub fn make_nodes(&self, n: u8) -> Vec<TestIngestNode> {
        let nodes = (0..n).map(|i| self.make_node(i, 0..n)).collect();
        // Give RPC etc. time to start
        sleep(Duration::from_millis(1000));
        nodes
    }

    /// Helper which makes i'th server and temp dir for its data.
    pub fn make_node(&self, idx: u8, peer_idxs: impl Iterator<Item = u8>) -> TestIngestNode {
        let state_file_path = TempDir::new("ingest_state")
            .expect("Could not make tempdir for ingest state")
            .into_path()
            .join(format!("mc-fog-ingest-state-{}", idx));
        self.make_node_with_state(idx, peer_idxs, state_file_path)
    }

    /// Set up a test server, reusing a [StateFile] at the given path.
    pub fn make_node_with_state(
        &self,
        idx: u8,
        peer_idxs: impl Iterator<Item = u8>,
        state_file_path: PathBuf,
    ) -> TestIngestNode {
        let logger = self.logger.new(o!("mc.node_id" => idx.to_string()));

        let (client_listen_uri, peer_listen_uri) = make_uris(self.base_port, idx);
        let local_node_id = peer_listen_uri
            .responder_id()
            .expect("Failed to get ResponderId from IngestPeerUri");

        let peers: BTreeSet<IngestPeerUri> = peer_idxs
            .map(|idx| make_uris(self.base_port, idx).1)
            .collect();

        let config = IngestServerConfig {
            ias_spid: Default::default(),
            local_node_id,
            peer_listen_uri: peer_listen_uri.clone(),
            peers,
            fog_report_id: Default::default(),
            client_listen_uri: client_listen_uri.clone(),
            max_transactions: 10_000,
            pubkey_expiry_window: 10,
            peer_checkup_period: Some(Duration::from_secs(5)),
            watcher_timeout: Duration::from_secs(5),
            state_file: Some(StateFile::new(state_file_path.clone())),
            enclave_path: get_enclave_path(mc_fog_ingest_enclave::ENCLAVE_FILE),
            omap_capacity: OMAP_CAPACITY,
        };

        let ra_client = AttestClient::new("").expect("Failed to create IAS client");

        let mut server = IngestServer::new(
            config,
            ra_client,
            self.recovery_db.clone(),
            self.watcher.clone(),
            self.ledger.clone(),
            logger,
        );
        server.start().expect("Failed to start IngestServer");
        assert!(
            !server.is_active(),
            "Newly created IngestServer should never be active"
        );

        TestIngestNode {
            server,
            state_file_path,
            client_listen_uri,
            peer_listen_uri,
        }
    }

    /// Generate a random [TxOut].
    pub fn random_output(&mut self) -> TxOut {
        random_output(&mut self.rng)
    }

    /// Add a randomly-generated block to our [LedgerDB].
    pub fn add_test_block(&mut self) {
        add_test_block(&mut self.ledger, &self.watcher, &mut self.rng);
    }

    /// Add N randomly-generated blocks to our [LedgerDB].
    pub fn add_test_blocks(&mut self, num_blocks: u16) {
        for _ in 0..num_blocks {
            self.add_test_block();
        }
    }

    /// Wait up to 60s for our [SqlRecoveryDb] to match [LedgerDB].
    #[track_caller]
    pub fn wait_till_recovery_db_in_sync(&self) {
        self.wait_till_recovery_db_in_sync_up_to(&Duration::from_secs(60));
    }

    /// Wait up to the given timeout for our [SqlRecoveryDb] to match
    /// [LedgerDB].
    #[track_caller]
    pub fn wait_till_recovery_db_in_sync_up_to(&self, timeout: &Duration) {
        self.wait_till_recovery_db_callback(
            || self.ledger.num_blocks().expect("ledger.num_blocks"),
            timeout,
        )
    }

    /// Wait up to the given timeout for our [SqlRecoveryDb]'s height to reach
    /// the value returned from the given callback, which is invoked on
    /// every iteration.
    #[track_caller]
    pub fn wait_till_recovery_db_callback<F: Fn() -> u64>(&self, callback: F, timeout: &Duration) {
        let start = Instant::now();
        loop {
            let recovery_db_count = self
                .recovery_db
                .get_highest_known_block_index()
                .expect("recovery_db.get_highest_known_block_index")
                .unwrap_or_default()
                + 1;
            let target = callback();
            log::trace!(
                self.logger,
                "Waiting for recovery_db block height ({}) to reach {}",
                recovery_db_count,
                target
            );
            if recovery_db_count >= target {
                break;
            }
            assert!(
                start.elapsed() <= *timeout,
                "Timed out waiting for active node to process data; recovery_db has {} blocks, target is {}",
                recovery_db_count,
                target,
            );
            sleep(Duration::from_millis(100));
        }
    }

    /// Query the recovery DB for the given key, and assert whether it is
    /// retired and/or lost.
    pub fn check_ingress_key(
        &self,
        query_key: &CompressedRistrettoPublic,
        retired: bool,
        lost: bool,
    ) {
        let ingress_key_public_status = self
            .recovery_db
            .get_ingress_key_status(query_key)
            .expect("failed to get ingress key status")
            .expect("failed to find ingress key");
        assert_eq!(ingress_key_public_status.retired, retired);
        assert_eq!(ingress_key_public_status.lost, lost);
    }
}

/// Get the ingress pubkeys for a collection of nodes.
pub fn get_ingress_keys(nodes: &[TestIngestNode]) -> Vec<CompressedRistrettoPublic> {
    nodes.iter().map(TestIngestNode::get_ingress_key).collect()
}

/// Add an arbitrary block to ledger and a timestamp for it
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

    let block_contents = BlockContents {
        key_images,
        outputs: vec![random_output(rng)],
        ..Default::default()
    };

    // Fake proofs
    let root_element = TxOutMembershipElement {
        range: Range::new(0, num_blocks as u64).unwrap(),
        hash: TxOutMembershipHash::from([0u8; 32]),
    };

    let block = Block::new_with_parent(
        BlockVersion::ZERO,
        &last_block,
        &root_element,
        &block_contents,
    );

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

/// Make a random output for a block
pub fn random_output<T: RngCore + CryptoRng>(rng: &mut T) -> TxOut {
    TxOut {
        masked_amount: MaskedAmount::default(),
        target_key: RistrettoPublic::from_random(rng).into(),
        public_key: RistrettoPublic::from_random(rng).into(),
        e_fog_hint: EncryptedFogHint::default(),
        e_memo: None,
    }
}
