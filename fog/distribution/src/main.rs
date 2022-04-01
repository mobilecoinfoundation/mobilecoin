// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Entry point for the fog distribution utility

//! Fog distribution is a transfer script which moves funds from a set of
//! accounts funded by a ledger bootstrap, to another set of accounts (which may
//! have fog).
//!
//! This is necessary because it is generally impossible to fund fog accounts
//! with bootstrap, because fog would have to exist and a public key be
//! available before the network has been stood up, or we cannot encrypt fog
//! hints.
//!
//! Fog distribution also has a secondary purpose of "slamming" the network with
//! as high of a volume of Tx's as possible. Fog distro fires and forgets its
//! Tx's rather than checking to see if they land, once it is in the slam step.
//!
//! Fog distro guarantees to pay each destination account at least once.

#![deny(missing_docs)]

use core::{cell::RefCell, cmp::max, convert::TryFrom};
use lazy_static::lazy_static;
use mc_account_keys::AccountKey;
use mc_attest_verifier::{Verifier, DEBUG_ENCLAVE};
use mc_common::{
    logger::{create_app_logger, log, o, Logger},
    HashMap, HashSet,
};
use mc_connection::{
    Error as ConnectionError, HardcodedCredentialsProvider, RetryError,
    RetryableBlockchainConnection, RetryableUserTxConnection, SyncConnection, ThickClient,
};
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPublic};
use mc_fog_distribution::Config;
use mc_fog_report_connection::{Error as ReportConnError, GrpcFogReportConnection};
use mc_fog_report_validation::FogResolver;
use mc_ledger_db::{Ledger, LedgerDB};
use mc_transaction_core::{
    get_tx_out_shared_secret,
    onetime_keys::recover_onetime_private_key,
    ring_signature::KeyImage,
    tokens::Mob,
    tx::{Tx, TxOut, TxOutMembershipProof},
    validation::TransactionValidationError,
    Amount, BlockVersion, Token,
};
use mc_transaction_std::{EmptyMemoBuilder, InputCredentials, TransactionBuilder};
use mc_util_cli::ParserWithBuildInfo;
use mc_util_uri::FogUri;
use rand::{seq::SliceRandom, thread_rng, Rng};
use rayon::prelude::*;
use retry::{delay, retry, OperationResult};
use std::{
    collections::BTreeMap,
    convert::TryInto,
    iter::empty,
    path::Path,
    str::FromStr,
    sync::{
        atomic::{AtomicU32, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};
use tempfile::tempdir;

thread_local! {
    /// global variable storing connections to the consensus network
    static CONNS: RefCell<Option<Vec<SyncConnection<ThickClient<HardcodedCredentialsProvider>>>>> = RefCell::new(None);
}

fn set_conns(config: &Config, logger: &Logger) {
    let conns = config.get_connections(logger).unwrap();
    CONNS.with(|c| c.replace(Some(conns)));
}

fn get_conns(
    config: &Config,
    logger: &Logger,
) -> Vec<SyncConnection<ThickClient<HardcodedCredentialsProvider>>> {
    let conns = CONNS.with(|c| c.borrow().clone());
    match conns {
        Some(c) => c,
        None => {
            set_conns(config, logger);
            CONNS.with(|c| c.borrow().clone()).unwrap()
        }
    }
}

lazy_static! {
    /// Keeps track of current block height of the block chain
    pub static ref BLOCK_HEIGHT: AtomicU64 = AtomicU64::default();

    /// Keeps track of block version we are targetting
    pub static ref BLOCK_VERSION: AtomicU32 = AtomicU32::new(1);

    /// Keeps track of the current MOB fee value
    pub static ref MOB_FEE: AtomicU64 = AtomicU64::default();

    /// A map of tx pub keys to account index. This is used in conjunction with ledger syncing to
    /// identify which new txs belong to which accounts without having to do any slow crypto.
    pub static ref TX_PUB_KEY_TO_ACCOUNT_KEY: Mutex<HashMap::<CompressedRistrettoPublic, AccountKey>> = Mutex::new(HashMap::default());
}

/// A TxOut found from the bootstrapped ledger that we can spend
#[derive(Clone, Debug, Eq, PartialEq)]
struct SpendableTxOut {
    pub tx_out: TxOut,
    /// The amount of the tx out
    pub amount: Amount,
    /// The account that owns this tx out
    pub from_account_key: AccountKey,
}

fn main() {
    mc_common::setup_panic_handler();
    let (logger, _global_logger_guard) = create_app_logger(o!());

    let config = Config::parse();

    // Read account root_entropies from disk
    let src_accounts: Vec<AccountKey> = mc_util_keyfile::keygen::read_default_root_entropies(
        config.sample_data_dir.join(Path::new("keys")),
    )
    .expect("Could not read default root entropies from keys")
    .iter()
    .map(AccountKey::from)
    .collect();

    let dest_accounts: Vec<AccountKey> = mc_util_keyfile::keygen::read_default_root_entropies(
        config
            .sample_data_dir
            .join(Path::new(&config.fog_keys_subdir)),
    )
    .expect("Could not read fog keys")
    .iter()
    .map(AccountKey::from)
    .collect();

    // Open the ledger_db to process the bootstrapped ledger
    log::info!(logger, "Loading ledger");

    let ledger_dir = tempdir().unwrap();
    std::fs::copy(
        config.sample_data_dir.join("ledger").join("data.mdb"),
        ledger_dir.path().join("data.mdb"),
    )
    .expect("failed copying ledger");

    let ledger_db = LedgerDB::open(ledger_dir.path()).expect("Could not open ledger_db");

    BLOCK_HEIGHT.store(ledger_db.num_blocks().unwrap(), Ordering::SeqCst);

    // Get the block info of all configured consensus nodes
    let block_infos: Vec<_> = get_conns(&config, &logger)
        .par_iter()
        .filter_map(|conn| conn.fetch_block_info(empty()).ok())
        .collect();

    MOB_FEE.store(
        block_infos
            .iter()
            .filter_map(|block_info| block_info.minimum_fee_or_none(&Mob::ID))
            .max()
            .unwrap_or(Mob::MINIMUM_FEE),
        Ordering::SeqCst,
    );
    BLOCK_VERSION.store(
        max(
            ledger_db.get_latest_block().unwrap().version,
            block_infos
                .iter()
                .map(|block_info| block_info.block_version)
                .max()
                .unwrap_or(0),
        ),
        Ordering::SeqCst,
    );

    // Load the bootstrapped transactions.
    let spendable_tx_outs = select_spendable_tx_outs(&ledger_db, &config, src_accounts, &logger);

    // Count how many of each token type
    {
        let mut token_count: BTreeMap<u32, usize> = Default::default();
        for tx_out in &spendable_tx_outs {
            *token_count.entry(*tx_out.amount.token_id).or_default() += 1;
        }

        log::info!(
            logger,
            "Loaded {} spendable tx outs",
            spendable_tx_outs.len()
        );
        for (token_id, count) in token_count {
            log::info!(logger, "TokenId({}): {} tx outs", token_id, count);
        }
    }

    // If we got this far and it's a dry-run, end successfully
    if config.dry_run {
        return;
    }

    // A channel to load with spendable tx outs, where worker threads will grab them
    // from.
    let (spendable_txouts_sender, spendable_txouts_receiver) =
        crossbeam_channel::unbounded::<SpendableTxOut>();

    let env = Arc::new(
        grpcio::EnvBuilder::new()
            .name_prefix("FogPubkeyResolver-RPC".to_string())
            .build(),
    );

    let fog_uri = FogUri::from_str(
        dest_accounts[0]
            .default_subaddress()
            .fog_report_url()
            .expect("No fog report url"),
    )
    .expect("Could not parse fog url");

    // A channel for worker threads to communicate when they have finished
    let (running_threads_sender, running_threads_receiver) =
        crossbeam_channel::unbounded::<usize>();

    let mut running_threads: usize = 0;

    // Seed each fog account with a TxOut. This ensures that integration tests
    // that check to make sure each fog account has a non-zero balance do not
    // fail.
    let mut seed_fog_resolver = build_fog_resolver(&fog_uri, &env, &logger);
    let conns = get_conns(&config, &logger);

    // Split tx outs into a group for the seed step and a group for the slam step
    let (seed_tx_outs, slam_tx_outs) = spendable_tx_outs
        .split_at(dest_accounts.len() * config.num_seed_transactions_per_destination_account);

    log::info!(
        logger,
        "Seeding Fog Accounts with {} initial TxOuts.",
        seed_tx_outs.len()
    );
    for (i, fog_account) in dest_accounts.iter().enumerate() {
        // We now send this account the next j seed tx outs, looping infinitely
        // until success
        for j in 0..config.num_seed_transactions_per_destination_account {
            let idx = i * config.num_seed_transactions_per_destination_account + j;
            seed_fog_resolver = build_and_submit_transaction(
                idx,
                // For this seed phase, only use one TxOut for each transaction.
                vec![seed_tx_outs[idx].clone()],
                fog_account,
                &config,
                &ledger_db,
                seed_fog_resolver,
                &logger,
                &conns,
                &env,
                &fog_uri,
            );
        }
        log::info!(
            logger,
            "Seeded {} / {} accounts successfully",
            i,
            dest_accounts.len()
        );
    }

    // Submit remaining tx outs to the crossbeam queue where the worker threads will
    // find them. Don't use spendable_txouts that were used in the seed step.
    for spendable_txout in slam_tx_outs {
        spendable_txouts_sender
            .send(spendable_txout.clone())
            .expect("failed sending to spendable_txouts_sender");
    }

    log::info!(logger, "Spawning workers for slam step");

    // Spawn worker threads
    for i in 0..config.max_threads {
        let spendable_txouts_receiver2 = spendable_txouts_receiver.clone();
        let running_threads_sender2 = running_threads_sender.clone();
        let config2 = config.clone();
        let ledger_db2 = ledger_db.clone();
        let dest_accounts2 = dest_accounts.clone();
        let logger2 = logger.new(o!("num" => i));
        let env2 = env.clone();
        let fog_resolver = build_fog_resolver(&fog_uri, &env2, &logger);

        thread::Builder::new()
            .name(format!("worker{}", i))
            .spawn(move || {
                worker_thread_entry(
                    spendable_txouts_receiver2,
                    running_threads_sender2,
                    config2,
                    ledger_db2,
                    dest_accounts2,
                    fog_resolver,
                    logger2,
                    env2,
                )
            })
            .expect("failed starting thread");

        running_threads += 1;
    }

    log::info!(logger, "Main thread entering infinite loop");
    while running_threads > 0 {
        let _thread_died = running_threads_receiver.recv().unwrap();
        running_threads -= 1;

        log::info!(logger, "A thread finished, {} remaining", running_threads);
    }

    log::info!(logger, "Done!");

    // Give logger time to flush.
    thread::sleep(Duration::from_secs(1));
}

/// Reads TxOut's from the ledger, adding them to a queue of spendable TxOuts:
/// * Confirms that they are owned by the expected owner
/// * Notes their amount and token id
///
/// This function assumes that:
/// * Bootstrap assigned a fixed number of outputs to consecutive accounts
///   (src_accounts)
/// * We either discover that number from the ledger, or take it as config
///
/// Returns all the tx outs we matched, their amounts, and the account that owns
/// them.
///
/// Arguments:
/// * ledger_db: The ledger db to read tx outs from
/// * config: configuration options:
///     * config.num_transactions_per_source_account: Override the automatic
///       detection of num_transactions_per_account in ledger
///     * config.num_tx_to_send: Caps the number of tx outs per account which
///       this slam will actually spend
///     * config.start_offset: Instructs to skip the first N transactions in
///       each block
/// * src_accounts: The source accounts which currently own the TxOut's in the
///   ledger db
fn select_spendable_tx_outs(
    ledger_db: &LedgerDB,
    config: &Config,
    src_accounts: Vec<AccountKey>,
    logger: &Logger,
) -> Vec<SpendableTxOut> {
    log::info!(logger, "Processing transactions");
    let mut num_transactions_per_account = config.num_transactions_per_source_account;

    let mut spendable_tx_outs: Vec<SpendableTxOut> = Vec::new();

    let mut block_count = 0;
    while let Ok(block_contents) = ledger_db.get_block_contents(block_count) {
        let transactions = block_contents.outputs;
        // If num_transactions_per_source_account is zero, then automatically detect
        // the number of transactions.
        // Only get num_transactions per account for the first block, then assume
        // future blocks that were bootstrapped are similar.
        if num_transactions_per_account == 0 {
            num_transactions_per_account =
                get_num_transactions_per_account(&src_accounts[0], &transactions, logger);
        }
        log::info!(
            logger,
            "Loaded {:?} transactions from block {:?}",
            transactions.len(),
            block_count
        );

        // NOTE: This will start at the same offset per block - we may want just the
        // first offset

        // The index of the account we expect to own the next Tx
        let mut account_index = 0;
        let mut account = &src_accounts[account_index];
        // The number of tx's we have processed for this account
        let mut num_processed_this_account = 0;
        for (index, tx_out) in transactions.iter().enumerate().skip(config.start_offset) {
            // If we have already seen num_transactions_per_account on this account, then we
            // have to increment account index
            if num_processed_this_account >= num_transactions_per_account {
                log::trace!(
                    logger,
                    "Moving on to next account {:?} at tx index {:?}",
                    account_index + 1,
                    index
                );
                account_index += 1;
                if account_index >= src_accounts.len() {
                    log::info!(logger, "Finished processing accounts. If no transactions sent, you may need to re-bootstrap.");
                    break;
                }
                account = &src_accounts[account_index];
                num_processed_this_account = 0;
            }

            // Num tx_to_send is a cap on how many Tx's of this accounts that we actually
            // spend If it is -1 then there is no cap.
            if config.num_tx_to_send == -1
                || num_processed_this_account < config.num_tx_to_send.try_into().unwrap()
            {
                let public_key = RistrettoPublic::try_from(&tx_out.public_key).unwrap();
                let shared_secret =
                    get_tx_out_shared_secret(account.view_private_key(), &public_key);

                let (amount, _blinding_factor) = tx_out
                    .masked_amount
                    .get_value(&shared_secret)
                    .unwrap_or_else(|err| {
                        panic!(
                        "TX ownership is not as expected: tx #{} not owned by account_index {}: {}",
                        index, account_index, err
                    )
                    });

                log::trace!(
                    logger,
                    "(account = {:?}) and (tx_index {:?}) = {:?}",
                    account_index,
                    index,
                    amount,
                );

                // Push to queue
                spendable_tx_outs.push(SpendableTxOut {
                    tx_out: tx_out.clone(),
                    amount,
                    from_account_key: account.clone(),
                });
            }
            num_processed_this_account += 1;
        }
        block_count += 1;
    }

    spendable_tx_outs
}

/// Make a request to fog report server, return fog resolver object
fn build_fog_resolver(
    fog_uri: &FogUri,
    env: &Arc<grpcio::Environment>,
    logger: &Logger,
) -> FogResolver {
    // Ensure there are fog reports available
    // XXX: This retry should possibly be in the GrpcFogPubkeyResolver object itself
    // instead 15'th fibonacci is 987, so the last delay should be ~100
    // seconds
    let conn = GrpcFogReportConnection::new(env.clone(), logger.clone());
    let responses = retry(
        delay::Fibonacci::from_millis(100)
            .map(delay::jitter)
            .take(15),
        || match conn.fetch_fog_reports(core::slice::from_ref(fog_uri).iter().cloned()) {
            Ok(responses) => OperationResult::Ok(responses),
            Err(ReportConnError::Rpc(err)) => {
                log::error!(
                    logger,
                    "grpc error reaching fog report server, retrying: {}",
                    err
                );
                OperationResult::Retry(ReportConnError::Rpc(err))
            }
            Err(ReportConnError::NoReports(_)) => {
                log::error!(logger, "no fog reports available, retrying");
                OperationResult::Retry(ReportConnError::NoReports(fog_uri.clone()))
            }
        },
    )
    .expect("Could not contact fog report server");

    let report_verifier = {
        let mr_signer_verifier = mc_fog_ingest_enclave_measurement::get_mr_signer_verifier(None);
        let mut verifier = Verifier::default();
        verifier.debug(DEBUG_ENCLAVE).mr_signer(mr_signer_verifier);
        verifier
    };

    FogResolver::new(responses, &report_verifier).expect("Could not get FogResolver")
}

/// Entry point for a worker thread which tries to pull spendable tx outs rom
/// queue and then build and submit transactions from them.
fn worker_thread_entry(
    spendable_txouts_receiver: crossbeam_channel::Receiver<SpendableTxOut>,
    running_threads_sender: crossbeam_channel::Sender<usize>,
    config: Config,
    ledger_db: LedgerDB,
    dest_accounts: Vec<AccountKey>,
    mut fog_resolver: FogResolver,
    logger: Logger,
    env: Arc<grpcio::Environment>,
) {
    log::info!(logger, "Worker started.");
    let mut txs_created: usize = 0;

    let mut conns = get_conns(&config, &logger);
    conns.shuffle(&mut thread_rng());

    loop {
        let mut pending_spendable_txouts = Vec::<SpendableTxOut>::new();
        while pending_spendable_txouts.len() < config.num_inputs {
            log::trace!(
                logger,
                "Waiting for {} more inputs",
                config.num_inputs - pending_spendable_txouts.len()
            );

            match spendable_txouts_receiver.try_recv() {
                Ok(tx_out) => pending_spendable_txouts.push(tx_out),
                Err(_) => {
                    log::debug!(logger, "No more inputs kill thread");

                    running_threads_sender.send(1).unwrap();
                    return;
                }
            }
        }

        // Send to the next fog account
        let to_account = &dest_accounts[txs_created % dest_accounts.len()];
        let fog_uri = FogUri::from_str(
            dest_accounts[0]
                .default_subaddress()
                .fog_report_url()
                .expect("No fog report url"),
        )
        .expect("Could not parse fog url");

        fog_resolver = build_and_submit_transaction(
            txs_created,
            pending_spendable_txouts,
            to_account,
            &config,
            &ledger_db,
            fog_resolver,
            &logger,
            &conns,
            &env,
            &fog_uri,
        );
        txs_created += 1;
    }
}

/// Builds and submits a transaction to a given FogAccount.
/// This retries infinitely until the tx succeeds, possibly rebuilding it.
///
/// If a transaction submit errors, then we get and use a new FogResolver
/// to build and submit transactions. In this case, we return this new
/// FogResolver to the caller so that it can be used in subsequent transactions.
/// If a transaction error doesn't occur, we return the old FogResolver.
fn build_and_submit_transaction(
    txs_created: usize,
    pending_spendable_txouts: Vec<SpendableTxOut>,
    to_account: &AccountKey,
    config: &Config,
    ledger_db: &LedgerDB,
    fog_resolver: FogResolver,
    logger: &Logger,
    conns: &[SyncConnection<ThickClient<HardcodedCredentialsProvider>>],
    env: &Arc<grpcio::Environment>,
    fog_uri: &FogUri,
) -> FogResolver {
    // Sometimes transactions can not be submitted before the tombstone block
    // has passed, so loop until transactions can be submmitted
    let mut current_fog_resolver = fog_resolver;
    loop {
        let tx = build_tx(
            &pending_spendable_txouts,
            to_account,
            config,
            ledger_db,
            current_fog_resolver.clone(),
            logger,
        );

        if submit_tx(txs_created, conns, &tx, config, logger) {
            let mut map = TX_PUB_KEY_TO_ACCOUNT_KEY.lock().unwrap();
            map.insert(tx.prefix.outputs[0].public_key, to_account.clone());
            return current_fog_resolver;
        } else {
            // If submit fails, trash and rebuild the FogResolver to ensure it's
            // building and submitting against a fresh Fog.
            current_fog_resolver = build_fog_resolver(fog_uri, env, logger);
            log::trace!(
                logger,
                "Rebuilding failed tx. Got new FogResolver: {:?}",
                current_fog_resolver
            );
        }
    }
}

/// Submit a built tx to any of the possible connections, with retries.
/// Returns true on success and false on failure
fn submit_tx(
    counter: usize,
    conns: &[SyncConnection<ThickClient<HardcodedCredentialsProvider>>],
    tx: &Tx,
    config: &Config,
    logger: &Logger,
) -> bool {
    let max_retries = 30;
    let retry_sleep_duration = Duration::from_millis(1000);

    for i in 0..max_retries {
        // Submit to a node in round robin fashion, starting with a random node
        let node_index = (i + counter) % conns.len();
        let conn = &conns[node_index];
        log::info!(
            logger,
            "Submitting transaction {} to node {} (attempt {} / {})",
            counter,
            conn,
            i,
            max_retries
        );
        thread::sleep(Duration::from_millis(config.add_tx_delay_ms));
        match conn.propose_tx(tx, empty()) {
            Ok(block_height) => {
                log::debug!(
                    logger,
                    "Successfully submitted {:?}, at block height {:?} (attempt {} / {})",
                    counter,
                    block_height,
                    i,
                    max_retries
                );

                BLOCK_HEIGHT.fetch_max(block_height, Ordering::SeqCst);
                return true;
            }
            Err(RetryError::Operation {
                error,
                total_delay,
                tries,
            }) => {
                if let ConnectionError::TransactionValidation(
                    TransactionValidationError::TombstoneBlockExceeded,
                ) = error
                {
                    log::debug!(
                            logger,
                            "Transaction {:?} could not be submitted before tombstone block passed, giving up", counter);
                    return false;
                }
                if let ConnectionError::TransactionValidation(
                    TransactionValidationError::ContainsSpentKeyImage,
                ) = error
                {
                    log::info!(
                        logger,
                        "Transaction {:?} contains a spent key image. Moving to next transaction",
                        counter
                    );
                    return true;
                }

                log::warn!(
                    logger,
                    "Failed to submit transaction {:?} to node {} (attempt {} / {}): {}. Total Delay: {:?}. Retry Crate 'tries': {}.",
                    counter,
                    conn,
                    i,
                    max_retries,
                    error,
                    total_delay,
                    tries
                );
                thread::sleep(retry_sleep_duration);
            }
            Err(RetryError::Internal(_s)) => {
                // Retry crate never actually returns Internal on any code path
                unreachable!()
            }
        }
    }
    log::error!(
        logger,
        "Failed to submit tx {:?} and max retries exceeded: {:?}",
        counter,
        max_retries
    );
    false
}

/// Build a tx using one or more spendable tx outs, to a particualr account.
fn build_tx(
    spendable_txouts: &[SpendableTxOut],
    to_account: &AccountKey,
    config: &Config,
    ledger_db: &LedgerDB,
    fog_resolver: FogResolver,
    logger: &Logger,
) -> Tx {
    let utxos_with_proofs = get_membership_proofs(ledger_db, spendable_txouts);
    let rings = get_rings(ledger_db, config.ring_size, utxos_with_proofs.len());

    let mut rng = rand::thread_rng();

    // Sanity
    assert_eq!(utxos_with_proofs.len(), rings.len());

    // This max occurs because the bootstrapped ledger has block version 0,
    // but non-bootstrap blocks always have block version >= 1
    let block_version = BlockVersion::try_from(BLOCK_VERSION.load(Ordering::SeqCst))
        .expect("Unsupported block version");

    // Use token id for first spendable tx out
    let token_id = spendable_txouts.first().unwrap().amount.token_id;

    // Create tx_builder.
    let mut tx_builder = TransactionBuilder::new(
        block_version,
        token_id,
        fog_resolver,
        EmptyMemoBuilder::default(),
    );

    // FIXME: This needs to be the fee for the current token, not MOB.
    // However, bootstrapping non MOB tokens is not supported right now.
    tx_builder.set_fee(MOB_FEE.load(Ordering::SeqCst)).unwrap();

    // Unzip each vec of tuples into a tuple of vecs.
    let mut rings_and_proofs: Vec<(Vec<TxOut>, Vec<TxOutMembershipProof>)> = rings
        .into_iter()
        .map(|tuples| tuples.into_iter().unzip())
        .collect();

    // Add inputs to the tx.
    for (utxo, proof) in utxos_with_proofs.clone() {
        let (mut ring, mut membership_proofs) = rings_and_proofs.pop().unwrap();
        assert_eq!(
            ring.len(),
            membership_proofs.len(),
            "Each ring element must have a corresponding membership proof."
        );

        // Add the input to the ring.
        let position_opt = ring.iter().position(|tx_out| *tx_out == utxo.tx_out);
        let real_key_index = match position_opt {
            Some(position) => {
                // The input is already present in the ring.
                // This could happen if ring elements are sampled randomly from the ledger.
                position
            }
            None => {
                // The input is not already in the ring.
                if ring.is_empty() {
                    // Append the input and its proof of membership.
                    ring.push(utxo.tx_out.clone());
                    membership_proofs.push(proof.clone());
                } else {
                    // Replace the first element of the ring.
                    ring[0] = utxo.tx_out.clone();
                    membership_proofs[0] = proof.clone();
                }
                // The real input is always the first element. This is safe because
                // TransactionBuilder sorts each ring.
                0
            }
        };

        assert_eq!(
            ring.len(),
            membership_proofs.len(),
            "Each ring element must have a corresponding membership proof."
        );

        let public_key = RistrettoPublic::try_from(&utxo.tx_out.public_key).unwrap();
        let onetime_private_key = recover_onetime_private_key(
            &public_key,
            utxo.from_account_key.view_private_key(),
            &utxo.from_account_key.default_subaddress_spend_private(),
        );

        let key_image = KeyImage::from(&onetime_private_key);
        log::trace!(
            logger,
            "Adding input: ring {:?}, utxo index {:?}, key image {:?}, pubkey {:?}",
            ring,
            real_key_index,
            key_image,
            public_key
        );

        tx_builder.add_input(
            InputCredentials::new(
                ring,
                membership_proofs,
                real_key_index,
                onetime_private_key,
                *utxo.from_account_key.view_private_key(),
            )
            .expect("add_input failed"),
        );
    }

    // Add ouputs
    for (i, (utxo, _proof)) in utxos_with_proofs.iter().enumerate() {
        if utxo.amount.token_id == token_id {
            let mut value = utxo.amount.value;
            // Use the first input to pay for the fee.
            if i == 0 {
                value -= MOB_FEE.load(Ordering::SeqCst);
            }

            let target_address = to_account.default_subaddress();

            tx_builder
                .add_output(value, &target_address, &mut rng)
                .expect("failed to add output");
        }
    }

    // Set tombstone block.
    let tombstone_block = BLOCK_HEIGHT.load(Ordering::SeqCst) + config.tombstone_block;
    tx_builder.set_tombstone_block(tombstone_block);

    // Build and return tx.
    tx_builder.build(&mut rng).expect("failed building tx")
}

/// Get merkle proofs of membership from the ledger for several utxos
fn get_membership_proofs(
    ledger_db: &LedgerDB,
    utxos: &[SpendableTxOut],
) -> Vec<(SpendableTxOut, TxOutMembershipProof)> {
    let indexes: Vec<u64> = utxos
        .iter()
        .map(|utxo| {
            ledger_db
                .get_tx_out_index_by_hash(&utxo.tx_out.hash())
                .unwrap()
        })
        .collect();
    let proofs = ledger_db.get_tx_out_proof_of_memberships(&indexes).unwrap();

    utxos.iter().cloned().zip(proofs.into_iter()).collect()
}

/// Get ring mixins for a transaction from the ledger
fn get_rings(
    ledger_db: &LedgerDB,
    ring_size: usize,
    num_rings: usize,
) -> Vec<Vec<(TxOut, TxOutMembershipProof)>> {
    let num_requested = ring_size * num_rings;
    let num_txos = ledger_db.num_txos().unwrap();

    // Randomly sample `num_requested` TxOuts, without replacement and convert into
    // a Vec<u64>
    let mut rng = rand::thread_rng();
    let mut sampled_indices: HashSet<u64> = HashSet::default();
    while sampled_indices.len() < num_requested {
        let index = rng.gen_range(0..num_txos);
        sampled_indices.insert(index);
    }
    let sampled_indices_vec: Vec<u64> = sampled_indices.into_iter().collect();

    // Get proofs for all of those indexes.
    let proofs = ledger_db
        .get_tx_out_proof_of_memberships(&sampled_indices_vec)
        .unwrap();

    // Create an iterator that returns (index, proof) elements.
    let mut indexes_and_proofs_iterator = sampled_indices_vec.into_iter().zip(proofs.into_iter());

    // Convert that into a Vec<Vec<TxOut, TxOutMembershipProof>>
    let mut rings_with_proofs = Vec::new();

    for _ in 0..num_rings {
        let mut ring = Vec::new();
        for _ in 0..ring_size {
            let (index, proof) = indexes_and_proofs_iterator.next().unwrap();
            let tx_out = ledger_db.get_tx_out_by_index(index).unwrap();

            ring.push((tx_out, proof));
        }
        rings_with_proofs.push(ring);
    }

    rings_with_proofs
}

/// Count how many consecutive TxOut's in a range are owned by a given account
fn get_num_transactions_per_account(
    account: &AccountKey,
    transactions: &[TxOut],
    logger: &Logger,
) -> usize {
    for (i, tx_out) in transactions.iter().enumerate() {
        // Make sure the view_key matches for this output that we are about to send
        // Assume accounts are numbered in order that they were processed by bootstrap
        if tx_out.view_key_match(account.view_private_key()).is_err() {
            log::trace!(
                logger,
                "Transaction {:?} does not belong to account. Total txs per account = {:?}",
                i,
                i,
            );
            return i;
        }
    }
    0
}
