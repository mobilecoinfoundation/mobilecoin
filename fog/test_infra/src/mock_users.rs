// Copyright (c) 2018-2021 The MobileCoin Foundation

//! A mock collection of users that can send a stream of transactions to ingest
//! node, and then exercise the view node to try to find them.
//! This is basically mocking both the consensus output and the SDK

use mc_common::logger::global_log;
use mc_crypto_keys::RistrettoPublic;
use mc_fog_types::{
    view::{FogTxOut, FogTxOutMetadata, TxOutRecord},
    BlockCount,
};
use mc_fog_view_protocol::{FogViewConnection, UserPrivate, UserRngSet};
use mc_transaction_core::{fog_hint::FogHint, tx::TxOut, Amount};
use mc_util_from_random::FromRandom;
use rand_core::{CryptoRng, RngCore};
use std::collections::{HashMap, HashSet};

/// Constructs for the test

/// Data that we are tracking of the user during the test
/// This is essentially mocking the SDK
#[derive(Default)]
pub struct UserData {
    rngs: UserRngSet,      // rngs
    txs: Vec<TxOutRecord>, // recieved TXOs
}

impl UserData {
    pub fn get_txos(&self) -> &[TxOutRecord] {
        &self.txs
    }
}

/// User Pool tracks a bunch of user's state
/// It makes up random transactions and feeds them to ingest, then all the users
/// query the view node and check that the expected thing happened.
pub struct UserPool {
    users: Vec<(UserPrivate, UserData)>,
}

// A test-block is a list of random TxOuts indexed by recipient.
type TestBlock = HashMap<UserPrivate, Vec<TxOut>>;

// A 'checkpoint' in the state is a count of transactions recieved by users
type Checkpoint = HashMap<UserPrivate, usize>;

// A 'delta' of the state is a list of new transactions recieved by users, since
// a checkpoint was taken. The test is based on, take a checkpoint, make random
// transactions, submit a block to ingest, poll the view node, and then measure
// delta against the checkpoint. If the generated transactions match the delta,
// we accept. If not we retry a few times, and then eventually fail.
type Delta = HashMap<UserPrivate, HashSet<TxOutRecord>>;

// Take a test block, order the TxOuts arbitrarily, compute their global tx out
// indices, and finally compute what we expect the users to see on the other
// end.
//
pub fn test_block_to_inputs_and_expected_outputs(
    block_index: u64,
    mut global_tx_out_index: usize,
    test_block: &TestBlock,
    timestamp: u64,
) -> (Vec<TxOut>, Delta) {
    let pairs = test_block_to_pairs(test_block);
    // TODO(Chris): It would be nice to take an RNG and shuffle pairs right here for
    // better coverage

    let result_block: Vec<TxOut> = pairs.iter().map(|(_key, val)| val.clone()).collect();

    let mut result_delta: Delta = Default::default();

    for (ref upriv, ref txo) in pairs.iter() {
        let user_result_set = result_delta
            .entry(upriv.clone())
            .or_insert_with(HashSet::default);

        let fog_tx_out = FogTxOut::from(txo);
        let meta = FogTxOutMetadata {
            global_index: global_tx_out_index as u64,
            block_index,
            timestamp,
        };
        let tx_out_record = TxOutRecord::new(fog_tx_out, meta);

        user_result_set.insert(tx_out_record);
        global_tx_out_index += 1;
    }

    (result_block, result_delta)
}

// Turn a test block into a list of UserPrivate, TxOut pairs
pub fn test_block_to_pairs(test_block: &TestBlock) -> Vec<(UserPrivate, TxOut)> {
    let mut result = Vec::new();

    for (upriv, ref redacted_transactions) in test_block.iter() {
        for rtx in redacted_transactions.iter() {
            result.push((upriv.clone(), rtx.clone()));
        }
    }
    result
}

/// Make a random transaction targeted at a specific user via fog
pub fn make_random_tx<T: RngCore + CryptoRng>(
    rng: &mut T,
    acct_server_pubkey: &RistrettoPublic,
    recipient: &FogHint,
) -> TxOut {
    let target_key = RistrettoPublic::from_random(rng);
    let public_key = RistrettoPublic::from_random(rng);
    TxOut {
        amount: Amount::new(1, &public_key).expect("amount failed unexpectedly"),
        target_key: target_key.into(),
        public_key: public_key.into(),
        e_fog_hint: recipient.encrypt(acct_server_pubkey, rng),
        e_memo: None,
    }
}

impl UserPool {
    // Make a new user pool with a given number of users
    pub fn new<T: RngCore + CryptoRng>(num_users: usize, rng: &mut T) -> Self {
        Self {
            users: (0..num_users)
                .map(|_| (UserPrivate::random(rng), Default::default()))
                .collect(),
        }
    }

    // get all the pubkeys for the users
    pub fn get_pubkeys(&self) -> Vec<RistrettoPublic> {
        self.users
            .iter()
            .map(|(user, _)| user.get_view_pubkey())
            .collect()
    }

    // Trash all user tx's and rng states
    pub fn trash_user_phones(&mut self) {
        for pair in self.users.iter_mut() {
            pair.1 = Default::default()
        }
    }

    // Get a checkpoint
    pub fn get_checkpoint(&self) -> Checkpoint {
        self.users
            .iter()
            .map(|(upriv, data)| (upriv.clone(), data.get_txos().len()))
            .collect()
    }

    // Get a checkpoint "at time zero" i.e. every user has zero tx's
    pub fn get_zero_checkpoint(&self) -> Checkpoint {
        self.users
            .iter()
            .map(|(upriv, _data)| (upriv.clone(), 0))
            .collect()
    }

    // Compute a delta of current state against a checkpoint
    pub fn compute_delta(&self, checkpoint: &Checkpoint) -> Delta {
        self.users
            .iter()
            .filter_map(|(upriv, data)| {
                let prev_count = *checkpoint.get(&upriv).unwrap_or(&0);
                let user_txos = data.get_txos();
                // If there are new txos associated to this user, report them,
                // otherwise None which strips this user from the delta
                if prev_count < user_txos.len() {
                    Some((
                        upriv.clone(),
                        user_txos[prev_count..].iter().cloned().collect(),
                    ))
                } else {
                    None
                }
            })
            .collect()
    }

    // Make a random test block, to be submitted as a block to ingest
    pub fn random_test_block<T: RngCore + CryptoRng>(
        &self,
        tx_count: usize,
        acct_server_pubkey: &RistrettoPublic,
        rng: &mut T,
    ) -> TestBlock {
        let mut result: TestBlock = HashMap::default();
        for _ in 0..tx_count {
            let user_idx = (rng.next_u64() % self.users.len() as u64) as usize;
            let user_id = &self.users[user_idx].0;
            result
                .entry(user_id.clone())
                .or_insert_with(Vec::new)
                .push(make_random_tx(rng, acct_server_pubkey, &user_id.get_hint()));
        }
        result
    }

    // Make each of the users poll consecutively, and add any Txos that they find
    // to their little cache.
    // Return the final num blocks values for each user
    pub fn poll<C: FogViewConnection>(&mut self, view_node: &mut C) -> Vec<BlockCount> {
        let mut final_num_blocks_values = Vec::<BlockCount>::default();
        for (ref upriv, ref mut udata) in self.users.iter_mut() {
            let initial_num_blocks = udata.rngs.get_highest_processed_block_count();

            let (mut txos, errors) = view_node.poll(&mut udata.rngs, upriv);
            if !errors.is_empty() {
                global_log::error!("Unexpected errors when polling account server");
                for err in errors {
                    global_log::error!("{:?}", err);
                }
                panic!("Unexpected errors are fatal!");
            }

            for txo in &txos {
                if txo.block_index < u64::from(initial_num_blocks) {
                    panic!("Polling fog view yielded txo records which were before the num_blocks value! This can lead to incorrect balance calculations");
                }
            }

            udata.txs.append(&mut txos);

            final_num_blocks_values.push(udata.rngs.get_highest_processed_block_count());
        }

        final_num_blocks_values
    }
}
