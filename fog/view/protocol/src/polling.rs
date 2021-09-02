// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Abstraction of a rust interface to a fog view server
//!
//! This is "business logic" and we are attempting to abstract out any reference
//! to grpcio or similar.
//!
//! This is not actually intended to be exposed as part of libmobilecoin,
//! because it probably cannot be done synchronously, but it's useful for tests,
//! and it's useful as an example.
//!
//! If you can implement `request`, for *some* error type of your choosing,
//! (and see the fog_client crate for an example of that using grpcio),
//! this trait shows you how can actually use the fog view connection to get
//! TxOutputRecord's, in your paykit implementation.

use crate::{
    user_private::UserPrivate,
    user_rng_set::{TxOutRecoveryError, UserRngSet},
};
use alloc::vec::Vec;
use core::fmt::{Debug, Display};
use displaydoc::Display;
use mc_common::HashSet;
use mc_crypto_keys::KeyError;
use mc_fog_kex_rng::BufferedRng;
use mc_fog_types::{
    view::{QueryResponse, TxOutRecord},
    BlockCount,
};

use alloc::vec;

/// Rust interface to a Fog view server, used by SDK txo_finder and test code
pub trait FogViewConnection {
    type Error: Debug + Display + Send + Sync;

    /// Queries the view server for new events and rng search results.
    /// - start_from_user_event_id: Limit user events search to only event ids
    ///   higher than this
    /// - start_from_block_index: Limit ETxOutRecord search for only tx outs
    ///   that appeared in or
    /// after start_from_block_index
    /// - search_keys: ETxOutRecord search keys
    fn request(
        &mut self,
        start_from_user_event_id: i64,
        start_from_block_index: u64,
        search_keys: Vec<Vec<u8>>,
    ) -> Result<QueryResponse, Self::Error>;

    /// Take a view endpoint and use the above two functions to poll for updates
    /// Returns any new TxOuts
    /// Abstracts all the rngs etc.
    /// This is logic that is expected to be implemented on client-side in
    /// paykits but this at least serves as a reference implementation,
    /// abstracting out any use of grpcio.
    fn poll(
        &mut self,
        user_rng_set: &mut UserRngSet,
        upriv: &UserPrivate,
    ) -> (Vec<TxOutRecord>, Vec<TxOutPollingError<Self::Error>>) {
        // Buffer for errors encountered.
        // It's not considered acceptable that one error can cause the whole process
        // fail, instead we get as many hits as we can and return any new txs as
        // well as any errors.
        let mut errs = Vec::<TxOutPollingError<Self::Error>>::new();

        // Update seeds, get block count
        let mut new_highest_processed_block_count = {
            match self
                .request(
                    user_rng_set.get_next_start_from_user_event_id(),
                    user_rng_set.get_highest_processed_block_count().into(),
                    Default::default(),
                )
                .map_err(TxOutPollingError::Conn)
            {
                // If there's a connection error it's probably unrecoverable and we should not loop
                // There are retries in the FogClient class
                Err(err) => {
                    return (vec![], vec![err]);
                }
                Ok(result) => {
                    // TODO: Handle decommissioning of ingest invocations

                    for rng_record in result.rng_records.iter() {
                        if let Err(err) = user_rng_set.ingest_rng_record(upriv, rng_record) {
                            errs.push(TxOutPollingError::from(err));
                        }
                    }

                    user_rng_set
                        .set_next_start_from_user_event_id(result.next_start_from_user_event_id);

                    result.highest_processed_block_count
                }
            }
        };

        // Optimization: If the num_blocks of the view server hasn't changed, or is
        // older, since last time we talked to it, then we don't have any new
        // tx's.
        if user_rng_set.get_highest_processed_block_count()
            >= BlockCount::from(new_highest_processed_block_count)
        {
            return Default::default();
        }

        // Get new tx's
        let mut results = Vec::new();
        let mut request_multiplier = 2u64; // This value doubles each round
                                           // A dead rng is one where, we got back fewer Tx's
                                           // than we requested for it in the previous round.
        let mut dead_rng_set: HashSet<Vec<u8>> = Default::default();
        loop {
            // Escape if there are no more live rngs
            if dead_rng_set.len() >= user_rng_set.get_rngs().len() {
                break;
            }

            // Clone the rngs so that we can figure out which ones advanced
            let old_rngs = user_rng_set.get_rngs().clone();

            // Inspect our rngs to collect the search keys we request
            // From any non-dead rng, collect "request_multiplier" outputs, without
            // advancing the rng.
            let search_keys: Vec<Vec<u8>> = user_rng_set
                .get_rngs()
                .iter()
                .filter(|(nonce, _)| !dead_rng_set.contains(&nonce[..]))
                .flat_map(|(_, rng)| {
                    rng.clone()
                        .take(request_multiplier as usize)
                        .collect::<Vec<Vec<u8>>>()
                })
                .collect();

            // Make the request to the view node.
            let resp = match self.request(
                i64::MAX, // We don't care about any events, we just want to search for TXOs.
                user_rng_set.get_highest_processed_block_count().into(),
                search_keys,
            ) {
                Ok(resp) => resp,
                Err(err) => {
                    // If there's a connection error it's probly unrecoverable and we should not
                    // loop There are retries in the FogClient class
                    errs.push(TxOutPollingError::Conn(err));
                    return (results, errs);
                }
            };

            // The new num blocks value is the minimum of all the num_blocks values we got
            // back from the server in all queries we made to it. This is needed
            // so that we can guarantee that if we don't find a transaction for
            // some particular rng output, then it didn't land
            // before num_blocks.
            new_highest_processed_block_count = core::cmp::min(
                new_highest_processed_block_count,
                resp.highest_processed_block_count,
            );

            // Feed all the new TxOutSearchResult objects into the user_rng_set at once,
            // which is more efficient
            let (this_round_results, mut this_round_errs) =
                user_rng_set.ingest_tx_out_search_results(upriv, &resp.tx_out_search_results);
            results.extend(this_round_results);
            errs.extend(this_round_errs.drain(..).map(TxOutPollingError::from));

            // Calculate dead rngs
            // Compare current rngs vs. old_rngs, if we did not advance at least (exactly)
            // request_multiplier steps, then we are dead.
            dead_rng_set = user_rng_set
                .get_rngs()
                .iter()
                .filter(|(key, rng)| {
                    old_rngs
                        .get(&key[..])
                        .map(|old_rng| old_rng.index() + request_multiplier > rng.index())
                        .unwrap_or(true)
                })
                .map(|(key, _)| key.clone())
                .collect();

            // Ask for twice as many values from each rng next round, so that we only need
            // log n round trips.
            request_multiplier *= 2;

            // There is some grpc limit (Recieved message larger than max)
            if request_multiplier >= 1000 {
                request_multiplier = 1000;
            }
        }

        // Don't update the num_blocks value in reverse. If this time the servers
        // are behind where they were the last time we talked to them (due to load
        // balancer), that doesn't mean our previous balance computation was
        // wrong, it just means we didn't get any new useful information.
        if new_highest_processed_block_count
            > user_rng_set.get_highest_processed_block_count().into()
        {
            user_rng_set.set_highest_processed_block_count(new_highest_processed_block_count);
        }
        (results, errs)
    }
}

/// TxOutPollingError type
/// Generic over ConnError so that we don't depend on grpcio
#[derive(Debug, Display)]
pub enum TxOutPollingError<ConnError: Debug + Display> {
    /// Connection error: {0}
    Conn(ConnError),
    /// TxOutRecovery error: {0}
    TxOutRecovery(TxOutRecoveryError),
    /// Prost decode error: {0}
    ProstDecode(mc_util_serial::DecodeError),
    /// Key Error: {0}
    KeyError(KeyError),
}

impl<ConnError: Debug + Display> From<TxOutRecoveryError> for TxOutPollingError<ConnError> {
    fn from(src: TxOutRecoveryError) -> Self {
        Self::TxOutRecovery(src)
    }
}

impl<ConnError: Debug + Display> From<mc_util_serial::DecodeError>
    for TxOutPollingError<ConnError>
{
    fn from(src: mc_util_serial::DecodeError) -> Self {
        Self::ProstDecode(src)
    }
}

impl<ConnError: Debug + Display> From<KeyError> for TxOutPollingError<ConnError> {
    fn from(src: KeyError) -> Self {
        Self::KeyError(src)
    }
}
