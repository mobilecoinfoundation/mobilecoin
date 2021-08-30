// Copyright (c) 2018-2021 The MobileCoin Foundation

use crate::user_private::UserPrivate;
use alloc::vec::Vec;
use core::convert::TryFrom;
use displaydoc::Display;
use mc_common::HashMap;
use mc_crypto_box::Error as CryptoBoxError;
use mc_crypto_keys::KeyError;
use mc_fog_kex_rng::{BufferedRng, Error as KexRngError, NewFromKex, VersionedKexRng};
use mc_fog_types::{
    view::{RngRecord, TxOutRecord, TxOutSearchResult, TxOutSearchResultCode},
    BlockCount,
};
use mc_util_serial::DecodeError;

/// A set of kex_rngs. Together with a view node endpoint, this can be used to
/// find the user's transactions.
#[derive(Clone, Default)]
pub struct UserRngSet {
    /// nonce -> rngs
    rngs: HashMap<Vec<u8>, VersionedKexRng>,

    /// Last highest_processed_block_count reported by the server
    highest_processed_block_count: u64,

    /// Last next_start_from_user_event_id reported by the server
    next_start_from_user_event_id: i64,
}

impl UserRngSet {
    pub fn new() -> Self {
        Self {
            rngs: HashMap::default(),
            highest_processed_block_count: 0,
            next_start_from_user_event_id: 0,
        }
    }

    pub fn get_rngs(&self) -> &HashMap<Vec<u8>, VersionedKexRng> {
        &self.rngs
    }

    pub fn get_highest_processed_block_count(&self) -> BlockCount {
        BlockCount::from(self.highest_processed_block_count)
    }

    pub fn set_highest_processed_block_count(&mut self, val: u64) {
        self.highest_processed_block_count = val;
    }

    pub fn get_next_start_from_user_event_id(&self) -> i64 {
        self.next_start_from_user_event_id
    }

    pub fn set_next_start_from_user_event_id(&mut self, val: i64) {
        self.next_start_from_user_event_id = val;
    }

    // Take a nonce and initialize a new rng from it if there isn't one
    // already
    // TODO: Also update the start_block and end_block values
    pub fn ingest_rng_record(
        &mut self,
        upriv: &UserPrivate,
        rec: &RngRecord,
    ) -> Result<(), TxOutRecoveryError> {
        let rng = VersionedKexRng::try_from_kex_pubkey(&rec.pubkey, upriv.get_view_key())?;
        self.rngs
            .entry(rec.pubkey.public_key.clone())
            .or_insert(rng);
        Ok(())
    }

    // Take a collection of TxOutSearchResult's and match them up with rngs,
    // matching as much as possible before stopping
    pub fn ingest_tx_out_search_results(
        &mut self,
        upriv: &UserPrivate,
        results: &[TxOutSearchResult],
    ) -> (Vec<TxOutRecord>, Vec<TxOutRecoveryError>) {
        let mut successes = Vec::<TxOutRecord>::new();
        let mut failures = Vec::<TxOutRecoveryError>::new();

        // Maps search keys to the associated payloads (ciphertexts)
        let mut tx_result_map = HashMap::<Vec<u8>, Vec<u8>>::default();

        // Build tx_result_map from the results list,
        // We drop anything that didn't have TxResultCode::Found
        for result in results.iter() {
            if let Ok(code) = TxOutSearchResultCode::try_from(result.result_code) {
                if code == TxOutSearchResultCode::Found {
                    // TODO: Log any collision when inserting?
                    tx_result_map.insert(result.search_key.clone(), result.ciphertext.clone());
                } else if code != TxOutSearchResultCode::NotFound {
                    failures.push(TxOutRecoveryError::TxOutSearchFailure(
                        code,
                        result.search_key.clone(),
                    ));
                }
            } else {
                failures.push(TxOutRecoveryError::UnexpectedTxOutSearchResultCode(
                    result.result_code,
                    result.search_key.clone(),
                ));
            }
        }

        // Iterate over rngs, searching for its current state and advancing it
        for (_, ref mut rng) in self.rngs.iter_mut() {
            while let Some(ciphertext) = tx_result_map.remove(rng.peek()) {
                match upriv.decrypt_tx_out_result(ciphertext) {
                    Ok(txo) => successes.push(txo),
                    Err(err) => failures.push(err),
                };
                rng.advance();
            }
        }

        // The old maids all becomes failures
        for (search_key, _) in tx_result_map.into_iter() {
            failures.push(TxOutRecoveryError::SearchKeyNotFound(search_key))
        }

        (successes, failures)
    }
}

// Error type for a user rng set

#[derive(Debug, Display)]
pub enum TxOutRecoveryError {
    /// Deserialization of recovery response failed
    ProstDeserializationFailed,
    /// Could not deserialize TxOutRecord
    TxOutRecordDeserializationFailed,
    /// Could not decrypt tx out record: {0}
    DecryptionFailed(CryptoBoxError),
    /// Could not decrypt tx out record: Mac check failed
    MacCheckFailed,
    /// Invalid nonce
    InvalidNonce,
    /// Key error: {0}
    InvalidKey(KeyError),
    /// Fog returned an error when searching for tx: {0}, search_key = {1:?}
    TxOutSearchFailure(TxOutSearchResultCode, Vec<u8>),
    /**
     * Fog returned an unexpected TxOutSearchResultCode value: {0},
     * search_key  = {1:?}
     */
    UnexpectedTxOutSearchResultCode(u32, Vec<u8>),
    /// Search key was not found amongst our rngs: {0:?}
    SearchKeyNotFound(Vec<u8>),
    /// Error initializing KexRng: {0}
    KexRng(KexRngError),
}

impl From<KeyError> for TxOutRecoveryError {
    fn from(src: KeyError) -> Self {
        Self::InvalidKey(src)
    }
}

impl From<KexRngError> for TxOutRecoveryError {
    fn from(err: KexRngError) -> Self {
        Self::KexRng(err)
    }
}

impl From<DecodeError> for TxOutRecoveryError {
    fn from(_: DecodeError) -> Self {
        Self::ProstDeserializationFailed
    }
}

#[derive(Debug)]
pub enum RngSetError {
    Decode(DecodeError),
    KexRng(KexRngError),
}

impl From<DecodeError> for RngSetError {
    fn from(err: DecodeError) -> Self {
        Self::Decode(err)
    }
}

impl From<KexRngError> for RngSetError {
    fn from(err: KexRngError) -> Self {
        Self::KexRng(err)
    }
}
