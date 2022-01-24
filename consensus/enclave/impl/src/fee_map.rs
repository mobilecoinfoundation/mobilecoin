// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A helper object for maintaining a map of token id -> minimum fee.

use alloc::{collections::BTreeMap, string::String};
use mc_crypto_digestible::{DigestTranscript, Digestible, MerlinTranscript};
use mc_sgx_compat::sync::Mutex;
use mc_transaction_core::{constants::MINIMUM_FEE, tx::TokenId};

/// State managed by `FeeMap`.
struct FeeMapInner {
    /// The actual map of token_id to fee.
    /// Since we hash this map, it is important to use a BTreeMap as it
    /// guarantees iterating over the map is in sorted and predictable
    /// order.
    pub map: BTreeMap<TokenId, u64>,

    /// Cached digest value, formatted as a string.
    /// (Suitable for appending to responder id)
    pub cached_digest: String,
}

/// A thread-safe object that contains a map of fee value by token id.
pub struct FeeMap {
    inner: Mutex<FeeMapInner>,
}

impl Default for FeeMap {
    fn default() -> Self {
        let mut map = BTreeMap::new();
        map.insert(TokenId::MOB, MINIMUM_FEE);

        let cached_digest = calc_digest_for_map(&map);

        Self {
            inner: Mutex::new(FeeMapInner { map, cached_digest }),
        }
    }
}

impl From<BTreeMap<TokenId, u64>> for FeeMap {
    fn from(map: BTreeMap<TokenId, u64>) -> Self {
        let cached_digest = calc_digest_for_map(&map);

        Self {
            inner: Mutex::new(FeeMapInner { map, cached_digest }),
        }
    }
}

impl FeeMap {
    /*
    pub fn update(&self, map: BTreeMap<TokenId, u64>) {
        let mut inner = self.inner.lock().unwrap();
        inner.map = map;
        inner.cached_digest = calc_digest_for_map(&inner.map);
    }
    */

    pub fn get_digest_str(&self) -> String {
        let inner = self.inner.lock().unwrap();
        inner.cached_digest.clone()
    }

    pub fn get_fee_for_token(&self, token_id: &TokenId) -> Option<u64> {
        let inner = self.inner.lock().unwrap();
        inner.map.get(&token_id).cloned()
    }

    /*
    pub fn get_map(&self) -> BTreeMap<TokenId, u64> {
        let inner = self.inner.lock().unwrap();
        inner.map.clone()
    }
    */
}

fn calc_digest_for_map(map: &BTreeMap<TokenId, u64>) -> String {
    let mut transcript = MerlinTranscript::new(b"fee_map");
    transcript.append_seq_header(b"fee_map", map.len() * 2); // TODO: is this kosher?
    for (token_id, fee) in map {
        token_id.append_to_transcript(b"token_id", &mut transcript);
        fee.append_to_transcript(b"fee", &mut transcript);
    }

    let mut result = [0u8; 32];
    transcript.extract_digest(&mut result);
    hex::encode(result)
}
