// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Contains methods that allow a Fog View Router enclave to combine all of the
//! Fog View Shard's query responses into one query response that'll be returned
//! for the client.

use aligned_cmov::{
    subtle::{Choice, ConstantTimeEq},
    CMov,
};
use alloc::vec::Vec;
use mc_fog_types::ledger::{KeyImageQuery, KeyImageResult, KeyImageResultCode};
use mc_transaction_core::ring_signature::KeyImage;
use mc_watcher_api::TimestampResultCode;

/// The default KeyImageResultCode used when collating the shard responses.
const DEFAULT_KEY_IMAGE_SEARCH_RESULT_CODE: KeyImageResultCode = KeyImageResultCode::NotSpent;

fn default_client_key_image(key_image: KeyImage) -> KeyImageResult {
    KeyImageResult {
        key_image,
        spent_at: 1, // not 0 because it's defined to be >0 in the .proto file
        timestamp: u64::MAX,
        timestamp_result_code: TimestampResultCode::TimestampFound as u32,
        key_image_result_code: DEFAULT_KEY_IMAGE_SEARCH_RESULT_CODE as u32,
    }
}

pub fn collate_shard_key_image_search_results(
    client_queries: Vec<KeyImageQuery>,
    shard_key_image_search_results: &[KeyImageResult],
) -> Vec<KeyImageResult> {
    let mut client_key_image_search_results: Vec<KeyImageResult> = client_queries
        .iter()
        .map(|client_query| default_client_key_image(client_query.key_image))
        .collect();

    for shard_key_image_search_result in shard_key_image_search_results.iter() {
        for client_key_image_search_result in client_key_image_search_results.iter_mut() {
            maybe_overwrite_key_image_search_result(
                client_key_image_search_result,
                shard_key_image_search_result,
            );
        }
    }

    client_key_image_search_results
}

fn maybe_overwrite_key_image_search_result(
    client_key_image_search_result: &mut KeyImageResult,
    shard_key_image_search_result: &KeyImageResult,
) {
    let should_overwrite_key_image_search_result = should_overwrite_key_image_search_result(
        client_key_image_search_result,
        shard_key_image_search_result,
    );

    client_key_image_search_result.key_image_result_code.cmov(
        should_overwrite_key_image_search_result,
        &shard_key_image_search_result.key_image_result_code,
    );

    client_key_image_search_result.spent_at.cmov(
        should_overwrite_key_image_search_result,
        &shard_key_image_search_result.spent_at,
    );

    client_key_image_search_result.timestamp.cmov(
        should_overwrite_key_image_search_result,
        &shard_key_image_search_result.timestamp,
    );

    client_key_image_search_result.timestamp_result_code.cmov(
        should_overwrite_key_image_search_result,
        &shard_key_image_search_result.timestamp_result_code,
    );
}

fn should_overwrite_key_image_search_result(
    client_key_image_search_result: &KeyImageResult,
    shard_key_image_search_result: &KeyImageResult,
) -> Choice {
    let client_key_image: &[u8] = client_key_image_search_result.key_image.as_ref();
    let shard_key_image: &[u8] = shard_key_image_search_result.key_image.as_ref();
    let key_images_match = client_key_image.ct_eq(shard_key_image);

    let client_key_image_search_result_code = client_key_image_search_result.key_image_result_code;
    let shard_key_image_search_result_code = shard_key_image_search_result.key_image_result_code;

    let client_code_is_default: Choice =
        client_key_image_search_result_code.ct_eq(&(DEFAULT_KEY_IMAGE_SEARCH_RESULT_CODE as u32));

    let shard_code_is_spent: Choice =
        shard_key_image_search_result_code.ct_eq(&(KeyImageResultCode::Spent as u32));
    let shard_code_is_error: Choice =
        shard_key_image_search_result_code.ct_eq(&(KeyImageResultCode::KeyImageError as u32));

    // We make the same query to several shards and get several responses, and
    //   this logic determines how we fill the one client response.
    // First, we only update the client response if the shard's key image for this
    // result matches   the key image for the client result we're considering
    // updating. At a high level, we want to prioritize "spent" responses.
    //   Error responses are "retriable" errors that the client will retry
    //   after a backoff. The "not spent" response is the default response and
    //   gets overwritten by any other response.
    // "Overwrite key image search result if the key images match and either the
    // shard's response is Spent or there is a new KeyImageError result"
    let new_error = shard_code_is_error & client_code_is_default;
    let should_update = shard_code_is_spent | new_error;
    key_images_match & should_update
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec;
    use yare::parameterized;

    #[test]
    fn differing_key_images_do_not_update() {
        let client_result = default_client_key_image(1.into());
        let shard_result = default_client_key_image(2.into());
        let result: bool =
            should_overwrite_key_image_search_result(&client_result, &shard_result).into();
        assert!(!result);
    }

    #[parameterized(
    client_default_shard_is_spent = { KeyImageResultCode::NotSpent, KeyImageResultCode::Spent},
    client_default_shard_is_error = { KeyImageResultCode::NotSpent, KeyImageResultCode::KeyImageError},
    client_error_shard_is_spent = { KeyImageResultCode::KeyImageError, KeyImageResultCode::Spent},
    client_spent_shard_is_spent = { KeyImageResultCode::Spent, KeyImageResultCode::Spent},
    )]
    fn should_update(client_code: KeyImageResultCode, shard_code: KeyImageResultCode) {
        let mut client_result = default_client_key_image(1.into());
        let mut shard_result = client_result.clone();
        client_result.key_image_result_code = client_code as u32;
        shard_result.key_image_result_code = shard_code as u32;
        let result: bool =
            should_overwrite_key_image_search_result(&client_result, &shard_result).into();
        assert!(result);
    }

    #[parameterized(
    client_default_shard_is_not_spent = { KeyImageResultCode::NotSpent, KeyImageResultCode::NotSpent},
    client_error_shard_is_not_spent = { KeyImageResultCode::KeyImageError, KeyImageResultCode::NotSpent},
    client_error_shard_is_error = { KeyImageResultCode::KeyImageError, KeyImageResultCode::KeyImageError},
    client_spent_shard_is_not_spent = { KeyImageResultCode::Spent, KeyImageResultCode::NotSpent},
    client_spent_shard_is_error = { KeyImageResultCode::Spent, KeyImageResultCode::KeyImageError},
    )]
    fn should_not_update(client_code: KeyImageResultCode, shard_code: KeyImageResultCode) {
        let mut client_result = default_client_key_image(1.into());
        let mut shard_result = client_result.clone();
        client_result.key_image_result_code = client_code as u32;
        shard_result.key_image_result_code = shard_code as u32;
        let result: bool =
            should_overwrite_key_image_search_result(&client_result, &shard_result).into();
        assert!(!result);
    }

    #[test]
    fn all_available() {
        let range = 1..=3;
        let client_queries = range
            .clone()
            .map(|key_image| KeyImageQuery {
                key_image: key_image.into(),
                start_block: 0,
            })
            .collect::<Vec<_>>();
        let mut shard_results = range
            .map(|key_image| KeyImageResult {
                key_image: key_image.into(),
                spent_at: key_image + 1,
                timestamp: key_image + 10,
                timestamp_result_code: TimestampResultCode::WatcherBehind as u32,
                key_image_result_code: KeyImageResultCode::Spent as u32,
            })
            .collect::<Vec<_>>();
        let mut results = collate_shard_key_image_search_results(client_queries, &shard_results);
        results.sort_by_key(|r| r.key_image);
        shard_results.sort_by_key(|r| r.key_image);
        assert_eq!(results, shard_results);
    }

    #[test]
    fn duplicate_shard_results_returns_one_result() {
        let client_queries = vec![KeyImageQuery {
            key_image: 1.into(),
            start_block: 0,
        }];
        let key_image_result = KeyImageResult {
            key_image: 1.into(),
            spent_at: 2,
            timestamp: 3,
            timestamp_result_code: TimestampResultCode::WatcherBehind as u32,
            key_image_result_code: KeyImageResultCode::Spent as u32,
        };
        let shard_results = vec![key_image_result.clone(), key_image_result.clone()];
        let mut results = collate_shard_key_image_search_results(client_queries, &shard_results);
        results.sort_by_key(|r| r.key_image);
        assert_eq!(results, vec![key_image_result]);
    }

    #[test]
    fn none_available() {
        let client_queries = vec![KeyImageQuery {
            key_image: 1.into(),
            start_block: 0,
        }];

        let shard_results = vec![];

        let result = collate_shard_key_image_search_results(client_queries, &shard_results);

        assert_eq!(result, vec![default_client_key_image(1.into())]);
    }

    #[test]
    fn error_result() {
        let client_queries = vec![KeyImageQuery {
            key_image: 1.into(),
            start_block: 0,
        }];

        let key_image_result = KeyImageResult {
            key_image: 1.into(),
            spent_at: 1,
            timestamp: 123,
            timestamp_result_code: TimestampResultCode::TimestampFound as u32,
            key_image_result_code: KeyImageResultCode::KeyImageError as u32,
        };
        let shard_results = vec![key_image_result.clone()];

        let results = collate_shard_key_image_search_results(client_queries, &shard_results);

        assert_eq!(results, vec![key_image_result]);
    }

    #[test]
    fn partial_responses() {
        let client_queries = vec![
            KeyImageQuery {
                key_image: 1.into(),
                start_block: 0,
            },
            KeyImageQuery {
                key_image: 2.into(),
                start_block: 0,
            },
        ];

        let key_image_result = KeyImageResult {
            key_image: 1.into(),
            spent_at: 1,
            timestamp: 123,
            timestamp_result_code: TimestampResultCode::TimestampFound as u32,
            key_image_result_code: KeyImageResultCode::Spent as u32,
        };
        let shard_results = vec![key_image_result];

        let results = collate_shard_key_image_search_results(client_queries, &shard_results);

        assert_eq!(
            results[0].key_image_result_code,
            KeyImageResultCode::Spent as u32
        );
        assert_eq!(
            results[1].key_image_result_code,
            DEFAULT_KEY_IMAGE_SEARCH_RESULT_CODE as u32
        );
    }
}
