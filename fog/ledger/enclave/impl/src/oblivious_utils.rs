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
use mc_watcher_api::TimestampResultCode;

/// The default KeyImageResultCode used when collating the shard responses.
const DEFAULT_KEY_IMAGE_SEARCH_RESULT_CODE: KeyImageResultCode = KeyImageResultCode::NotSpent;

pub fn collate_shard_key_image_search_results(
    client_queries: Vec<KeyImageQuery>,
    shard_key_image_search_results: Vec<KeyImageResult>,
) -> Vec<KeyImageResult> {
    let mut client_key_image_search_results: Vec<KeyImageResult> = client_queries
        .iter()
        .map(|client_query| KeyImageResult {
            key_image: client_query.key_image,
            spent_at: 1, // not 0 because it's defined to be >0 in the .proto file
            timestamp: u64::MAX,
            timestamp_result_code: TimestampResultCode::TimestampFound as u32,
            key_image_result_code: DEFAULT_KEY_IMAGE_SEARCH_RESULT_CODE as u32,
        })
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
    let do_key_images_match = client_key_image.ct_eq(shard_key_image);

    let client_key_image_search_result_code = client_key_image_search_result.key_image_result_code;
    let shard_key_image_search_result_code = shard_key_image_search_result.key_image_result_code;

    let client_code_is_not_spent: Choice =
        client_key_image_search_result_code.ct_eq(&(KeyImageResultCode::NotSpent as u32));

    let shard_code_is_spent: Choice =
        shard_key_image_search_result_code.ct_eq(&(KeyImageResultCode::Spent as u32));
    let shard_code_is_error: Choice =
        shard_key_image_search_result_code.ct_eq(&(KeyImageResultCode::KeyImageError as u32));

    //   We make the same query to several shards and get several responses, and
    // this logic determines how we fill the one client response.
    //   At a high level, we want to prioritize "spent" responses.
    // Error responses are "retriable" errors that the client will retry
    // after a backoff. The "not spent" response is the default response and
    // gets overwritten by any other response.
    // spent > error > not spent
    do_key_images_match
           // Always write a Found code
        & (shard_code_is_spent
            // Write an error code IFF the client code is NotFound.
            | ((shard_code_is_error) & client_code_is_not_spent))
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec;

    #[test]
    fn should_overwrite_tests() {
        let test_cases = vec![
            // Images don't match
            (
                123456,
                1,
                123456,
                TimestampResultCode::TimestampFound,
                KeyImageResultCode::NotSpent,
                654321,
                1,
                123456,
                TimestampResultCode::TimestampFound,
                KeyImageResultCode::Spent,
                false,
                "key images don't match, but overwritten anyway!",
            ),
            // Spent beats not spent
            (
                123456,
                1,
                u64::MAX,
                TimestampResultCode::TimestampFound,
                KeyImageResultCode::NotSpent,
                123456,
                1,
                123456,
                TimestampResultCode::TimestampFound,
                KeyImageResultCode::Spent,
                true,
                "Shard key is spent but doesn't overwrite unspent client!",
            ),
            // Spent beats error
            (
                123456,
                1,
                123456,
                TimestampResultCode::TimestampFound,
                KeyImageResultCode::KeyImageError,
                123456,
                1,
                123456,
                TimestampResultCode::TimestampFound,
                KeyImageResultCode::Spent,
                true,
                "Shard key is spent but doesn't overwrite error client!",
            ),
            // Error beats not spent
            (
                123456,
                1,
                123456,
                TimestampResultCode::TimestampFound,
                KeyImageResultCode::NotSpent,
                123456,
                1,
                123456,
                TimestampResultCode::TimestampFound,
                KeyImageResultCode::KeyImageError,
                true,
                "Shard result is error but doesn't overwrite unspent client!",
            ),
            // Error doesn't beat spent
            (
                123456,
                1,
                123456,
                TimestampResultCode::TimestampFound,
                KeyImageResultCode::Spent,
                123456,
                1,
                123456,
                TimestampResultCode::TimestampFound,
                KeyImageResultCode::KeyImageError,
                false,
                "Shard result is error but overwrites spent client!",
            ),
            // Unspent doesn't beat error
            (
                123456,
                1,
                123456,
                TimestampResultCode::TimestampFound,
                KeyImageResultCode::KeyImageError,
                123456,
                1,
                123456,
                TimestampResultCode::TimestampFound,
                KeyImageResultCode::NotSpent,
                false,
                "Shard result is unspent but overwrites client error!",
            ),
            // Unspent doesn't beat spent
            (
                123456,
                1,
                123456,
                TimestampResultCode::TimestampFound,
                KeyImageResultCode::Spent,
                123456,
                1,
                123456,
                TimestampResultCode::TimestampFound,
                KeyImageResultCode::NotSpent,
                false,
                "Shard result is unspent but overwrites spent client!",
            ),
        ];

        for (
            client_key_image,
            client_spent_at,
            client_timestamp,
            client_timestamp_result_code,
            client_key_image_result_code,
            shard_key_image,
            shard_spent_at,
            shard_timestamp,
            shard_timestamp_result_code,
            shard_key_image_result_code,
            expected_result,
            panic_message,
        ) in test_cases.into_iter()
        {
            let client_result = KeyImageResult {
                key_image: client_key_image.into(),
                spent_at: client_spent_at,
                timestamp: client_timestamp,
                timestamp_result_code: client_timestamp_result_code as u32,
                key_image_result_code: client_key_image_result_code as u32,
            };
            let shard_result = KeyImageResult {
                key_image: shard_key_image.into(),
                spent_at: shard_spent_at,
                timestamp: shard_timestamp,
                timestamp_result_code: shard_timestamp_result_code as u32,
                key_image_result_code: shard_key_image_result_code as u32,
            };
            let result: bool =
                should_overwrite_key_image_search_result(&client_result, &shard_result).into();
            assert_eq!(result, expected_result, "{}", panic_message);
        }
    }

    fn collate(
        client_queries: Vec<KeyImageQuery>,
        shard_key_image_search_results: Vec<KeyImageResult>,
    ) -> Vec<KeyImageResult> {
        let queries_count = client_queries.len();
        let result =
            collate_shard_key_image_search_results(client_queries, shard_key_image_search_results);

        let results_count = result.len();
        assert_eq!(
            results_count, queries_count,
            "{}",
            "results length does not match number of queries"
        );

        result
    }

    #[test]
    fn collation_tests() {
        // All results available, no dupes
        let client_queries = vec![KeyImageQuery {
            key_image: 1.into(),
            start_block: 0,
        }];

        let shard_results = vec![KeyImageResult {
            key_image: 1.into(),
            spent_at: 1,
            timestamp: 123,
            timestamp_result_code: TimestampResultCode::TimestampFound as u32,
            key_image_result_code: KeyImageResultCode::Spent as u32,
        }];

        let result = collate(client_queries, shard_results);

        let all_images_found = result.iter().all(|key_image_result| {
            key_image_result.key_image_result_code == KeyImageResultCode::Spent as u32
        });

        assert!(
            all_images_found,
            "{}",
            "all images are present but some were not collated"
        );

        // All results available, one duplicate
        let client_queries = vec![KeyImageQuery {
            key_image: 1.into(),
            start_block: 0,
        }];

        let shard_results = vec![
            KeyImageResult {
                key_image: 1.into(),
                spent_at: 1,
                timestamp: 123,
                timestamp_result_code: TimestampResultCode::TimestampFound as u32,
                key_image_result_code: KeyImageResultCode::Spent as u32,
            },
            KeyImageResult {
                key_image: 1.into(),
                spent_at: 1,
                timestamp: 123,
                timestamp_result_code: TimestampResultCode::TimestampFound as u32,
                key_image_result_code: KeyImageResultCode::Spent as u32,
            },
        ];

        let result = collate(client_queries, shard_results);

        let all_images_found = result.iter().all(|key_image_result| {
            key_image_result.key_image_result_code == KeyImageResultCode::Spent as u32
        });

        assert!(
            all_images_found,
            "{}",
            "all images are present but some were not collated"
        );

        // All results available, one error
        let client_queries = vec![KeyImageQuery {
            key_image: 1.into(),
            start_block: 0,
        }];

        let shard_results = vec![
            KeyImageResult {
                key_image: 1.into(),
                spent_at: 1,
                timestamp: 123,
                timestamp_result_code: TimestampResultCode::TimestampFound as u32,
                key_image_result_code: KeyImageResultCode::Spent as u32,
            },
            KeyImageResult {
                key_image: 1.into(),
                spent_at: 1,
                timestamp: 123,
                timestamp_result_code: TimestampResultCode::TimestampFound as u32,
                key_image_result_code: KeyImageResultCode::KeyImageError as u32,
            },
        ];

        let result = collate(client_queries, shard_results);

        let all_images_found = result.iter().all(|key_image_result| {
            key_image_result.key_image_result_code == KeyImageResultCode::Spent as u32
        });

        assert!(
            all_images_found,
            "{}",
            "all images are present but some were not collated"
        );

        // No results available
        let client_queries = vec![KeyImageQuery {
            key_image: 1.into(),
            start_block: 0,
        }];

        let shard_results = vec![];

        let result = collate(client_queries, shard_results);

        let all_images_found = result.iter().all(|key_image_result| {
            key_image_result.key_image_result_code == KeyImageResultCode::Spent as u32
        });

        assert!(
            !all_images_found,
            "{}",
            "all images show results but no result provided"
        );

        // Result is error
        let client_queries = vec![KeyImageQuery {
            key_image: 1.into(),
            start_block: 0,
        }];

        let shard_results = vec![KeyImageResult {
            key_image: 1.into(),
            spent_at: 1,
            timestamp: 123,
            timestamp_result_code: TimestampResultCode::TimestampFound as u32,
            key_image_result_code: KeyImageResultCode::KeyImageError as u32,
        }];

        let result = collate(client_queries, shard_results);

        let all_images_error = result.iter().all(|key_image_result| {
            key_image_result.key_image_result_code == KeyImageResultCode::KeyImageError as u32
        });

        assert!(
            all_images_error,
            "{}",
            "an image reported no error despite an error result"
        );

        // Only some queries answered
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

        let shard_results = vec![KeyImageResult {
            key_image: 1.into(),
            spent_at: 1,
            timestamp: 123,
            timestamp_result_code: TimestampResultCode::TimestampFound as u32,
            key_image_result_code: KeyImageResultCode::Spent as u32,
        }];

        let result = collate(client_queries, shard_results);

        let all_images_found = result.iter().all(|key_image_result| {
            key_image_result.key_image_result_code == KeyImageResultCode::Spent as u32
        });

        assert!(
            !all_images_found,
            "{}",
            "all images show results but some had no result provided"
        );
    }
}
