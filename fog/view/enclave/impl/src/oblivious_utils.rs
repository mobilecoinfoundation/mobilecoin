// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Contains methods that allow a Fog View Router enclave to combine all of the
//! Fog View Shard's query responses into one query response that'll be returned
//! for the client.

use crate::Result;

use aligned_cmov::{
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq},
    CMov,
};
use alloc::{vec, vec::Vec};
use mc_fog_types::view::{TxOutSearchResult, TxOutSearchResultCode};

/// The default TxOutSearchResultCode used when collating the shard responses.
///   Warning: Do not change this without careful thought because the logic in
///            the [should_over_write_tx_out_search_result] method assumes that
///            the default code is NotFound.
const DEFAULT_TX_OUT_SEARCH_RESULT_CODE: TxOutSearchResultCode = TxOutSearchResultCode::NotFound;
/// The length of the ciphertext returned to the client.
const CLIENT_CIPHERTEXT_LENGTH: usize = 255;

#[allow(dead_code)]
pub fn collate_shard_tx_out_search_results(
    client_search_keys: Vec<Vec<u8>>,
    shard_tx_out_search_results: Vec<TxOutSearchResult>,
) -> Result<Vec<TxOutSearchResult>> {
    let mut client_tx_out_search_results: Vec<TxOutSearchResult> = client_search_keys
        .iter()
        .map(|client_search_key| TxOutSearchResult {
            search_key: client_search_key.to_vec(),
            result_code: DEFAULT_TX_OUT_SEARCH_RESULT_CODE as u32,
            ciphertext: vec![0u8; CLIENT_CIPHERTEXT_LENGTH],
            payload_length: CLIENT_CIPHERTEXT_LENGTH as u32,
        })
        .collect();

    for shard_tx_out_search_result in shard_tx_out_search_results.iter() {
        for client_tx_out_search_result in client_tx_out_search_results.iter_mut() {
            maybe_overwrite_tx_out_search_result(
                client_tx_out_search_result,
                shard_tx_out_search_result,
            );
        }
    }

    Ok(client_tx_out_search_results)
}

fn maybe_overwrite_tx_out_search_result(
    client_tx_out_search_result: &mut TxOutSearchResult,
    shard_tx_out_search_result: &TxOutSearchResult,
) {
    let should_overwrite_tx_out_search_result = should_overwrite_tx_out_search_result(
        client_tx_out_search_result,
        shard_tx_out_search_result,
    );
    let shard_ciphertext_length = shard_tx_out_search_result.ciphertext.len();
    client_tx_out_search_result
        .payload_length
        .conditional_assign(
            &(shard_ciphertext_length as u32),
            should_overwrite_tx_out_search_result,
        );
    for idx in 0..shard_ciphertext_length {
        client_tx_out_search_result.ciphertext[idx].conditional_assign(
            &shard_tx_out_search_result.ciphertext[idx],
            should_overwrite_tx_out_search_result,
        );
    }
    client_tx_out_search_result.result_code.cmov(
        should_overwrite_tx_out_search_result,
        &shard_tx_out_search_result.result_code,
    );
}

fn should_overwrite_tx_out_search_result(
    client_tx_out_search_result: &TxOutSearchResult,
    shard_tx_out_search_result: &TxOutSearchResult,
) -> Choice {
    let do_search_keys_match = client_tx_out_search_result
        .search_key
        .ct_eq(&shard_tx_out_search_result.search_key);

    let client_tx_out_search_result_code = client_tx_out_search_result.result_code;
    let shard_tx_out_search_result_code = shard_tx_out_search_result.result_code;

    let client_code_is_found: Choice =
        client_tx_out_search_result_code.ct_eq(&(TxOutSearchResultCode::Found as u32));
    let client_code_is_not_found: Choice =
        client_tx_out_search_result_code.ct_eq(&(TxOutSearchResultCode::NotFound as u32));

    let shard_code_is_found: Choice =
        shard_tx_out_search_result_code.ct_eq(&(TxOutSearchResultCode::Found as u32));

    let shard_code_is_retryable_error =
        is_code_retryable_error(shard_tx_out_search_result.result_code);
    let shard_code_is_bad_search_key =
        shard_tx_out_search_result_code.ct_eq(&(TxOutSearchResultCode::BadSearchKey as u32));

    //   We make the same query to several shards and get several responses, and
    // this logic determines how we fill the one client response.
    //   At a high level, we want to prioritize "found" responses, and then "bad
    // search key" responses,  which means the argument was invalid. After that
    // the other two responses are "retriable" errors that the client will retry
    // after a backoff. The "not found" response is the default response and
    // gets overwritten by any other response.
    do_search_keys_match
           // Always write a Found code
        & (shard_code_is_found
            // Write a BadSearchKey code IFF the client code is
            //       -InternalError,
            //       -RateLimitedError
            //       -NotFound
            //       -BadSearchKey
            | (shard_code_is_bad_search_key & !client_code_is_found))
            // Write an InternalError OR RateLimited code IFF the code is NotFound.
            | (shard_code_is_retryable_error & client_code_is_not_found)
}

fn is_code_retryable_error(result_code: u32) -> Choice {
    let is_internal_error = result_code.ct_eq(&(TxOutSearchResultCode::InternalError as u32));
    let is_rate_limited = result_code.ct_eq(&(TxOutSearchResultCode::RateLimited as u32));

    is_internal_error | is_rate_limited
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::oblivious_utils::CLIENT_CIPHERTEXT_LENGTH;
    use itertools::Itertools;
    use std::collections::HashSet;

    fn create_test_tx_out_search_result(
        search_key: Vec<u8>,
        ciphertext_number: u8,
        ciphertext_length: usize,
        result_code: TxOutSearchResultCode,
    ) -> TxOutSearchResult {
        TxOutSearchResult {
            search_key,
            result_code: result_code as u32,
            ciphertext: vec![ciphertext_number; ciphertext_length],
            payload_length: ciphertext_length as u32,
        }
    }

    #[test]
    fn should_overwrite_tx_out_search_result_client_not_found_shard_has_tx_out_returns_true() {
        let search_key = vec![0u8; 10];
        let client_tx_out_search_result = create_test_tx_out_search_result(
            search_key.clone(),
            0,
            CLIENT_CIPHERTEXT_LENGTH - 1,
            TxOutSearchResultCode::NotFound,
        );
        let shard_tx_out_search_result = create_test_tx_out_search_result(
            search_key,
            0,
            CLIENT_CIPHERTEXT_LENGTH - 1,
            TxOutSearchResultCode::Found,
        );

        let result: bool = should_overwrite_tx_out_search_result(
            &client_tx_out_search_result,
            &shard_tx_out_search_result,
        )
        .into();

        assert!(result);
    }

    #[test]
    fn should_overwrite_tx_out_search_result_client_bad_search_key_shard_has_tx_out_returns_true() {
        let search_key = vec![0u8; 10];
        let client_tx_out_search_result = create_test_tx_out_search_result(
            search_key.clone(),
            0,
            CLIENT_CIPHERTEXT_LENGTH - 1,
            TxOutSearchResultCode::BadSearchKey,
        );
        let shard_tx_out_search_result = create_test_tx_out_search_result(
            search_key,
            0,
            CLIENT_CIPHERTEXT_LENGTH - 1,
            TxOutSearchResultCode::Found,
        );

        let result: bool = should_overwrite_tx_out_search_result(
            &client_tx_out_search_result,
            &shard_tx_out_search_result,
        )
        .into();

        assert!(result);
    }

    #[test]
    fn should_overwrite_tx_out_search_result_client_has_internal_error_shard_has_tx_out_returns_true(
    ) {
        let search_key = vec![0u8; 10];
        let client_tx_out_search_result = create_test_tx_out_search_result(
            search_key.clone(),
            0,
            CLIENT_CIPHERTEXT_LENGTH - 1,
            TxOutSearchResultCode::InternalError,
        );
        let shard_tx_out_search_result = create_test_tx_out_search_result(
            search_key,
            0,
            CLIENT_CIPHERTEXT_LENGTH - 1,
            TxOutSearchResultCode::Found,
        );

        let result: bool = should_overwrite_tx_out_search_result(
            &client_tx_out_search_result,
            &shard_tx_out_search_result,
        )
        .into();

        assert!(result);
    }

    #[test]
    fn should_overwrite_tx_out_search_result_client_has_rate_limited_error_shard_has_tx_out_returns_true(
    ) {
        let search_key = vec![0u8; 10];
        let client_tx_out_search_result = create_test_tx_out_search_result(
            search_key.clone(),
            0,
            CLIENT_CIPHERTEXT_LENGTH - 1,
            TxOutSearchResultCode::RateLimited,
        );
        let shard_tx_out_search_result = create_test_tx_out_search_result(
            search_key,
            0,
            CLIENT_CIPHERTEXT_LENGTH - 1,
            TxOutSearchResultCode::Found,
        );

        let result: bool = should_overwrite_tx_out_search_result(
            &client_tx_out_search_result,
            &shard_tx_out_search_result,
        )
        .into();

        assert!(result);
    }

    #[test]
    fn should_overwrite_tx_out_client_has_found_never_overwritten_returns_false_unless_shard_finds()
    {
        let search_key = vec![0u8; 10];
        let client_tx_out_search_result = create_test_tx_out_search_result(
            search_key.clone(),
            0,
            CLIENT_CIPHERTEXT_LENGTH - 1,
            TxOutSearchResultCode::Found,
        );

        let mut shard_tx_out_search_result = create_test_tx_out_search_result(
            search_key.clone(),
            0,
            CLIENT_CIPHERTEXT_LENGTH - 1,
            TxOutSearchResultCode::NotFound,
        );
        let mut result: bool = should_overwrite_tx_out_search_result(
            &client_tx_out_search_result,
            &shard_tx_out_search_result,
        )
        .into();
        assert!(!result);

        shard_tx_out_search_result = create_test_tx_out_search_result(
            search_key.clone(),
            0,
            CLIENT_CIPHERTEXT_LENGTH - 1,
            TxOutSearchResultCode::BadSearchKey,
        );
        result = should_overwrite_tx_out_search_result(
            &client_tx_out_search_result,
            &shard_tx_out_search_result,
        )
        .into();
        assert!(!result);

        shard_tx_out_search_result = create_test_tx_out_search_result(
            search_key.clone(),
            0,
            CLIENT_CIPHERTEXT_LENGTH - 1,
            TxOutSearchResultCode::InternalError,
        );
        result = should_overwrite_tx_out_search_result(
            &client_tx_out_search_result,
            &shard_tx_out_search_result,
        )
        .into();
        assert!(!result);

        shard_tx_out_search_result = create_test_tx_out_search_result(
            search_key.clone(),
            0,
            CLIENT_CIPHERTEXT_LENGTH - 1,
            TxOutSearchResultCode::RateLimited,
        );
        result = should_overwrite_tx_out_search_result(
            &client_tx_out_search_result,
            &shard_tx_out_search_result,
        )
        .into();
        assert!(!result);

        shard_tx_out_search_result = create_test_tx_out_search_result(
            search_key,
            0,
            CLIENT_CIPHERTEXT_LENGTH - 1,
            TxOutSearchResultCode::Found,
        );
        result = should_overwrite_tx_out_search_result(
            &client_tx_out_search_result,
            &shard_tx_out_search_result,
        )
        .into();
        assert!(result);
    }

    #[test]
    fn should_overwrite_tx_out_search_result_client_has_not_found_shard_has_retryable_error_returns_true(
    ) {
        let search_key = vec![0u8; 10];
        let client_tx_out_search_result = create_test_tx_out_search_result(
            search_key.clone(),
            0,
            CLIENT_CIPHERTEXT_LENGTH - 1,
            TxOutSearchResultCode::NotFound,
        );

        let mut shard_tx_out_search_result = create_test_tx_out_search_result(
            search_key.clone(),
            0,
            CLIENT_CIPHERTEXT_LENGTH - 1,
            TxOutSearchResultCode::InternalError,
        );
        let mut result: bool = should_overwrite_tx_out_search_result(
            &client_tx_out_search_result,
            &shard_tx_out_search_result,
        )
        .into();
        assert!(result);

        shard_tx_out_search_result = create_test_tx_out_search_result(
            search_key,
            0,
            CLIENT_CIPHERTEXT_LENGTH - 1,
            TxOutSearchResultCode::RateLimited,
        );
        result = should_overwrite_tx_out_search_result(
            &client_tx_out_search_result,
            &shard_tx_out_search_result,
        )
        .into();
        assert!(result);
    }

    #[test]
    fn should_overwrite_tx_out_search_result_client_has_bad_search_key_shard_has_retryable_error_returns_false(
    ) {
        let search_key = vec![0u8; 10];
        let client_tx_out_search_result = create_test_tx_out_search_result(
            search_key.clone(),
            0,
            CLIENT_CIPHERTEXT_LENGTH - 1,
            TxOutSearchResultCode::BadSearchKey,
        );

        let mut shard_tx_out_search_result = create_test_tx_out_search_result(
            search_key.clone(),
            0,
            CLIENT_CIPHERTEXT_LENGTH - 1,
            TxOutSearchResultCode::InternalError,
        );
        let mut result: bool = should_overwrite_tx_out_search_result(
            &client_tx_out_search_result,
            &shard_tx_out_search_result,
        )
        .into();
        assert!(!result);

        shard_tx_out_search_result = create_test_tx_out_search_result(
            search_key,
            0,
            CLIENT_CIPHERTEXT_LENGTH - 1,
            TxOutSearchResultCode::RateLimited,
        );
        result = should_overwrite_tx_out_search_result(
            &client_tx_out_search_result,
            &shard_tx_out_search_result,
        )
        .into();
        assert!(!result);
    }

    #[test]
    fn should_overwrite_tx_out_search_result_client_has_bad_search_key() {
        let search_key = vec![0u8; 10];
        let shard_tx_out_search_result = create_test_tx_out_search_result(
            search_key.clone(),
            0,
            CLIENT_CIPHERTEXT_LENGTH - 1,
            TxOutSearchResultCode::BadSearchKey,
        );

        let mut client_tx_out_search_result = create_test_tx_out_search_result(
            search_key.clone(),
            0,
            CLIENT_CIPHERTEXT_LENGTH - 1,
            TxOutSearchResultCode::RateLimited,
        );
        let mut result: bool = should_overwrite_tx_out_search_result(
            &client_tx_out_search_result,
            &shard_tx_out_search_result,
        )
        .into();
        assert!(result);

        client_tx_out_search_result = create_test_tx_out_search_result(
            search_key,
            0,
            CLIENT_CIPHERTEXT_LENGTH - 1,
            TxOutSearchResultCode::RateLimited,
        );
        result = should_overwrite_tx_out_search_result(
            &client_tx_out_search_result,
            &shard_tx_out_search_result,
        )
        .into();
        assert!(result);
    }

    #[test]
    fn should_overwrite_tx_out_search_result_client_has_retryable_error_shard_has_not_found_returns_true(
    ) {
        let search_key = vec![0u8; 10];
        let client_tx_out_search_result = create_test_tx_out_search_result(
            search_key.clone(),
            0,
            CLIENT_CIPHERTEXT_LENGTH - 1,
            TxOutSearchResultCode::BadSearchKey,
        );

        let mut shard_tx_out_search_result = create_test_tx_out_search_result(
            search_key.clone(),
            0,
            CLIENT_CIPHERTEXT_LENGTH - 1,
            TxOutSearchResultCode::InternalError,
        );
        let mut result: bool = should_overwrite_tx_out_search_result(
            &client_tx_out_search_result,
            &shard_tx_out_search_result,
        )
        .into();
        assert!(!result);

        shard_tx_out_search_result = create_test_tx_out_search_result(
            search_key,
            0,
            CLIENT_CIPHERTEXT_LENGTH - 1,
            TxOutSearchResultCode::RateLimited,
        );
        result = should_overwrite_tx_out_search_result(
            &client_tx_out_search_result,
            &shard_tx_out_search_result,
        )
        .into();
        assert!(!result);
    }

    #[test]
    fn collate_shard_query_responses_shards_find_all_tx_outs() {
        let client_search_keys: Vec<Vec<u8>> = (0..10).map(|num| vec![num; 10]).collect();
        let shard_tx_out_search_results: Vec<TxOutSearchResult> = client_search_keys
            .iter()
            .map(|search_key| {
                create_test_tx_out_search_result(
                    search_key.clone(),
                    0,
                    CLIENT_CIPHERTEXT_LENGTH - 1,
                    TxOutSearchResultCode::Found,
                )
            })
            .collect();

        let result = collate_shard_tx_out_search_results(
            client_search_keys.clone(),
            shard_tx_out_search_results,
        )
        .unwrap();

        let all_tx_out_found = result.iter().all(|tx_out_search_result| {
            tx_out_search_result.result_code == TxOutSearchResultCode::Found as u32
        });
        assert!(all_tx_out_found);

        let result_client_search_keys: HashSet<Vec<u8>> = HashSet::from_iter(
            result
                .iter()
                .map(|tx_out_search_result| tx_out_search_result.search_key.clone()),
        );
        assert_eq!(
            result_client_search_keys,
            HashSet::from_iter(client_search_keys)
        );
    }

    #[test]
    fn collate_shard_query_responses_shards_one_not_found() {
        let client_search_keys: Vec<Vec<u8>> = (0..10).map(|num| vec![num; 10]).collect();
        let shard_tx_out_search_results: Vec<TxOutSearchResult> = client_search_keys
            .iter()
            .enumerate()
            .map(|(i, search_key)| {
                let result_code = match i {
                    0 => TxOutSearchResultCode::NotFound,
                    _ => TxOutSearchResultCode::Found,
                };
                create_test_tx_out_search_result(
                    search_key.clone(),
                    0,
                    CLIENT_CIPHERTEXT_LENGTH - 1,
                    result_code,
                )
            })
            .collect();

        let result = collate_shard_tx_out_search_results(
            client_search_keys.clone(),
            shard_tx_out_search_results,
        )
        .unwrap();

        let result_client_search_keys: HashSet<Vec<u8>> = HashSet::from_iter(
            result
                .iter()
                .map(|tx_out_search_result| tx_out_search_result.search_key.clone()),
        );
        assert_eq!(
            result_client_search_keys,
            HashSet::from_iter(client_search_keys)
        );

        let not_found_count = result
            .iter()
            .filter(|tx_out_search_result| {
                tx_out_search_result.result_code == TxOutSearchResultCode::NotFound as u32
            })
            .count();
        assert_eq!(not_found_count, 1);
    }

    #[test]
    fn collate_shard_query_responses_ciphertext_is_greater_than_client_ciphertext_length_panics() {
        let client_search_keys: Vec<Vec<u8>> = (0..10).map(|num| vec![num; 10]).collect();
        let shard_tx_out_search_results: Vec<TxOutSearchResult> = client_search_keys
            .iter()
            .map(|search_key| TxOutSearchResult {
                search_key: search_key.clone(),
                result_code: TxOutSearchResultCode::NotFound as u32,
                ciphertext: vec![0u8; CLIENT_CIPHERTEXT_LENGTH + 1],
                payload_length: (CLIENT_CIPHERTEXT_LENGTH + 1) as u32,
            })
            .collect();

        let result = std::panic::catch_unwind(|| {
            collate_shard_tx_out_search_results(
                client_search_keys.clone(),
                shard_tx_out_search_results,
            )
        });

        assert!(result.is_err());
    }

    #[test]
    fn collate_shard_query_responses_different_ciphertext_lengths_returns_correct_client_ciphertexts(
    ) {
        let client_search_keys: Vec<Vec<u8>> = (0..3).map(|num| vec![num; 10]).collect();
        let ciphertext_values = [5u8, 28u8, 128u8];
        let ciphertext_lengths: [u32; 3] = [1, 2, 3];
        let shard_tx_out_search_results: Vec<TxOutSearchResult> = client_search_keys
            .iter()
            .enumerate()
            .map(|(idx, search_key)| {
                let ciphertext = vec![ciphertext_values[idx]; ciphertext_lengths[idx] as usize];
                let payload_length = ciphertext.len() as u32;
                TxOutSearchResult {
                    search_key: search_key.clone(),
                    result_code: TxOutSearchResultCode::Found as u32,
                    ciphertext,
                    payload_length,
                }
            })
            .collect();

        let results: Vec<TxOutSearchResult> =
            collate_shard_tx_out_search_results(client_search_keys, shard_tx_out_search_results)
                .unwrap()
                .into_iter()
                // Sort by ciphertext length (ascending) in order to know what each expected result
                // should be.
                .sorted_by(|a, b| Ord::cmp(&a.ciphertext[0], &b.ciphertext[0]))
                .collect();

        let mut expected_first_result = [0u8; CLIENT_CIPHERTEXT_LENGTH];
        expected_first_result[0] = ciphertext_values[0];
        assert_eq!(results[0].ciphertext, expected_first_result);
        assert_eq!(results[0].payload_length, ciphertext_lengths[0]);

        let mut expected_second_result = [0u8; CLIENT_CIPHERTEXT_LENGTH];
        expected_second_result[0] = ciphertext_values[1];
        expected_second_result[1] = ciphertext_values[1];
        assert_eq!(results[1].ciphertext, expected_second_result);
        assert_eq!(results[1].payload_length, ciphertext_lengths[1]);

        let mut expected_third_result = [0u8; CLIENT_CIPHERTEXT_LENGTH];
        expected_third_result[0] = ciphertext_values[2];
        expected_third_result[1] = ciphertext_values[2];
        expected_third_result[2] = ciphertext_values[2];
        assert_eq!(results[2].ciphertext, expected_third_result);
        assert_eq!(results[2].payload_length, ciphertext_lengths[2]);
    }
}
