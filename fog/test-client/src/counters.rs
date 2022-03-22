// Copyright (c) 2018-2021 MobileCoin Inc.

//! Prometheus metrics, interesting when the test runs continuously

use mc_util_metrics::{register_histogram, Histogram, IntCounter, IntGauge, OpMetrics};

// Histogram buckets used for reporting the TX_CONFIRMED_TIME and
// TX_RECEIVED_TIME to prometheus
//
// The resolution in grafana can be improved by adding more buckets, but this
// increases storage costs. We may wish to tune the buckets over time as we
// collect more data and have more of an idea of how long it usually takes and
// where it is interesting to get more resolution.
const TX_TIME_BUCKETS: &[f64] = &[
    1.0, 2.0, 2.5, 3.0, 3.5, 4.0, 4.5, 5.0, 5.5, 6.0, 6.5, 7.0, 7.5, 8.0, 9.0, 10.0, 12.0, 14.0,
    16.0, 18.0, 20.0,
];

// Histogram buckets used for reporting the TX_BUILD_TIME and
// TX_SEND_TIME to prometheus
//
// The resolution in grafana can be improved by adding more buckets, but this
// increases storage costs. We may wish to tune the buckets over time as we
// collect more data and have more of an idea of how long it usually takes and
// where it is interesting to get more resolution.
const TX_TIME_BUCKETS_SHORT: &[f64] = &[0.2, 0.5, 0.7, 1.0, 1.2, 1.5, 1.7, 2.0, 2.5, 3.0];

lazy_static::lazy_static! {
    /// Counter group
    pub static ref OP_COUNTERS: OpMetrics = OpMetrics::new_and_registered("fog_test_client");

    /// Time in seconds that it takes for the source client to build a transaction (including fog interactions)
    pub static ref TX_BUILD_TIME: Histogram =
        register_histogram!("fog_test_client_tx_build_time", "Time for source client to build a transaction, including fog interactions", TX_TIME_BUCKETS_SHORT.to_vec()).unwrap();

    /// Time in seconds that it takes for the source client to send a transaction
    pub static ref TX_SEND_TIME: Histogram =
        register_histogram!("fog_test_client_tx_send_time", "Time for source client to send a built transaction", TX_TIME_BUCKETS_SHORT.to_vec()).unwrap();

    /// Time in seconds that it takes for the source client to observe that a submitted transaction landed in the blockchain (timer starts immediately after submission)
    pub static ref TX_CONFIRMED_TIME: Histogram =
        register_histogram!("fog_test_client_tx_confirmed_time", "Time for source client to observe that submitted transaction landed in blockchain", TX_TIME_BUCKETS.to_vec()).unwrap();

    /// Time in seconds that it takes for the target client to observe the received transfer (timer starts immediately after submission)
    pub static ref TX_RECEIVED_TIME: Histogram =
        register_histogram!("fog_test_client_tx_received_time", "Time for target client to observe received transfer", TX_TIME_BUCKETS.to_vec()).unwrap();

    /// Number of times that TX_CONFIRMED_TIME exceeded the configured deadline
    pub static ref TX_CONFIRMED_DEADLINE_EXCEEDED_COUNT: IntCounter = OP_COUNTERS.counter("tx_confirmed_deadline_exceeded_count");

    /// Number of times that TX_RECEIVED_TIME exceeded the configured deadline
    pub static ref TX_RECEIVED_DEADLINE_EXCEEDED_COUNT: IntCounter = OP_COUNTERS.counter("tx_received_deadline_exceeded_count");

    /// Number of times that a transfer was successful
    pub static ref TX_SUCCESS_COUNT: IntCounter = OP_COUNTERS.counter("tx_success_count");

    /// Number of times that a transfer was not successful
    /// This is the sum of all of the more specific failure mode counters
    pub static ref TX_FAILURE_COUNT: IntCounter = OP_COUNTERS.counter("tx_failure_count");

    /// Number of times that the transfer failed because the submitted transaction expired (tombstone block)
    pub static ref TX_EXPIRED_COUNT: IntCounter = OP_COUNTERS.counter("tx_expired_count");

    /// Number of times that we failed fast for a confirm tx timeout
    pub static ref CONFIRM_TX_TIMEOUT_COUNT: IntCounter = OP_COUNTERS.counter("confirm_tx_timeout_count");

    /// Number of times that we failed fast for a receive tx timeout
    pub static ref RECEIVE_TX_TIMEOUT_COUNT: IntCounter = OP_COUNTERS.counter("receive_tx_timeout_count");

    /// Number of times that the test could not be run because a client has a zero balance
    pub static ref ZERO_BALANCE_COUNT: IntCounter = OP_COUNTERS.counter("zero_balance_count");

    /// Number of times that the test failed because we observed a bad balance during the test
    pub static ref BAD_BALANCE_COUNT: IntCounter = OP_COUNTERS.counter("bad_balance_count");

    /// Number of times that we observed a successful double-spend
    pub static ref TX_DOUBLE_SPEND_COUNT: IntCounter = OP_COUNTERS.counter("tx_double_spend_count");

    /// Number of times that the test failed because we observed an unexpected memo value, e.g. wrong address or amount
    pub static ref TX_UNEXPECTED_MEMO_COUNT: IntCounter = OP_COUNTERS.counter("tx_unexpected_memo_count");

    /// Number of times that the test failed because we observed an invalid memo, e.g. parse or validation failed
    pub static ref TX_INVALID_MEMO_COUNT: IntCounter = OP_COUNTERS.counter("tx_invalid_memo_count");

    /// Number of times that the test failed because a balance check operation failed
    pub static ref CHECK_BALANCE_ERROR_COUNT: IntCounter = OP_COUNTERS.counter("check_balance_error_count");

    /// Number of times that the test failed because a get fee operation failed
    pub static ref GET_FEE_ERROR_COUNT: IntCounter = OP_COUNTERS.counter("get_fee_error_count");

    /// Number of times that the test failed because the token id is not configured
    pub static ref TOKEN_NOT_CONFIGURED_ERROR_COUNT: IntCounter = OP_COUNTERS.counter("token_not_configured_error_count");

    /// Number of times that the test failed because a build tx operation failed
    pub static ref BUILD_TX_ERROR_COUNT: IntCounter = OP_COUNTERS.counter("build_tx_error_count");

    /// Number of times that the test failed because a submit tx operation failed
    pub static ref SUBMIT_TX_ERROR_COUNT: IntCounter = OP_COUNTERS.counter("submit_tx_error_count");

    /// Number of times that the test failed because a confirm tx operation failed
    pub static ref CONFIRM_TX_ERROR_COUNT: IntCounter = OP_COUNTERS.counter("confirm_tx_error_count");

    /// The LAST_POLLING_SUCCESSFUL status is false (0) if ANY of the clients failed their most recent transfers.
    /// It is (1) if NO client has failed their most recent transfer.
    /// This is updated after every transfer attempt.
    pub static ref LAST_POLLING_SUCCESSFUL: IntGauge = OP_COUNTERS.gauge("last_polling_successful");
}
