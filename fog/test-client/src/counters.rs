// Copyright (c) 2018-2021 MobileCoin Inc.

//! Prometheus metrics, interesting when the test runs continuously

use mc_util_metrics::{Histogram, IntCounter, OpMetrics};

lazy_static::lazy_static! {
    /// Counter group
    pub static ref OP_COUNTERS: OpMetrics = OpMetrics::new_and_registered("fog_test_client");

    /// Time in seconds that it takes for the source client to observe that a submitted transaction landed in the blockchain (timer starts immediately after submission)
    pub static ref TX_CONFIRMED_TIME: Histogram = OP_COUNTERS.histogram("tx_confirmed_time");

    /// Time in seconds that it takes for the target client to observe the received transfer (timer starts immediately after submission)
    pub static ref TX_RECEIVED_TIME: Histogram = OP_COUNTERS.histogram("tx_received_time");

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

    /// Number of times that the test failed because a build tx operation failed
    pub static ref BUILD_TX_ERROR_COUNT: IntCounter = OP_COUNTERS.counter("build_tx_error_count");

    /// Number of times that the test failed because a submit tx operation failed
    pub static ref SUBMIT_TX_ERROR_COUNT: IntCounter = OP_COUNTERS.counter("submit_tx_error_count");

    /// Number of times that the test failed because a confirm tx operation failed
    pub static ref CONFIRM_TX_ERROR_COUNT: IntCounter = OP_COUNTERS.counter("confirm_tx_error_count");
}
