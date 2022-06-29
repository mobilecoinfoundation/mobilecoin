// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Prometheus counters.

use mc_util_metrics::{IntCounter, IntGauge, OpMetrics};

lazy_static::lazy_static! {
    /// Prometheus counters.
    pub static ref OP_COUNTERS: OpMetrics = OpMetrics::new_and_registered("mc_mint_auditor");

    /// Number of blocks synced.
    pub static ref NUM_BLOCKS_SYNCED: IntGauge = OP_COUNTERS.gauge("num_blocks_synced");

    /// Number of burns exceeding calculated balance.
    pub static ref NUM_BURNS_EXCEEDING_BALANCE: IntGauge = OP_COUNTERS.gauge("num_burns_exceeding_balance");

    /// Number of MintTxs without a matching MintConfig.
    pub static ref NUM_MINT_TXS_WITHOUT_MATCHING_MINT_CONFIG: IntGauge = OP_COUNTERS.gauge("num_mint_txs_without_matching_mint_config");

    /// Number of mismatched MintTxs and Gnosis deposits.
    pub static ref NUM_MISMATCHING_MINTS_AND_DEPOSITS: IntGauge = OP_COUNTERS.gauge("num_mismatching_mints_and_deposits");

    /// Number of deposits to an unaudited Ethereum token contract address.
    pub static ref NUM_UNKNOWN_ETHEREUM_TOKEN_DEPOSITS: IntGauge = OP_COUNTERS.gauge("num_unknown_ethereum_token_deposits");

    /// Number of times we failed to fetch gnosis transactions.
    pub static ref NUM_FAILED_GNOSIS_GET_ALL_TRANSACTION_DATA: IntCounter = OP_COUNTERS.counter("num_failed_gnosis_get_all_transaction_data");
}
