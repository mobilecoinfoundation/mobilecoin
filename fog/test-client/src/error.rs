// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Test client error type

use displaydoc::Display;
use mc_fog_sample_paykit::Error as SamplePaykitError;
use mc_transaction_core::{BlockVersionError, TokenId};

/// Error that can occur when running a test transfer
#[derive(Display, Debug)]
pub enum TestClientError {
    /// Zero Balance: Test could not be run
    ZeroBalance,
    /// A submitted Tx expired
    TxExpired,
    /// A submitted Tx did not appear within the deadline
    SubmittedTxTimeout,
    /// A Tx was not recieved within the deadline
    TxTimeout,
    /// A bad balance was observed: expected {0}, found {1}
    BadBalance(u64, u64),
    /// A double spend was not rejected by consensus as expected
    DoubleSpend,
    /// An unexpected memo was received
    UnexpectedMemo,
    /// An invalid memo was received
    InvalidMemo,
    /// Client error while checking balance: {0}
    CheckBalance(SamplePaykitError),
    /// Client error while building a transaction: {0}
    BuildTx(SamplePaykitError),
    /// Client error while sending a transaction: {0}
    SubmitTx(SamplePaykitError),
    /// Client error while confirming a transaction: {0}
    ConfirmTx(SamplePaykitError),
    /// Block version error: {0}
    BlockVersion(BlockVersionError),
    /// Client error while getting a fee: {0}
    GetFee(SamplePaykitError),
    /// TokenId is not configured in consensus (no fee is available): {0}
    TokenNotConfigured(TokenId),
}

impl From<BlockVersionError> for TestClientError {
    fn from(src: BlockVersionError) -> Self {
        Self::BlockVersion(src)
    }
}
