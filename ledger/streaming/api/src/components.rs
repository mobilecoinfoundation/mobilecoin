// Copyright (c) 2018-2022 The MobileCoin Foundation

use mc_attest_core::VerificationReport;
use mc_consensus_scp::QuorumSet;
use mc_crypto_digestible::Digestible;
use mc_transaction_core::BlockData;

/// Wrapper for the components needed for block streaming.
#[derive(Clone, Debug, Digestible, PartialEq, Eq)]
pub struct BlockStreamComponents {
    /// The block data.
    pub block_data: BlockData,
    /// The SCP quorum set for this block.
    /// Optional; will be required with a future BlockVersion (see #1682).
    pub quorum_set: Option<QuorumSet>,
    /// The AVR for this block.
    /// Optional; will be required with a future BlockVersion (see #1682).
    pub verification_report: Option<VerificationReport>,
}

impl BlockStreamComponents {
    /// Instantiate an instance with the given values.
    pub fn new(
        block_data: BlockData,
        // Allows passing `Some(qs)`, `qs`, or `None`.
        quorum_set: impl Into<Option<QuorumSet>>,
        verification_report: impl Into<Option<VerificationReport>>,
    ) -> Self {
        Self {
            block_data,
            quorum_set: quorum_set.into(),
            verification_report: verification_report.into(),
        }
    }
}
