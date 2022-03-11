// Copyright (c) 2018-2022 The MobileCoin Foundation

use mc_attest_core::VerificationReport;
use mc_consensus_scp::QuorumSet;
use mc_transaction_core::BlockData;

/// Wrapper for the components needed for block streaming.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockStreamComponents {
    /// The block data.
    pub block_data: BlockData,
    /// The SCP quorum set for this block.
    /// Currently optional, will become required with a future BlockVersion.
    pub quorum_set: Option<QuorumSet>,
    /// The AVR for this block.
    /// Currently optional, will become required with a future BlockVersion.
    pub verification_report: Option<VerificationReport>,
}
