use crate::Result;
use mc_attest_core::VerificationReport;
use mc_consensus_scp::QuorumSet;
use mc_transaction_core::BlockData;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockStreamComponents {
    pub block_data: BlockData,
    pub quorum_set: Option<QuorumSet>,
    pub verification_report: Option<VerificationReport>,
}

pub trait BlockStream {
    type Stream: futures::Stream<Item = Result<BlockStreamComponents>>;

    fn get_block_stream(&self, starting_height: u64) -> Result<Self::Stream>;
}
