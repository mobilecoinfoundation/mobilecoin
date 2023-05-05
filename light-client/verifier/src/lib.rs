use config::LightClientVerifierConfig;
use error::VerifierError;
use mc_api::blockchain::ArchiveBlock;
use mc_blockchain_types::{BlockData, BlockID, BlockIndex};
use mc_common::ResponderId;
use mc_ledger_sync::{NetworkState, SCPNetworkState};
use mc_transaction_core::tx::TxOut;
use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
    sync::{Arc, Mutex},
};

pub mod config;
pub mod error;

const FAKE_NODE_ID: &str = "fake:7777";
// This is what the verifier will receive from the relayer
#[derive(Clone, Debug)]
pub struct RelayerMessage {
    // FIXME: Do we need Mutexes & Arcs here?
    // This map should include each node's signed copy of the block containing 'tx'.
    pub blocks: Arc<Mutex<Vec<ArchiveBlock>>>,
    pub txos: Arc<Mutex<Vec<TxOut>>>,
}

impl RelayerMessage {
    // FIXME: Is this necessary? Is it idiomatic?
    fn new(blocks: Vec<BlockData>, txos: Vec<TxOut>) -> Self {
        let archive_blocks = Arc::new(Mutex::new(
            blocks
                .into_iter()
                .map(|block| ArchiveBlock::from(&block))
                .collect(),
        ));
        let txos_ptr = Arc::new(Mutex::new(txos));
        Self {
            blocks: archive_blocks.into(),
            txos: txos_ptr,
        }
    }
}

// The only purpose of this struct is to be able to access the quorum testing
// logic implemented for SCPNetworkState.
pub struct OfflineNetworkState {
    scp_network_state: SCPNetworkState<ResponderId>,
}

impl OfflineNetworkState {
    pub fn new(config: &LightClientVerifierConfig) -> Self {
        let local_node_id = ResponderId::from_str(FAKE_NODE_ID).unwrap();
        Self {
            scp_network_state: SCPNetworkState::new(local_node_id, config.quorum_set.clone()),
        }
    }
}

impl NetworkState for OfflineNetworkState {
    /// Returns true if `connections` forms a blocking set for this node and, if
    /// the local node is included, a quorum.
    ///
    /// # Arguments
    /// * `responder_ids` - IDs of other nodes.
    fn is_blocking_and_quorum(&self, conn_ids: &HashSet<ResponderId>) -> bool {
        self.scp_network_state.is_blocking_and_quorum(conn_ids)
    }

    /// NOT USED
    fn is_behind(&self, _: BlockIndex) -> bool {
        unimplemented!("Node is not connected to the network")
    }

    /// NOT USED
    fn highest_block_index_on_network(&self) -> Option<BlockIndex> {
        unimplemented!("Node is not connected to the network")
    }
}

/// Group nodes according to the block they externalized.
/// These blocks should already be validated; in particular, we assume the
/// BlockID matches the hash of the BlockContents.
///
/// # Arguments
/// * `node_to_blocks` - mapping from ResponderId to Block
fn group_by_block(blocks: &Vec<BlockData>) -> HashMap<BlockID, HashSet<ResponderId>> {
    // This partitions nodes according to the contents of the
    // block they externalized.
    //
    // The BlockID is the hash of the entire block contents, which is why we can
    // group by it. Block IDs are verified before they are handed to this
    // function.

    let mut block_id_to_group: HashMap<BlockID, HashSet<ResponderId>> = HashMap::default();

    for block_data in blocks.iter() {
        let group = block_id_to_group
            .entry(block_data.block().id.clone())
            .or_insert_with(HashSet::default);
        group.insert(
            block_data
                .metadata()
                .unwrap()
                .contents()
                .responder_id()
                .clone(),
        );
    }
    block_id_to_group
}

// This checks that 'block' is valid, signed by the right node, and contains
// each output in the vector 'txos'. If so, it returns the BlockData.
fn verify_block_with_txos(
    block: &ArchiveBlock,
    txos: &Vec<TxOut>,
) -> Result<BlockData, VerifierError> {
    // The conversion function from ArchiveBlock to BlockData includes validation of
    // the block. In particular, it checks:
    // - the hash in the block header matches the hash of the block contents
    // - the signature on the block header is valid
    // - the signature on the BlockMetadata is valid.
    let block_data = BlockData::try_from(block).map_err(VerifierError::InvalidBlock)?;

    // The metadata and signature fields are optional, so let's make sure they're
    // present.
    if block_data.metadata().is_none() {
        return Err(VerifierError::MissingBlockMetadata);
    }
    if block_data.signature().is_none() {
        return Err(VerifierError::MissingBlockSignature);
    } else {
        let block_contents = block_data.contents();
        let mut missing_txos = Vec::<TxOut>::new();
        for txo in txos.iter() {
            // Verify that 'tx' is a TxOut occurring in 'block'.
            // FIXME: Is == the right comparison here?
            if !block_contents.outputs.iter().any(|tx| tx == txo) {
                missing_txos.push(txo.clone());
            }
        }
        if !missing_txos.is_empty() {
            Err(VerifierError::TxosNotFoundInBlock(missing_txos))
        } else {
            Ok(block_data)
        }
    }
}

fn verify_relayer_message(
    config: &LightClientVerifierConfig,
    message: &RelayerMessage,
) -> Result<(), VerifierError> {
    let network_state = OfflineNetworkState::new(config);
    let txos = message.txos.lock().expect("Failed to lock txos");
    let blocks = message.blocks.lock().expect("Failed to lock blocks");
    // Remove any blocks that fail validation.
    let good_blocks = group_by_block(
        blocks
            .iter()
            .filter_map(|block| verify_block_with_txos(block, txos.as_ref()).ok())
            .collect::<Vec<BlockData>>()
            .as_ref(),
    );
    if good_blocks.is_empty() {
        return Err(VerifierError::NoValidBlocks);
    } else {
        // It's possible that the network is forked, so that there are multiple BlockIDs
        // that correspond to blocks passing the above validation - in
        // particular, they all contain all of the TxOuts in `txos`.
        // This function returns Ok(()) if *any* of these BlockID's have been
        // externalized by a quorum of nodes.
        for (_block_id, responder_ids) in good_blocks.iter() {
            if network_state.is_blocking_and_quorum(responder_ids) {
                // It should be possible to sync with these nodes up to `block_id` at
                // `block_index`.
                //
                // Note: in the event of a network fork, there may be multiple distinct sets of
                // nodes that could be chosen here. Arbitrarily, we take the first such set of
                // nodes.
                return Ok(());
            }
        }
        Err(VerifierError::QuorumNotReached)
    }
}
