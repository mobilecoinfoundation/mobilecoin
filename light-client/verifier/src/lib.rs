use mc_api::blockchain::ArchiveBlock;
use mc_blockchain_types::BlockData;
use mc_common::ResponderId;
use mc_ledger_sync::{NetworkState, SCPNetworkState}; 
use crate::config::LightClientVerifierConfig;

const FAKE_NODE_ID: &str = "fake:7777"

// This is what the verifier will receive from the relayer
#!derive[Clone, Debug]
pub struct RelayerMessage: {
    // This map should include each node's signed copy of the block containing 'tx'.
    pub blocks: Arc<Mutex<HashMap<ResponderId, ArchiveBlock>>>,
    pub txo: TxOut,    
}

impl RelayerMessage {
    fn new(block: &BlockData, tx: TxOut) -> Self {
        Self { block: ArchiveBlock::from(block), txo }
    }
}
// The only purpose of this struct is to be able to access the quorum testing logic implemented for SCPNetworkState.
pub struct OfflineNetworkState: {
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
    fn is_behind(&self, local_block_index: BlockIndex) -> bool {
        unimplemented!("Node is not connected to the network")
    }

    /// NOT USED
    fn highest_block_index_on_network(&self) -> Option<BlockIndex> {
        unimplemented!("Node is not connected to the network")
    }
}


/// Group nodes according to the block they externalized.
/// These blocks should already be validated; in particular, we assume the BlockID matches the hash of the BlockContents.
///
/// # Arguments
/// * `node_to_blocks` - mapping from ResponderId to Block
fn group_by_block(
    node_to_block: &HashMap<ResponderId, Block>,
) -> HashMap<BlockID, HashSet<ResponderId>> {
    // This partitions nodes according to the contents of the
    // block they externalized. 
    //
    // The BlockID is the hash of the entire block contents, which is why we can
    // group by it. Block IDs are verified before they are handed to this
    // function.

    let block_id_to_group: &mut HashMap<BlockID, HashSet<ResponderId>> =
        HashMap::default();

    for (responder_id, block) in node_to_block.iter() {
            let group: &mut HashSet<ResponderId> = block_id_to_group
                .entry(block.id.clone())
                .or_insert_with(HashSet::default);
            group.insert(responder_id.clone());
        }
    }
    block_id_to_group
}


// This checks that the block is valid, signed by the right node, and contains the transaction.
fn verify_block_with_txo(block: ArchiveBlock, &txo: TxOut) -> Result<Block, Error> {
    // The conversion function from ArchiveBlock to BlockData includes validation of the block: 
    // in particular, it checks that the block hash matches the hash of the block contents,
    // and that the signature on the BlockMetadata is valid.
    let block_data = BlockData::try_from(block).unwrap()?;

    // The metadata and signature fields are optional, so let's make sure they're present.
    if block_data.metadata.is_none() {
        return Err(Error::MissingBlockMetadata);
    }
    if block_data.signature.is_none() {
        return Err(Error::MissingBlockSignature);
    } else {
        block_data.clone()
    }

    let block_contents = block_data.contents();
    // Verify that 'tx' is a TxOut occurring in 'block'.
    if block_contents.outputs.iter().any(|tx| tx.id == txo.id) {
        Ok(block_data.block.clone())
    } else {
        Err(Error::TxoNotFoundInBlock)
    }
}

fn verify_relayer_message(message: &RelayerMessage) -> Result<(), Error> {
    let txo = message.txo;
    let mut blocks = message.blocks.lock().expect("Failed to lock blocks");
    // Remove any blocks that fail validation.
    let good_blocks = blocks.map(|block| verify_block_with_txo(block, &txo)).collect().retain(|block| block.is_ok());
    if good_blocks.is_empty() {
        return Err(Error::NoValidBlocks);
    } else {
        for (block_id, responder_ids) in good_blocks.iter() {
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
        Err(Error::QuorumNotReached)
        }
}

