// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Performs SCP validation on streams from multiple peers and merges them into
//! a single stream

use futures::{stream, Stream, StreamExt};
use hashbrown::HashMap;
use mc_blockchain_types::BlockID;
use mc_common::{
    logger::{log, Logger},
    NodeID,
};
use mc_ledger_streaming_api::{BlockData, BlockIndex, Error, Result, Streamer};
use std::{fmt, future};

const MAX_BLOCK_DEFICIT: u64 = 50;

pub use mc_consensus_scp_types::{GenericNodeId, QuorumSet, QuorumSetMember, SlotIndex};

/// SCP Validation stream factory, this factory takes in a group of
/// streams from individual peers and validate that they pass SCP consensus.
/// Note this will consume all other streams and return a single result
#[derive(Debug)]
pub struct SCPValidator<
    US: Streamer<Result<BlockData>, BlockIndex> + 'static,
    ID: GenericNodeId + Send = NodeID,
> {
    upstreams: HashMap<ID, US>,
    scp_validation_state: SCPValidationState<ID>,
    logger: Logger,
}

impl<US: Streamer<Result<BlockData>, BlockIndex> + 'static, ID: GenericNodeId + Send>
    SCPValidator<US, ID>
{
    /// Create new SCP validator stream factory
    pub fn new(upstreams: HashMap<ID, US>, quorum_set: QuorumSet<ID>, logger: Logger) -> Self {
        let scp_validation_state = SCPValidationState::new(quorum_set, logger.clone());
        Self {
            upstreams,
            scp_validation_state,
            logger,
        }
    }
}

/// State of SCP validation
#[derive(Clone)]
pub struct SCPValidationState<ID: GenericNodeId + Send = NodeID> {
    /// The quorum set of the node we are tracking state for.
    local_quorum_set: QuorumSet<ID>,

    /// Highest slot that a given node has externalized.
    slots_to_externalized_blocks: HashMap<SlotIndex, HashMap<ID, BlockData>>,

    /// Highest block externalized
    highest_slot_index: SlotIndex,

    /// Num blocks externalized
    num_blocks_externalized: u64,

    /// Logger
    logger: Logger,
}

impl<ID: GenericNodeId + Send> SCPValidationState<ID> {
    /// Create new validator object
    pub fn new(local_quorum_set: QuorumSet<ID>, logger: Logger) -> Self {
        Self {
            local_quorum_set,
            slots_to_externalized_blocks: HashMap::new(),
            highest_slot_index: 0,
            num_blocks_externalized: 0,
            logger,
        }
    }

    /// Fill slot with received BlockData for certain block_height. If we've
    /// already recorded a block for that slot, discard it.
    pub fn update_slot(&mut self, node_id: ID, block_data: BlockData) {
        let index = block_data.block().index;

        // If we've already externalized a block at this index, ignore it
        if index < self.highest_slot_index && self.highest_slot_index > 0 {
            return;
        }

        // Otherwise associate it with the node it was received from
        self.slots_to_externalized_blocks
            .entry(index)
            .or_default()
            .insert(node_id, block_data);
    }

    /// After block is externalized, remove records at previous slot
    pub fn set_highest_externalized_slot(&mut self, index: SlotIndex) {
        self.highest_slot_index = index;
    }

    /// Highest slot currently externalized by the stream
    pub fn highest_externalized_slot(&self) -> SlotIndex {
        self.highest_slot_index
    }

    /// Determine if we can externalize a block, if so return the block
    pub fn attempt_externalize_block(&mut self) -> Option<BlockData> {
        // Set our target index one block above the highest block externalized
        // unless we're recording the genesis block
        let index = if self.num_blocks_externalized == 0 && self.highest_slot_index == 0 {
            0
        } else {
            self.highest_slot_index + 1
        };

        // If blocks received so far are less than a possible quorum, don't proceed
        if let Some(ballots) = self.slots_to_externalized_blocks.get(&index) {
            if self.local_quorum_set.threshold > ballots.len() as u32 {
                return None;
            }
        }

        // Else check for a quorum and see if the blocks externalized constitute a
        // quorum slice for this node
        let mut selected_node = None;
        if let Some(block_id) = self.find_quorum(&self.local_quorum_set, index) {
            let blocks = self.slots_to_externalized_blocks.get(&index).unwrap();
            for (node_id, block_data) in blocks {
                if &block_data.block().id == block_id {
                    selected_node = Some(node_id.clone());
                    break;
                }
            }
        }

        // If we found quorum and a matching block, return it
        if let Some(selected_node) = selected_node {
            let mut blocks = self.slots_to_externalized_blocks.remove(&index).unwrap();
            log::trace!(
                self.logger,
                "SCP found a quorum slice for block {}",
                self.highest_slot_index,
            );

            // Increment our targets
            self.highest_slot_index += 1;
            self.num_blocks_externalized += 1;
            return blocks.remove(&selected_node);
        }

        // If not let consumers know
        None
    }

    /// Check to find there's a quorum on the value of the blocks
    fn find_quorum<'a>(
        &'a self,
        quorum_set: &'a QuorumSet<ID>,
        index: SlotIndex,
    ) -> Option<&'a BlockID> {
        let mut ballot_map: HashMap<&'a BlockID, Vec<&'a QuorumSetMember<ID>>> = HashMap::new();
        let threshold = quorum_set.threshold;
        let mut nodes_counted = 0;

        // Determine if the blocks we've collected so far are a quorum slice
        if let Some(tracked_blocks) = self.slots_to_externalized_blocks.get(&index) {
            for member in &quorum_set.members {
                let member = member.as_ref();
                // Go through our slice and determine what nodes sent blocks AND
                // what block they externalized
                match member {
                    Some(node @ QuorumSetMember::Node(node_id)) => {
                        if let Some(block_data) = tracked_blocks.get(node_id) {
                            // Record a vote for the block externalized
                            ballot_map
                                .entry(&block_data.block().id)
                                .or_default()
                                .push(node);
                            nodes_counted += 1;

                            // If we've counted a # of nodes above the threshold
                            // check for quorum
                            if nodes_counted >= threshold {
                                for (key, votes_for_key) in &ballot_map {
                                    if votes_for_key.len() >= threshold as usize {
                                        return Some(*key);
                                    }
                                }
                            }
                        }
                    }
                    Some(inner_set @ QuorumSetMember::InnerSet(qs)) => {
                        // If internal slice reached quorum, record the block voted for
                        if let Some(block_id) = self.find_quorum(qs, index) {
                            ballot_map.entry(block_id).or_default().push(inner_set);
                            nodes_counted += 1;
                            if nodes_counted >= threshold {
                                for (key, votes_for_key) in &ballot_map {
                                    if votes_for_key.len() >= threshold as usize {
                                        return Some(*key);
                                    }
                                }
                            }
                        }
                    }
                    None => {}
                }
            }
        }
        None
    }

    /// Get highest block received
    pub fn highest_block_received(&self) -> u64 {
        *self
            .slots_to_externalized_blocks
            .keys()
            .max()
            .unwrap_or(&self.highest_slot_index)
    }

    /// Check if our recorded quorum is lagging behind what we've received
    pub fn is_behind(&self) -> bool {
        self.highest_block_received() - self.highest_slot_index > MAX_BLOCK_DEFICIT
    }
}

impl<ID: GenericNodeId + Send> fmt::Debug for SCPValidationState<ID> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SCPValidationState")
            .field("highest_slot_index", &self.highest_slot_index)
            .field("num_blocks_externalized", &self.num_blocks_externalized)
            .field(
                "slots_to_externalized_blocks",
                &self
                    .slots_to_externalized_blocks
                    .iter()
                    .map(|(slot_id, blocks)| {
                        (
                            slot_id,
                            blocks
                                .iter()
                                .map(|(node_id, block_data)| {
                                    (
                                        node_id.to_string(),
                                        format!("block with index {}", block_data.block().index),
                                    )
                                })
                                .collect::<HashMap<_, _>>(),
                        )
                    })
                    .collect::<HashMap<_, _>>(),
            )
            .field("local_quorum_set", &self.local_quorum_set)
            .field("logger", &self.logger)
            .finish()
    }
}

/// Enum to allow monadic results other than Some & None for
/// stream types were None would terminate the stream. Useful for
/// stream combinations like Scan --> Filter_Map
pub enum Ready<T> {
    /// Value with data container to indicate a value is ready
    Ready(T),

    /// Indicates to subsequent future/stream upstream is not ready
    NotReady,
}

impl<US: Streamer<Result<BlockData>, BlockIndex> + 'static, ID: GenericNodeId + Send>
    Streamer<Result<BlockData>, BlockIndex> for SCPValidator<US, ID>
{
    type Stream<'s> = impl Stream<Item = Result<BlockData>> + 's where ID: 's;

    /// Get block stream that performs validation
    fn get_stream(&self, starting_height: BlockIndex) -> Result<Self::Stream<'_>> {
        // Merge all streams into one
        let mut merged_streams = stream::SelectAll::new();
        for stream_factory in &self.upstreams {
            let (node_id, upstream) = stream_factory;
            log::info!(self.logger, "Generating new stream from {:?}", node_id);
            let us = upstream.get_stream(starting_height)?;
            let peer_id = node_id.clone();
            merged_streams.push(Box::pin(us.map(move |result| (peer_id.clone(), result))));
        }

        // Create SCP validation state object and insert it into stateful stream
        let mut validation_state = self.scp_validation_state.clone();
        if starting_height > 0 {
            validation_state.set_highest_externalized_slot(starting_height - 1);
        }

        let logger = self.logger.clone();
        Ok(merged_streams
            .scan(validation_state, move |scp_state, (node_id, result)| {
                log::info!(
                    &logger,
                    "SCPValidator got {:?} with state {:?}",
                    result
                        .as_ref()
                        .map(|block_data| format!("block with index {}", block_data.block().index)),
                    scp_state
                );
                if let Ok(block_data) = result {
                    // Put block into underlying state
                    scp_state.update_slot(node_id, block_data);

                    // Attempt to externalize it if there's quorum
                    if let Some(block_data) = scp_state.attempt_externalize_block() {
                        return future::ready(Some(Ready::Ready(Ok(block_data))));
                    }
                }

                if scp_state.is_behind() {
                    return future::ready(Some(Ready::Ready(Err(Error::ConsensusBlocked(
                        scp_state.highest_externalized_slot(),
                        scp_state.highest_block_received(),
                    )))));
                }
                // If there's not quorum yet, forward NotReady to filter stream
                future::ready(Some(Ready::NotReady))
            })
            .filter_map(|result| {
                // If the block data is in ready state forward it to next stream
                if let Ready::Ready(result) = result {
                    return future::ready(Some(result));
                }

                // If no ready message was received don't send anything onwards
                // (FilterMap streams don't forward None values)
                future::ready(None)
            }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_common::logger::{test_with_logger, Logger};
    use mc_ledger_streaming_api::test_utils::{make_blocks, test_node_id, MockStream};

    #[test_with_logger]
    fn scp_validates_nodes_in_quorum(logger: Logger) {
        let nodes = (1..10).map(test_node_id).collect::<Vec<_>>();

        let quorum_set = QuorumSet::new(
            5,
            vec![
                QuorumSetMember::Node(nodes[0].clone()),
                QuorumSetMember::Node(nodes[1].clone()),
                QuorumSetMember::Node(nodes[2].clone()),
                QuorumSetMember::Node(nodes[3].clone()),
                QuorumSetMember::InnerSet(QuorumSet::new(
                    2,
                    vec![
                        QuorumSetMember::Node(nodes[4].clone()),
                        QuorumSetMember::Node(nodes[5].clone()),
                        QuorumSetMember::Node(nodes[6].clone()),
                    ],
                )),
                QuorumSetMember::InnerSet(QuorumSet::new(
                    2,
                    vec![
                        QuorumSetMember::Node(nodes[7].clone()),
                        QuorumSetMember::Node(nodes[8].clone()),
                    ],
                )),
            ],
        );
        assert!(quorum_set.is_valid());

        let blocks = make_blocks(100);
        let s = MockStream::from_blocks(blocks);
        let mut upstreams = HashMap::new();
        for i in 0..9 {
            upstreams.insert(nodes[i].clone(), s.clone());
        }
        let validator = SCPValidator::new(upstreams, quorum_set, logger);

        futures::executor::block_on(async move {
            let mut scp_stream = validator.get_stream(0).unwrap();
            let mut index: BlockIndex = 0;
            while let Some(result) = scp_stream.next().await {
                index = result.unwrap().block().index;
            }
            assert_eq!(index, 19)
        });
    }
}
