// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Performs SCP validation on streams from multiple peers and merges them into
//! a single stream

use crate::streaming_futures::{Ready, Ready::NotReady};
use futures::{stream, Stream, StreamExt};
use mc_common::{
    logger::{log, Logger},
    NodeID,
};
use mc_consensus_scp::{GenericNodeId, QuorumSet, QuorumSetMember, SlotIndex};
use mc_ledger_streaming_api::{
    BlockStream, BlockStreamComponents, Error as StreamError, Result as StreamResult,
};
use mc_transaction_core::BlockID;
use std::{collections::HashMap, future};

/// SCP Validation streaming factor, this stream will take in a group of block
/// streams from individual peers and validate that they pass SCP consensus.
/// Note this will consume all other streams and return a single result
pub struct SCPValidator<US: BlockStream, ID: GenericNodeId + Send = NodeID> {
    upstreams: Vec<(ID, US)>,
    logger: Logger,
    scp_validation_state: SCPValidationState<ID>,
}

/// State of SCP validation
#[derive(Clone)]
pub struct SCPValidationState<ID: GenericNodeId + Send = NodeID> {
    /// The local node ID.
    local_node_id: ID,

    /// The quorum set of the node we are tracking state for.
    local_quorum_set: QuorumSet<ID>,

    /// Highest slot that a given node has externalized.
    slots_to_externalized_blocks: HashMap<SlotIndex, HashMap<ID, BlockStreamComponents>>,

    /// Highest block externalized
    highest_slot_index: SlotIndex,

    /// Num blocks externalized
    num_blocks_externalized: u64,

    /// Logger
    logger: Logger,
}

const MAX_BLOCK_DEFICIT: u64 = 50;

/// Helper trait to easily transform streams between two generic types
pub trait TransformStream<T> {
    /// Definition of what the output stream should look like
    type OutputStream;

    /// Optional modifier such as extra data
    type Modifier;

    /// Transform a stream from one predictable type to another
    fn transform_stream(&self, stream: T, modifier: Option<Self::Modifier>) -> Self::OutputStream;
}

impl<US: BlockStream, ID: GenericNodeId + Send> SCPValidator<US, ID> {
    /// Create new SCP validator stream factory
    pub fn new(
        upstreams: Vec<(ID, US)>,
        logger: Logger,
        local_node_id: ID,
        quorum_set: QuorumSet<ID>,
    ) -> Self {
        let scp_validation_state =
            SCPValidationState::new(local_node_id, quorum_set, logger.clone());
        Self {
            upstreams,
            logger,
            scp_validation_state,
        }
    }
}

impl<
        US: BlockStream + 'static,
        S: Stream<Item = StreamResult<BlockStreamComponents>>,
        ID: GenericNodeId + Send,
    > TransformStream<S> for SCPValidator<US, ID>
{
    type OutputStream = impl Stream<Item = (Self::Modifier, StreamResult<BlockStreamComponents>)>;
    type Modifier = ID;

    fn transform_stream(&self, stream: S, modifier: Option<Self::Modifier>) -> Self::OutputStream {
        stream.map(move |component| (modifier.clone().unwrap(), component))
    }
}

impl<ID: GenericNodeId + Send + Clone> SCPValidationState<ID> {
    /// Create new validator object
    pub fn new(local_node_id: ID, local_quorum_set: QuorumSet<ID>, logger: Logger) -> Self {
        Self {
            local_node_id,
            local_quorum_set,
            slots_to_externalized_blocks: HashMap::new(),
            highest_slot_index: 0,
            num_blocks_externalized: 0,
            logger,
        }
    }

    /// Fill slot with received component for certain block_height. If we've
    /// already recorded a block for that slot, discard it.
    pub fn update_slot(&mut self, node_id: ID, component: BlockStreamComponents) {
        let index = component.block_data.block().index;

        // If we've already externalized a block at this index, ignore it
        if index <= self.highest_slot_index && self.highest_slot_index > 0 {
            return;
        }

        // Otherwise associate it with the node it was received from
        if let std::collections::hash_map::Entry::Vacant(e) =
            self.slots_to_externalized_blocks.entry(index)
        {
            let mut node_map = HashMap::new();
            node_map.insert(node_id, component);
            e.insert(node_map);
        } else {
            let node_map = self.slots_to_externalized_blocks.get_mut(&index).unwrap();
            node_map.insert(node_id, component);
        }
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
    pub fn attempt_externalize_block(&mut self) -> Option<BlockStreamComponents> {
        // Set our target index one block above the highest block externalized
        // unless we're recording the genesis block
        let mut index = self.highest_slot_index + 1;
        if self.num_blocks_externalized == 0 && self.highest_slot_index == 0 {
            index = 0;
        }

        // If blocks received so far are less than a possible quorum, don't proceed
        if let Some(ballots) = self.slots_to_externalized_blocks.get(&index) {
            if self.local_quorum_set.threshold > ballots.len() as u32 {
                return None;
            }
        }

        // Else check for a quorum and see if the blocks externalized constitute a
        // quorum slice for this node
        let ballot_map = self.find_quorum(self.local_quorum_set.clone(), index);
        let block_id = self.get_quorum_slice_vote(self.local_quorum_set.threshold, &ballot_map);

        // If there's consensus among a quorum slice, return the block contents
        if let Some(block_id) = block_id {
            let winning_ballots = ballot_map.get(&block_id).unwrap();
            for ballot in winning_ballots {
                if let QuorumSetMember::Node(id) = ballot {
                    let mut blocks = self.slots_to_externalized_blocks.remove(&index).unwrap();
                    log::trace!(
                        self.logger,
                        "Node: {} found a quorum slice for block {}",
                        self.local_node_id,
                        self.highest_slot_index,
                    );

                    // Increment the highest block seen + the total number of
                    // blocks we've counted
                    let result = Some(blocks.remove(id).unwrap());
                    self.highest_slot_index += 1;
                    self.num_blocks_externalized += 1;
                    return result;
                }
            }
        }

        // If not let consumers know
        None
    }

    /// Check to find there's a quorum on the value of the blocks
    fn find_quorum(
        &self,
        quorum_set: QuorumSet<ID>,
        index: SlotIndex,
    ) -> HashMap<BlockID, Vec<QuorumSetMember<ID>>> {
        let mut ballot_map: HashMap<BlockID, Vec<QuorumSetMember<ID>>> = HashMap::new();
        let threshold = quorum_set.threshold;
        let mut nodes_counted = 0;

        // Determine if the blocks we've collected so far are a quorum slice
        if let Some(tracked_blocks) = self.slots_to_externalized_blocks.get(&index) {
            for member in quorum_set.members {
                // Go through our slice and determine what nodes sent blocks AND
                // what block they externalized
                match member.clone() {
                    QuorumSetMember::Node(node_id) => {
                        if let Some(component) = tracked_blocks.get(&node_id) {
                            let block_id = &component.block_data.block().id;
                            // Record a vote for the block externalized
                            ballot_map
                                .entry(block_id.clone())
                                .and_modify(|vec| vec.push(member.clone()))
                                .or_insert_with(|| vec![member.clone()]);
                            nodes_counted += 1;

                            // If we've counted a # of nodes above the threshold
                            // check for quorum
                            if nodes_counted >= threshold
                                // If quorum, stop early
                                && self.get_quorum_slice_vote(threshold, &ballot_map).is_some()
                            {
                                return ballot_map;
                            }
                        }
                    }
                    QuorumSetMember::InnerSet(qs) => {
                        // Recursively call ourselves to check nested sets
                        let sub_quorum = self.find_quorum(qs.clone(), index);

                        // If internal slice reached quorum, record the block voted for
                        if let Some(block_id) =
                            self.get_quorum_slice_vote(qs.threshold, &sub_quorum)
                        {
                            ballot_map
                                .entry(block_id)
                                .and_modify(|vec| vec.push(member.clone()))
                                .or_insert_with(|| vec![member.clone()]);
                            nodes_counted += 1;
                            if nodes_counted >= threshold
                                && self.get_quorum_slice_vote(threshold, &ballot_map).is_some()
                            {
                                return ballot_map;
                            }
                        }
                    }
                }
            }
        }
        ballot_map
    }

    /// Check the blocks the peers externalized for quorum
    pub fn get_quorum_slice_vote(
        &self,
        threshold: u32,
        ballot_map: &HashMap<BlockID, Vec<QuorumSetMember<ID>>>,
    ) -> Option<BlockID> {
        for key in ballot_map.keys() {
            if let Some(votes_for_key) = ballot_map.get(key) {
                if votes_for_key.len() >= threshold as usize {
                    return Some(key.clone());
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

impl<US: BlockStream + 'static, ID: GenericNodeId + Send> BlockStream for SCPValidator<US, ID> {
    type Stream = impl Stream<Item = StreamResult<BlockStreamComponents>>;

    /// Get block stream that performs validation
    fn get_block_stream(&self, starting_height: u64) -> StreamResult<Self::Stream> {
        // Merge all streams into one
        let mut merged_streams = stream::SelectAll::new();
        for stream_factory in &self.upstreams {
            let (node_id, upstream) = stream_factory;
            log::info!(self.logger, "Generating new stream from {:?}", node_id);
            let us = upstream.get_block_stream(starting_height).unwrap();
            merged_streams.push(Box::pin(self.transform_stream(us, Some(node_id.clone()))));
        }

        // Create SCP validation state object and insert it into stateful stream
        let mut validation_state = self.scp_validation_state.clone();
        if starting_height > 0 {
            validation_state.set_highest_externalized_slot(starting_height - 1);
        }

        Ok(merged_streams
            .scan(validation_state, |scp_state, (node_id, component)| {
                if let Ok(component) = component {
                    // Put component into underlying state
                    scp_state.update_slot(node_id, component);

                    // Attempt to externalize it if there's quorum
                    if let Some(component) = scp_state.attempt_externalize_block() {
                        return future::ready(Some(Ready::Ready(Ok(component))));
                    }
                }

                if scp_state.is_behind() {
                    return future::ready(Some(Ready::Ready(Err(StreamError::ConsensusBlocked(
                        scp_state.highest_externalized_slot(),
                        scp_state.highest_block_received(),
                    )))));
                }
                // If there's not quorum yet, forward NotReady to filter stream
                future::ready(Some(NotReady))
            })
            .filter_map(|result| {
                // If the component is in ready state forward it to next stream
                if let Ready::Ready(component) = result {
                    return future::ready(Some(component));
                }

                // If no ready message was received don't send anything onwards
                // (FilterMap streams don't forward None values)
                future::ready(None)
            }))
    }
}

#[cfg(test)]
mod tests {
    use mc_common::logger::{test_with_logger, Logger};
    use mc_consensus_scp::test_utils::test_node_id;
    use mc_ledger_streaming_api::test_utils::stream::SimpleMockStream;
    use mc_transaction_core::BlockIndex;

    use super::*;

    #[test_with_logger]
    fn scp_validates_nodes_in_quorum(logger: Logger) {
        let mut nodes = Vec::new();
        for i in 1..10 {
            nodes.push(test_node_id(i));
        }

        let quorum_set = QuorumSet::new(
            5,
            vec![
                QuorumSetMember::Node(nodes.get(0).unwrap().clone()),
                QuorumSetMember::Node(nodes.get(1).unwrap().clone()),
                QuorumSetMember::Node(nodes.get(2).unwrap().clone()),
                QuorumSetMember::Node(nodes.get(3).unwrap().clone()),
                QuorumSetMember::InnerSet(QuorumSet::new(
                    2,
                    vec![
                        QuorumSetMember::Node(nodes.get(4).unwrap().clone()),
                        QuorumSetMember::Node(nodes.get(5).unwrap().clone()),
                        QuorumSetMember::Node(nodes.get(6).unwrap().clone()),
                    ],
                )),
                QuorumSetMember::InnerSet(QuorumSet::new(
                    2,
                    vec![
                        QuorumSetMember::Node(nodes.get(7).unwrap().clone()),
                        QuorumSetMember::Node(nodes.get(8).unwrap().clone()),
                    ],
                )),
            ],
        );
        assert!(quorum_set.is_valid());
        let s = SimpleMockStream::new(100);
        let mut upstreams = Vec::new();
        for i in 0..9 {
            upstreams.push((nodes.get(i).unwrap().clone(), s.clone()));
        }
        let local_node_id = test_node_id(10);

        let validator = SCPValidator::new(upstreams, logger.clone(), local_node_id, quorum_set);

        futures::executor::block_on(async move {
            let mut scp_stream = validator.get_block_stream(0).unwrap();
            let mut index: BlockIndex = 0;
            while let Some(component) = scp_stream.next().await {
                index = component.unwrap().block_data.block().index;
            }
            assert_eq!(index, 99)
        });
    }
}
