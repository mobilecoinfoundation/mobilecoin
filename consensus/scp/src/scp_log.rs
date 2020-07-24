// Copyright (c) 2018-2020 MobileCoin Inc.

//! This crate provides a logging framework for recording and replaying SCP messages.
use crate::{slot::SlotMetrics, Msg, QuorumSet, ScpNode, SlotIndex, Value};
use mc_common::NodeID;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, VecDeque},
    fs::{create_dir_all, read, read_dir, remove_dir_all, File},
    io::Write,
    marker::PhantomData,
    path::PathBuf,
};

use std::time::Instant;

/// A node specifically for logging SCP messages.
pub struct LoggingScpNode<V: Value, N: ScpNode<V>> {
    /// Output path.
    out_path: PathBuf,

    /// Highest slot number we've encountered so far.
    highest_slot_index: SlotIndex,

    /// Message counter counting how many messages we logged since we cleaned the directory.
    msg_count: usize,

    /// Time when we started logging for current slot.
    slot_start_time: Instant,

    /// Underlying node implementation.
    node: N,

    _v: PhantomData<V>,
}

/// Message types for logging.
#[derive(Serialize, Deserialize, Debug)]
pub enum LoggedMsg<V: Value> {
    /// Specifies the settings for this node.
    NodeSettings(NodeID, QuorumSet),

    /// An incoming message to this node.
    IncomingMsg(Msg<V>),

    /// An outgoing message from this node.
    OutgoingMsg(Msg<V>),

    /// A Nominate message.
    Nominate(SlotIndex, BTreeSet<V>),

    /// A timeout event.
    ProcessTimeouts(Vec<Msg<V>>),

    /// A message container for an arbitrary string.
    Marker(String),
}

/// A stored message.
#[derive(Serialize, Deserialize, Debug)]
pub struct StoredMsg<V: Value> {
    /// Milliseconds since the start of the slot.
    pub msec_since_start: u64,

    /// The message.
    pub msg: LoggedMsg<V>,
}

impl<V: Value, N: ScpNode<V>> LoggingScpNode<V, N> {
    /// Create a new LoggingScpNode.
    pub fn new(node: N, out_path: PathBuf) -> Result<Self, String> {
        if out_path.exists() {
            return Err(format!("{:?} already exists, refusing to re-use", out_path));
        }

        create_dir_all(out_path.clone())
            .map_err(|e| format!("Failed creating directory {:?}: {:?}", out_path, e))?;

        Ok(Self {
            node,
            out_path,
            highest_slot_index: 0,
            msg_count: 0,
            slot_start_time: Instant::now(),
            _v: Default::default(),
        })
    }

    fn write(&mut self, msg: LoggedMsg<V>) -> Result<(), String> {
        let msg_slot_index = match &msg {
            LoggedMsg::IncomingMsg(msg) | LoggedMsg::OutgoingMsg(msg) => msg.slot_index,
            LoggedMsg::Nominate(slot_index, _) => *slot_index,
            _ => self.highest_slot_index,
        };

        if msg_slot_index > self.highest_slot_index {
            // Switched to a newer slot, clean the output directory.
            remove_dir_all(&self.out_path)
                .map_err(|e| format!("failed emptying {:?}: {:?}", self.out_path, e))?;
            create_dir_all(&self.out_path)
                .map_err(|e| format!("Failed creating directory {:?}: {:?}", self.out_path, e))?;

            self.highest_slot_index = msg_slot_index;
            self.msg_count = 0;
            self.slot_start_time = Instant::now();

            let n: NodeID = self.node.node_id();
            self.write(LoggedMsg::NodeSettings(n, self.node.quorum_set()))?;
        }

        // If message if for a previous slot, ignore it.
        if msg_slot_index < self.highest_slot_index {
            return Ok(());
        }

        // Serialize and write to a log file.
        let data = StoredMsg {
            msec_since_start: (Instant::now() - self.slot_start_time).as_millis() as u64,
            msg,
        };
        let bytes =
            mc_util_serial::serialize(&data).map_err(|e| format!("failed serialize: {:?}", e))?;

        let mut file_path = self.out_path.clone();
        file_path.push(format!("{:08}", self.msg_count));
        self.msg_count += 1;

        let mut file = File::create(&file_path)
            .map_err(|e| format!("failed creating {:?}: {:?}", file_path, e))?;
        file.write_all(&bytes)
            .map_err(|e| format!("failed writing {:?}: {:?}", file_path, e))?;

        Ok(())
    }
}

impl<V: Value, N: ScpNode<V>> ScpNode<V> for LoggingScpNode<V, N> {
    fn node_id(&self) -> NodeID {
        self.node.node_id()
    }

    fn quorum_set(&self) -> QuorumSet {
        self.node.quorum_set()
    }

    fn propose_values(
        &mut self,
        slot_index: SlotIndex,
        values: BTreeSet<V>,
    ) -> Result<Option<Msg<V>>, String> {
        self.write(LoggedMsg::Nominate(slot_index, values.clone()))?;

        let out_msg = self.node.propose_values(slot_index, values)?;

        if let Some(ref msg) = out_msg {
            self.write(LoggedMsg::OutgoingMsg(msg.clone()))?;
        }

        Ok(out_msg)
    }

    fn handle(&mut self, msg: &Msg<V>) -> Result<Option<Msg<V>>, String> {
        self.write(LoggedMsg::IncomingMsg(msg.clone()))?;

        let out_msg = self.node.handle(msg)?;

        if let Some(ref msg) = out_msg {
            self.write(LoggedMsg::OutgoingMsg(msg.clone()))?;
        }

        Ok(out_msg)
    }

    fn get_externalized_values(&self, slot_index: SlotIndex) -> Vec<V> {
        self.node.get_externalized_values(slot_index)
    }

    fn has_externalized_values(&self, slot_index: SlotIndex) -> bool {
        self.node.has_externalized_values(slot_index)
    }

    fn process_timeouts(&mut self) -> Vec<Msg<V>> {
        let out_msgs = self.node.process_timeouts();

        if !out_msgs.is_empty() {
            self.write(LoggedMsg::ProcessTimeouts(out_msgs.clone()))
                .expect("failed writing");
        }

        out_msgs
    }

    fn get_slot_metrics(&mut self, slot_index: SlotIndex) -> Option<SlotMetrics> {
        self.node.get_slot_metrics(slot_index)
    }

    fn clear_pending_slots(&mut self) {
        self.node.clear_pending_slots()
    }
}

/// An SCP log reader, to read a series of SCP messages.
pub struct ScpLogReader<V: Value> {
    /// The log files to read.
    files: VecDeque<PathBuf>,

    _v: PhantomData<V>,
}

impl<V: Value> ScpLogReader<V> {
    /// Create a new ScpLogReader.
    pub fn new(path: &PathBuf) -> Result<Self, String> {
        let mut files: Vec<_> = read_dir(path)
            .map_err(|e| format!("failed reading dir {:?}: {:?}", path, e))?
            .filter_map(|entry| {
                let entry = entry.unwrap().path();
                if entry.is_file() {
                    Some(entry)
                } else {
                    None
                }
            })
            .collect();
        files.sort();

        Ok(Self {
            files: VecDeque::from(files),
            _v: Default::default(),
        })
    }
}

impl<V: serde::de::DeserializeOwned + Value> Iterator for ScpLogReader<V> {
    type Item = StoredMsg<V>;

    fn next(&mut self) -> Option<Self::Item> {
        let path = self.files.pop_front()?;
        let bytes = read(&path).unwrap_or_else(|_| panic!("failed reading {:?}", path));
        let data: Self::Item = mc_util_serial::deserialize(&bytes)
            .unwrap_or_else(|_| panic!("failed deserializing {:?}", path));
        Some(data)
    }
}
