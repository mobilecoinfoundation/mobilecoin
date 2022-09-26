// Copyright (c) 2018-2022 The MobileCoin Foundation

//! This crate provides a logging framework for recording and replaying SCP
//! messages.
use crate::{slot::SlotMetrics, Msg, QuorumSet, ScpNode, SlotIndex, Value};
use mc_common::NodeID;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, VecDeque},
    fs::{create_dir_all, read, read_dir, File},
    io::Write,
    marker::PhantomData,
    path::{Path, PathBuf},
    time::Instant,
};

/// A node specifically for logging SCP messages.
pub struct LoggingScpNode<V: Value, N: ScpNode<V>> {
    /// Output path for slot logs.
    out_path: PathBuf,

    /// Highest slot number we've encountered so far.
    highest_slot_index: SlotIndex,

    /// Message counter counting how many messages we logged for the current
    /// slot.
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
    NodeSettings(NodeID, QuorumSet, SlotIndex),

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

    /// Current slot state.
    pub state: String,
}

impl<V: Value, N: ScpNode<V>> LoggingScpNode<V, N> {
    /// Create a new LoggingScpNode.
    pub fn new(node: N, out_path: PathBuf) -> Result<Self, String> {
        // Create the output directory if it doesn't already exist
        if !out_path.exists() {
            create_dir_all(&out_path)
                .map_err(|e| format!("Failed creating directory {:?}: {:?}", out_path, e))?;
        }

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
        // Get current slot index based on the message being logged.
        let msg_slot_index = match &msg {
            LoggedMsg::IncomingMsg(msg) | LoggedMsg::OutgoingMsg(msg) => msg.slot_index,
            LoggedMsg::Nominate(slot_index, _) => *slot_index,
            _ => self.highest_slot_index,
        };

        // Directory for writing messages.
        let slot_out_path = self.out_path.join(format!("{:08}", msg_slot_index));
        if !slot_out_path.exists() {
            create_dir_all(&slot_out_path)
                .map_err(|e| format!("Failed creating directory {:?}: {:?}", slot_out_path, e))?;
        }

        if msg_slot_index > self.highest_slot_index {
            // Switched to a newer slot
            self.highest_slot_index = msg_slot_index;
            self.msg_count = 0;
            self.slot_start_time = Instant::now();

            self.write(LoggedMsg::NodeSettings(
                self.node.node_id(),
                self.node.quorum_set(),
                self.highest_slot_index,
            ))?;
        }

        // If message if for a previous slot, ignore it.
        if msg_slot_index < self.highest_slot_index {
            return Ok(());
        }

        // Serialize and write to a log file.
        let data = StoredMsg {
            msec_since_start: (Instant::now() - self.slot_start_time).as_millis() as u64,
            msg,
            state: self
                .get_slot_debug_snapshot(msg_slot_index)
                .unwrap_or_default(),
        };
        let data_json = serde_json::to_string_pretty(&data)
            .map_err(|e| format!("failed serialize: {:?}", e))?;

        let mut file_path = slot_out_path;
        file_path.push(format!("{:08}.json", self.msg_count));
        self.msg_count += 1;

        let mut file = File::create(&file_path)
            .map_err(|e| format!("failed creating {:?}: {:?}", file_path, e))?;
        file.write_all(data_json.as_bytes())
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

    fn propose_values(&mut self, values: BTreeSet<V>) -> Result<Option<Msg<V>>, String> {
        let slot_index = self.node.current_slot_index();
        self.write(LoggedMsg::Nominate(slot_index, values.clone()))?;
        let out_msg = self.node.propose_values(values)?;
        if let Some(ref msg) = out_msg {
            self.write(LoggedMsg::OutgoingMsg(msg.clone()))?;
        }

        Ok(out_msg)
    }

    fn handle_message(&mut self, msg: &Msg<V>) -> Result<Option<Msg<V>>, String> {
        self.write(LoggedMsg::IncomingMsg(msg.clone()))?;

        let response_opt = self.node.handle_message(msg)?;

        if let Some(ref response) = response_opt {
            self.write(LoggedMsg::OutgoingMsg(response.clone()))?;
        }

        Ok(response_opt)
    }

    fn handle_messages(
        &mut self,
        msgs: Vec<Msg<V, NodeID>>,
    ) -> Result<Vec<Msg<V, NodeID>>, String> {
        let mut responses = Vec::new();
        for msg in msgs {
            if let Some(response) = self.handle_message(&msg)? {
                responses.push(response)
            }
        }
        Ok(responses)
    }

    fn max_externalized_slots(&self) -> usize {
        self.node.max_externalized_slots()
    }

    fn set_max_externalized_slots(&mut self, n: usize) {
        self.node.set_max_externalized_slots(n)
    }

    fn get_externalized_values(&self, slot_index: SlotIndex) -> Option<Vec<V>> {
        self.node.get_externalized_values(slot_index)
    }

    fn process_timeouts(&mut self) -> Vec<Msg<V>> {
        let out_msgs = self.node.process_timeouts();

        if !out_msgs.is_empty() {
            self.write(LoggedMsg::ProcessTimeouts(out_msgs.clone()))
                .expect("failed writing");
        }

        out_msgs
    }

    fn current_slot_index(&self) -> u64 {
        self.node.current_slot_index()
    }

    fn get_current_slot_metrics(&mut self) -> SlotMetrics {
        self.node.get_current_slot_metrics()
    }

    fn get_slot_debug_snapshot(&mut self, slot_index: SlotIndex) -> Option<String> {
        self.node.get_slot_debug_snapshot(slot_index)
    }

    fn reset_slot_index(&mut self, slot_index: SlotIndex) {
        self.node.reset_slot_index(slot_index)
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
    pub fn new(path: &Path) -> Result<Self, String> {
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
