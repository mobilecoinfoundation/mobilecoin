// Copyright (c) 2018-2021 The MobileCoin Foundation

//! A utility to play back SCP messages logged by `LoggingScpNode`.

use mc_common::{logger::log, NodeID};
use mc_consensus_scp::{
    scp_log::{LoggedMsg, ScpLogReader, StoredMsg},
    test_utils::{get_bounded_combine_fn, trivial_validity_fn},
    Msg, Node, QuorumSet, ScpNode, SlotIndex,
};
use mc_transaction_core::{constants::MAX_TRANSACTIONS_PER_BLOCK, tx::TxHash};
use mc_util_uri::ConsensusPeerUri as PeerUri;
use std::{
    collections::VecDeque, fmt, path::PathBuf, str::FromStr, sync::Arc, thread::sleep,
    time::Duration,
};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
pub struct Config {
    /// Node Id
    ///
    /// Should be specified with a PeerURI, with consensus-msg-key param
    /// provided
    #[structopt(long, parse(try_from_str=parse_node_id_from_uri))]
    pub node_id: Option<NodeID>,

    /// Quorum set.
    ///
    /// The quorum set is represented in JSON. For example:
    /// {"threshold":1,"members":[{"type":"Node","args":"node2.test.mobilecoin.
    /// com:8443"},{"type":"Node","args":"node3.test.mobilecoin.com:4843"}]}
    #[structopt(long, parse(try_from_str=parse_quorum_set_from_json))]
    pub quorum_set: Option<QuorumSet>,

    /// SCP debug dump.
    #[structopt(long, parse(from_os_str))]
    pub scp_debug_dump: PathBuf,
}

fn parse_quorum_set_from_json(src: &str) -> Result<QuorumSet, String> {
    let quorum_set: QuorumSet = serde_json::from_str(src)
        .map_err(|err| format!("Error parsing quorum set {}: {:?}", src, err))?;

    if !quorum_set.is_valid() {
        return Err(format!("Invalid quorum set: {:?}", quorum_set));
    }

    Ok(quorum_set)
}

fn parse_node_id_from_uri(src: &str) -> Result<NodeID, String> {
    let uri = PeerUri::from_str(src)
        .map_err(|err| format!("Could not get URI from param {}: {:?}", src, err))?;
    Ok(NodeID::from(&uri))
}

struct TransactionValidationError;
impl fmt::Display for TransactionValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("TransactionValidationError")
    }
}

fn main() {
    let (logger, _global_logger_guard) =
        mc_common::logger::create_app_logger(mc_common::logger::o!());
    let config = Config::from_args();

    let validity_fn = Arc::new(trivial_validity_fn);
    let combine_fn = Arc::new(get_bounded_combine_fn(MAX_TRANSACTIONS_PER_BLOCK));

    let mut scp_reader =
        ScpLogReader::<TxHash>::new(&config.scp_debug_dump).expect("failed creating ScpLogReader");

    // The first entry is expected to be a NodeSettings entry.
    let (node_id, quorum_set, slot_index) = match scp_reader.next() {
        Some(StoredMsg {
            msg: LoggedMsg::NodeSettings(node_id, quorum_set, slot_index),
            ..
        }) => (node_id, quorum_set, slot_index),
        _ => panic!("failed getting NodeSettings entry"),
    };

    // Allow config to override these.
    let local_node_id = config.node_id.clone().unwrap_or(node_id);
    let local_quorum_set = config.quorum_set.unwrap_or(quorum_set);

    // Create the simulated node.
    let mut scp_node = Node::new(
        local_node_id.clone(),
        local_quorum_set,
        validity_fn,
        combine_fn,
        slot_index,
        logger.clone(),
    );

    let mut prev_timestamp = 0;
    let mut sent_msgs: VecDeque<Msg<TxHash>> = VecDeque::new();
    let mut cur_slot_index: Option<SlotIndex> = None;
    for stored_msg in scp_reader {
        sleep(Duration::from_millis(
            stored_msg.msec_since_start - prev_timestamp,
        ));
        prev_timestamp = stored_msg.msec_since_start;

        log::trace!(
            logger,
            "------------------------------------------------------------"
        );
        log::trace!(logger, "processing {:?}", stored_msg.msg);

        match stored_msg.msg {
            LoggedMsg::NodeSettings(..) => {
                panic!("Unexpected NodeSettings entry");
            }

            LoggedMsg::IncomingMsg(msg) => {
                assert_eq!(msg.slot_index, cur_slot_index.unwrap_or(msg.slot_index));
                cur_slot_index = Some(msg.slot_index);

                if let Some(out_msg) = scp_node.handle_message(&msg).expect("scp handle failed") {
                    sent_msgs.push_back(out_msg);
                }
            }

            LoggedMsg::Nominate(slot_index, values) => {
                assert_eq!(slot_index, cur_slot_index.unwrap_or(slot_index));
                cur_slot_index = Some(slot_index);

                if let Some(out_msg) = scp_node
                    .propose_values(values)
                    .expect("scp nominate failed")
                {
                    sent_msgs.push_back(out_msg);
                }
            }

            LoggedMsg::OutgoingMsg(msg) => {
                assert_eq!(msg.slot_index, cur_slot_index.unwrap_or(msg.slot_index));
                assert_eq!(msg.sender_id, local_node_id);
                cur_slot_index = Some(msg.slot_index);

                let expected_msg = sent_msgs.pop_front().unwrap();
                assert_eq!(expected_msg, msg);
            }

            LoggedMsg::ProcessTimeouts(msgs) => {
                for msg in scp_node.process_timeouts() {
                    sent_msgs.push_back(msg);
                }

                for msg in msgs {
                    assert_eq!(msg.slot_index, cur_slot_index.unwrap_or(msg.slot_index));
                    assert_eq!(msg.sender_id, local_node_id);
                    cur_slot_index = Some(msg.slot_index);

                    let expected_msg = sent_msgs.pop_front().unwrap();
                    assert_eq!(expected_msg, msg);
                }
            }

            LoggedMsg::Marker(s) => {
                log::info!(logger, "MARKER: {}", s);
            }
        }
    }

    // Give log messages time to flush
    sleep(Duration::from_secs(1));
}
