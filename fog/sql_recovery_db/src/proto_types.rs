// Copyright (c) 2018-2021 The MobileCoin Foundation

use mc_fog_types::ETxOutRecord;
use prost::Message;

/// Protobuf data stored with an ingested block record in sql
/// Having smaller tables (fewer entries which are bigger) is better for perf in
/// SQL
///
/// Block index, invocation id, and some other data are stored in postgres
/// along-side this data,
/// so they don't need to be duplicated in this proto.
#[derive(Message)]
pub struct ProtoIngestedBlockData {
    /// Any ETxOutRecord's that fog ingest emitted in connection to this block
    #[prost(repeated, message, tag = 1)]
    pub e_tx_out_records: Vec<ETxOutRecord>,
}
