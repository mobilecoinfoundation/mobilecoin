// Copyright (c) 2018-2021 The MobileCoin Foundation

use prost::Message as ProstMessage;
use protobuf::Message as ProtobufMessage;

/// Take a ProstMessage value, and a ProtobufMessage type. Try to encode the
/// prost message, decode as protobuf, re-encode that, and decode as prost
/// again, and check that you got the original value back.
/// This ensures that the fields in the manually written, prosty rust structure,
/// are at least a subset of the fields in the .proto file, so no data loss
/// occurs if the client decodes using that .proto file.
///
/// We could have another version of this function that tests that the
/// ProtobufMessage round-trips through the prosty structure. That would ensure
/// that the struct and the .proto are identical. I haven't found that necessary
/// yet but maybe I'm wrong. It would have caught a subtle bug where we were
/// using external.TxOut instead of transaction.TxOut in the fog view proto.
pub fn round_trip_message<SRC: ProstMessage + Eq + Default, DEST: ProtobufMessage>(
    prost_val: &SRC,
) {
    let prost_bytes = mc_util_serial::encode(prost_val);

    let dest_val =
        DEST::parse_from_bytes(&prost_bytes).expect("Parsing protobuf from prost bytes failed");

    let protobuf_bytes = dest_val
        .write_to_bytes()
        .expect("Writing protobuf to bytes failed");

    let final_val: SRC = mc_util_serial::decode(&protobuf_bytes)
        .expect("Parsing prost back from protobuf bytes failed");

    assert_eq!(*prost_val, final_val);
}

pub fn round_trip_protobuf_object<SRC: ProtobufMessage + Eq, DEST: ProstMessage + Default>(
    protobuf_val: &SRC,
) {
    let protobuf_bytes = protobuf_val
        .write_to_bytes()
        .expect("Writing protobuf to bytes failed");

    let prost_val: DEST =
        mc_util_serial::decode(&protobuf_bytes).expect("Parsing prost from protobuf bytes failed");

    let prost_bytes = mc_util_serial::encode(&prost_val);

    let final_val =
        SRC::parse_from_bytes(&prost_bytes).expect("Parsing protobuf back from prost bytes failed");

    assert_eq!(*protobuf_val, final_val);
}
