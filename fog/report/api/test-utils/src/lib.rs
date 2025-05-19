// Copyright (c) 2018-2022 The MobileCoin Foundation

use prost::Message as ProstMessage;

/// Take two ProstMessage values.
///
/// Try to encode the first prost message, decode as the second prost message,
/// re-encode that, and decode as first prost again, and check that you got the
/// original value back. This ensures that the fields in the manually written,
/// prosty rust structure, are at least a subset of the fields in the .proto
/// file, so no data loss occurs if the client decodes using that .proto file.
pub fn round_trip_message<SRC: ProstMessage + Eq + Default, DEST: ProstMessage + Default>(
    prost_val: &SRC,
) {
    let prost_bytes = mc_util_serial::encode(prost_val);

    let dest_val =
        DEST::decode(prost_bytes.as_slice()).expect("Parsing protobuf from prost bytes failed");

    let protobuf_bytes = dest_val.encode_to_vec();

    let final_val: SRC = mc_util_serial::decode(&protobuf_bytes)
        .expect("Parsing prost back from protobuf bytes failed");

    assert_eq!(*prost_val, final_val);
}
