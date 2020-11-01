// Copyright (c) 2018-2020 MobileCoin Inc.

mod validated_chain;
mod verify;
pub use validated_chain::{parse_keypair_from_pem, Chain, ValidatedChain};
pub use verify::{verify_fog_authority, ReportAuthorityError};

use mc_crypto_digestible::Digestible;
use prost::Message;
use serde::{Deserialize, Serialize};
use std::{string::String, vec::Vec}; // FIXME: alloc if no_std

// Prost proto schema types
// These are synced with types in fog_api report.proto, and tests enforce that they round trip
// These are NOT expected to be synced with Db schema types

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Digestible, Message)]
pub struct ProstReport {
    #[prost(string, tag = "1")]
    pub fog_report_id: String,

    #[prost(bytes, required, tag = "2")]
    pub report: Vec<u8>,

    #[prost(fixed64, required, tag = "3")]
    pub pubkey_expiry: u64,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Digestible, Message)]
pub struct ProstReports {
    #[prost(message, repeated, tag = "1")]
    pub reports: Vec<ProstReport>,
}

// Conversions

#[cfg(test)]
mod tests {
    use super::*;

    use mc_fog_api;
    use mc_util_test_helper::{run_with_several_seeds, RngCore};
    use prost::Message as ProstMessage;
    use protobuf::Message as ProtobufMessage;
    use rand::{distributions::Alphanumeric, Rng};

    /// Take a ProstMessage value, and a ProtobufMessage type. Try to encode the prost message,
    /// decode as protobuf, re-encode that, and decode as prost again, and check that you got the
    /// original value back.
    /// This ensures that the fields in the manually written, prosty rust structure,
    /// are at least a subset of the fields in the .proto file, so no data loss occurs if the client
    /// decodes using that .proto file.
    ///
    /// We could have another version of this function that tests that the ProtobufMessage round-trips
    /// through the prosty structure. That would ensure that the struct and the .proto are identical.
    fn round_trip_message<SRC: ProstMessage + Eq + Default, DEST: ProtobufMessage>(
        prost_val: &SRC,
    ) {
        let prost_bytes = mc_util_serial::encode(prost_val);

        let dest_val: DEST = protobuf::parse_from_bytes(&prost_bytes)
            .expect("Parsing protobuf from prost bytes failed");

        let protobuf_bytes = dest_val
            .write_to_bytes()
            .expect("Writing protobuf to bytes failed");

        let final_val: SRC = mc_util_serial::decode(&protobuf_bytes)
            .expect("Parsing prost from protobuf bytes failed");

        assert_eq!(*prost_val, final_val);
    }

    /// Test that many random instances of ProstReport round trip with mc_fog_api::report::Report
    #[test]
    fn report_round_trip() {
        {
            let test_val: ProstReport = Default::default();
            round_trip_message::<ProstReport, mc_fog_api::report::Report>(&test_val);
        }

        run_with_several_seeds(|mut rng| {
            let test_val = ProstReport {
                fog_report_id: rng.clone().sample_iter(&Alphanumeric).take(3).collect(),
                report: rng.gen::<[u8; 32]>().to_vec(),
                pubkey_expiry: rng.next_u64(),
            };

            round_trip_message::<ProstReport, mc_fog_api::report::Report>(&test_val);
        });
    }

    // FIXME: Add ProstReportResponse
}
