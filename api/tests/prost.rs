//! Tests that prost-versions of structures round-trip with the versions
//! generated from external.proto

use maplit::btreemap;
use mc_account_keys::{AccountKey, PublicAddress, RootIdentity};
use mc_api::external;
use mc_fog_report_validation_test_utils::{FullyValidatedFogPubkey, MockFogResolver};
use mc_transaction_core::{Amount, BlockVersion, SignedContingentInput};
use mc_transaction_std::{
    test_utils::get_input_credentials, ChangeDestination, EmptyMemoBuilder,
    SignedContingentInputBuilder,
};
use mc_util_from_random::FromRandom;
use mc_util_test_helper::{run_with_several_seeds, CryptoRng, RngCore};
use prost::Message as ProstMessage;
use protobuf::Message as ProtobufMessage;

// Take a prost type and try to roundtrip it through a protobuf type
fn round_trip_message<SRC: ProstMessage + Eq + Default, DEST: ProtobufMessage>(prost_val: &SRC) {
    let prost_bytes = mc_util_serial::encode(prost_val);

    let dest_val =
        DEST::parse_from_bytes(&prost_bytes).expect("Parsing protobuf from prost bytes failed");

    let protobuf_bytes = dest_val
        .write_to_bytes()
        .expect("Writing protobuf to bytes failed");

    let final_val: SRC =
        mc_util_serial::decode(&protobuf_bytes).expect("Parsing prost from protobuf bytes failed");

    assert_eq!(*prost_val, final_val);
}

// Generate some example root identities
fn root_identity_examples<T: RngCore + CryptoRng>(rng: &mut T) -> Vec<RootIdentity> {
    vec![
        RootIdentity::from_random(rng),
        RootIdentity::random_with_fog(rng, "fog://example.com", "", &[]),
        RootIdentity::random_with_fog(rng, "fog://example.com", "", &[7u8, 7u8, 7u8, 7u8]),
        RootIdentity::random_with_fog(rng, "fog://example.com", "1", &[7u8, 7u8, 7u8, 7u8]),
        RootIdentity::random_with_fog(rng, "fog://example.com", "1", &[]),
    ]
}

// Signed contingent input examples
fn signed_contingent_input_examples<T: RngCore + CryptoRng>(
    block_version: BlockVersion,
    rng: &mut T,
) -> Vec<SignedContingentInput> {
    let mut result = Vec::new();

    let sender = AccountKey::random(rng);
    let recipient = AccountKey::random(rng).default_subaddress();
    let recipient2 = AccountKey::random_with_fog(rng).default_subaddress();
    let sender_change_dest = ChangeDestination::from(&sender);

    let fpr = MockFogResolver(btreemap! {
                        recipient2
                .fog_report_url()
                .unwrap()
                .to_string()
        =>
            FullyValidatedFogPubkey {
                pubkey: FromRandom::from_random(rng),
                pubkey_expiry: 1000,
            },
    });

    let input_credentials = get_input_credentials(
        block_version,
        Amount::new(200, 1.into()),
        &sender,
        &fpr,
        rng,
    );
    let mut builder = SignedContingentInputBuilder::new(
        block_version,
        input_credentials,
        vec![0u64, 1u64],
        fpr.clone(),
        EmptyMemoBuilder::default(),
    );
    builder
        .add_output(Amount::new(400, 0.into()), &recipient, rng)
        .unwrap();
    result.push(builder.build(rng).unwrap());

    let input_credentials = get_input_credentials(
        block_version,
        Amount::new(200, 1.into()),
        &sender,
        &fpr,
        rng,
    );
    let mut builder = SignedContingentInputBuilder::new(
        block_version,
        input_credentials,
        vec![0u64, 1u64],
        fpr.clone(),
        EmptyMemoBuilder::default(),
    );
    builder
        .add_output(Amount::new(400, 0.into()), &recipient, rng)
        .unwrap();
    builder
        .add_output(Amount::new(600, 2.into()), &recipient2, rng)
        .unwrap();
    result.push(builder.build(rng).unwrap());

    let input_credentials = get_input_credentials(
        block_version,
        Amount::new(300, 1.into()),
        &sender,
        &fpr,
        rng,
    );
    let mut builder = SignedContingentInputBuilder::new(
        block_version,
        input_credentials,
        vec![0u64, 1u64],
        fpr.clone(),
        EmptyMemoBuilder::default(),
    );
    builder
        .add_output(Amount::new(400, 0.into()), &recipient, rng)
        .unwrap();
    builder
        .add_output(Amount::new(600, 2.into()), &recipient2, rng)
        .unwrap();
    builder
        .add_change_output(Amount::new(100, 1.into()), &sender_change_dest, rng)
        .unwrap();
    result.push(builder.build(rng).unwrap());

    result
}

// Test that RootIdentity roundtrips through .proto structure
#[test]
fn root_identity_round_trip() {
    run_with_several_seeds(|mut rng| {
        for example in root_identity_examples(&mut rng).iter() {
            round_trip_message::<RootIdentity, external::RootIdentity>(example);
        }
    })
}

// Test that AccountKey roundtrips through .proto structure
#[test]
fn account_key_round_trip() {
    run_with_several_seeds(|mut rng| {
        for example in root_identity_examples(&mut rng).iter() {
            round_trip_message::<AccountKey, external::AccountKey>(&AccountKey::from(example));
        }
    })
}

// Test that PublicAddress roundtrips through .proto structure
#[test]
fn public_address_round_trip() {
    run_with_several_seeds(|mut rng| {
        for example in root_identity_examples(&mut rng).iter() {
            round_trip_message::<PublicAddress, external::PublicAddress>(
                &AccountKey::from(example).default_subaddress(),
            );
        }
    })
}

// Test that a SignedContingentInput round trips through .proto structure
#[test]
fn signed_contingent_input_round_trip() {
    run_with_several_seeds(|mut rng| {
        for block_version in BlockVersion::iterator().skip(3) {
            for example in signed_contingent_input_examples(block_version, &mut rng) {
                round_trip_message::<SignedContingentInput, external::SignedContingentInput>(
                    &example,
                );
            }
        }
    })
}
