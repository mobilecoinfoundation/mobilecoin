// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Tests that prost-versions of structures round-trip with the versions
//! generated from external.proto

use maplit::btreemap;
use mc_account_keys::{AccountKey, PublicAddress, RootIdentity};
use mc_api::{blockchain, external, quorum_set};
use mc_attest_verifier_types::VerificationReport;
use mc_blockchain_types::{BlockID, BlockMetadata, BlockMetadataContents, BlockVersion, QuorumSet};
use mc_consensus_scp::test_utils::test_node_id;
use mc_crypto_keys::Ed25519Pair;
use mc_crypto_ring_signature_signer::NoKeysRingSigner;
use mc_fog_report_validation_test_utils::{FullyValidatedFogPubkey, MockFogResolver};
use mc_transaction_core::{Amount, SignedContingentInput};
use mc_transaction_std::{
    test_utils::get_input_credentials, EmptyMemoBuilder, ReservedSubaddresses,
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

fn random_bytes_vec<RNG: RngCore + CryptoRng>(num_bytes: usize, rng: &mut RNG) -> Vec<u8> {
    let mut result = Vec::with_capacity(num_bytes);
    rng.fill_bytes(&mut result);
    result
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
    let sender_change_dest = ReservedSubaddresses::from(&sender);

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
        fpr.clone(),
        EmptyMemoBuilder::default(),
    )
    .unwrap();
    builder
        .add_required_output(Amount::new(400, 0.into()), &recipient, rng)
        .unwrap();
    result.push(builder.build(&NoKeysRingSigner {}, rng).unwrap());

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
        fpr.clone(),
        EmptyMemoBuilder::default(),
    )
    .unwrap();
    builder
        .add_required_output(Amount::new(400, 0.into()), &recipient, rng)
        .unwrap();
    builder
        .add_required_output(Amount::new(600, 2.into()), &recipient2, rng)
        .unwrap();
    result.push(builder.build(&NoKeysRingSigner {}, rng).unwrap());

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
        fpr.clone(),
        EmptyMemoBuilder::default(),
    )
    .unwrap();
    builder
        .add_required_output(Amount::new(400, 0.into()), &recipient, rng)
        .unwrap();
    builder
        .add_required_output(Amount::new(600, 2.into()), &recipient2, rng)
        .unwrap();
    builder
        .add_required_change_output(Amount::new(100, 1.into()), &sender_change_dest, rng)
        .unwrap();
    result.push(builder.build(&NoKeysRingSigner {}, rng).unwrap());

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

fn make_quorum_set<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> QuorumSet {
    let n = rng.next_u32() % 20 + 3; // n in [3, 22]
    let threshold = rng.next_u32() % n + 1; // [1, n]
    let node_ids = (0..n).map(|x| (&test_node_id(x)).into()).collect();
    QuorumSet::new_with_node_ids(threshold, node_ids)
}

#[test]
fn quorum_set_round_trip() {
    run_with_several_seeds(|mut rng| {
        round_trip_message::<QuorumSet, quorum_set::QuorumSet>(&make_quorum_set(&mut rng))
    })
}

fn make_verification_report<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> VerificationReport {
    let sig = random_bytes_vec(42, rng).into();
    let chain_len = rng.next_u32() % 40 + 2; // in [2, 41]
    let chain = (1..=chain_len)
        .map(|n| random_bytes_vec(n as usize, rng))
        .collect();
    VerificationReport {
        sig,
        chain,
        http_body: "testing".to_owned(),
    }
}

fn make_block_metadata<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> BlockMetadata {
    let signer = Ed25519Pair::from_random(rng);
    let contents = BlockMetadataContents::new(
        BlockID(FromRandom::from_random(rng)),
        Some(make_quorum_set(rng)),
        Some(make_verification_report(rng)),
    );

    BlockMetadata::from_contents_and_keypair(contents, &signer)
        .expect("SignedBlockMetadata::from_contents_and_keypair")
}

#[test]
fn block_metadata_round_trip() {
    run_with_several_seeds(|mut rng| {
        let metadata = make_block_metadata(&mut rng);
        round_trip_message::<BlockMetadata, blockchain::BlockMetadata>(&metadata);
    })
}
