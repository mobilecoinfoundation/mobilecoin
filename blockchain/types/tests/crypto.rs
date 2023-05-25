//! Testing cryptography helpers.
//!
//! We assume signing, context changes, mutability, etc. is tested at lower
//! level, and just do a round-trip.

use mc_blockchain_test_utils::{make_block_id, make_block_metadata_contents};
use mc_blockchain_types::crypto::metadata::{MetadataSigner, MetadataVerifier};
use mc_crypto_keys::Ed25519Pair;
use mc_util_from_random::FromRandom;
use mc_util_test_helper::run_with_several_seeds;

#[test]
fn block_metadata() {
    run_with_several_seeds(|mut csprng| {
        let rng = &mut csprng;
        let block_id = make_block_id(rng);
        let contents = make_block_metadata_contents(block_id, rng);
        let signer = Ed25519Pair::from_random(rng);

        let sig = signer
            .sign_metadata(&contents)
            .expect("Could not sign metadata contents");

        signer
            .public_key()
            .verify_metadata(&contents, &sig)
            .expect("Could not verify signature over metadata contents");
    })
}
