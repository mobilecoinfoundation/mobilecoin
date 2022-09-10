// Copyright (c) 2018-2022 The MobileCoin Foundation

mod util;

use mc_account_keys::AccountKey;
use mc_crypto_ring_signature_signer::NoKeysRingSigner;
use mc_fog_report_validation_test_utils::MockFogResolver;
use mc_transaction_core::{
    constants::MILLIMOB_TO_PICOMOB, tokens::Mob, Amount, BlockVersion, Token,
};
use mc_transaction_std::{
    test_utils::get_input_credentials, EmptyMemoBuilder, ReservedSubaddresses,
    SignedContingentInputBuilder,
};
use rand::{rngs::StdRng, SeedableRng};

#[test]
// Test that fill_to_fractional_output_at is working as expected
fn test_fill_to_fractional_output_at() {
    let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

    for block_version in 3..=*BlockVersion::MAX {
        let block_version = BlockVersion::try_from(block_version).unwrap();

        let sender = AccountKey::random(&mut rng);

        let fog_resolver = MockFogResolver(Default::default());

        let value = 1475 * MILLIMOB_TO_PICOMOB;
        let amount = Amount::new(value, Mob::ID);
        let amount2 = Amount::new(100_000, 2.into());

        let input_credentials =
            get_input_credentials(block_version, amount, &sender, &fog_resolver, &mut rng);

        let mut builder = SignedContingentInputBuilder::new(
            block_version,
            input_credentials,
            fog_resolver,
            EmptyMemoBuilder::default(),
        )
        .unwrap();

        builder
            .add_fractional_change_output(amount, &ReservedSubaddresses::from(&sender), &mut rng)
            .unwrap();

        builder
            .add_fractional_output(amount2, &sender.default_subaddress(), &mut rng)
            .unwrap();

        builder.set_tombstone_block(2000);

        let sci = builder.build(&NoKeysRingSigner {}, &mut rng).unwrap();

        // The contingent input should have a valid signature.
        sci.validate().unwrap();

        // Check what fill amounts are suggested by fill_to_fractional_output_at
        let suggested_change = sci
            .fill_to_fractional_output_at(0, Amount::new(50_000, 2.into()))
            .unwrap();
        assert_eq!(suggested_change.token_id, Mob::ID);
        assert_eq!(suggested_change.value, value / 2);

        let suggested_change = sci
            .fill_to_fractional_output_at(0, Amount::new(20_000, 2.into()))
            .unwrap();
        assert_eq!(suggested_change.token_id, Mob::ID);
        assert_eq!(suggested_change.value, value * 4 / 5);

        // Expect an error if a bad token id is used
        assert!(sci
            .fill_to_fractional_output_at(0, Amount::new(20_000, Mob::ID))
            .is_err());

        // Expect an error if the index is out of bounds
        assert!(sci
            .fill_to_fractional_output_at(1, Amount::new(20_000, Mob::ID))
            .is_err());
    }
}
