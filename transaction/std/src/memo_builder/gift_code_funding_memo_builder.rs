// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Defines the Memo Builder for the gift code funding memo (0x0201)
//! specified in MCIP #32

use crate::{
    memo::{GiftCodeFundingMemo, UnusedMemo},
    MemoBuilder, ReservedSubaddresses,
};
use mc_account_keys::PublicAddress;
use mc_crypto_keys::RistrettoPublic;
use mc_transaction_core::{tokens::Mob, Amount, MemoContext, MemoPayload, NewMemoError, Token};

/// There are three possible gift code memo types specified in MCIP #32
/// | Memo type bytes | Name                        |
/// | -----------     | -----------                 |
/// |    0x0002       | Gift Code Sender Memo       |
/// | -->0x0201<--    | Gift Code Funding Memo      |
/// |    0x0202       | Gift Code Cancellation Memo |
/// This memo builder builds a gift code funding memo (0x0201). When a gift
/// code is funded, the amount of the gift code is sent to a TxOut at the
/// Sender's reserved gift code subaddress and a second (potentially zero
/// valued) change TxOut is sent to the sender's reserved change subaddress
/// with the gift code funding memo attached. The funding memo has 4 bytes
/// reserved for the first 4 bytes of the hash of the gift code TxOut sent
/// to the sender's reserved gift code subaddress, 7 bytes for a 56 bit
/// unsigned big endian integer representing the fee paid for the TxOut and
/// 53 bytes for an optional utf-8 note.
#[derive(Clone, Debug)]
pub struct GiftCodeFundingMemoBuilder {
    // TxOut Public Key of the gift code TxOut sent to the gift code subaddress.
    // This is populated when the output is created
    gift_code_tx_out_public_key: Option<RistrettoPublic>,
    // Fee paid for gift code funding transaction
    fee: Amount,
    // Utf-8 note within the memo that can be up to 53 bytes long
    note: String,
    // Whether we've already written the change memo
    wrote_change_memo: bool,
}

impl GiftCodeFundingMemoBuilder {
    /// Initialize memo builder with a utf-8 note (up to 53 bytes), This
    /// method will enforce the 53 byte limit with a NewMemoErr if the
    /// note passed is longer than 53 bytes.
    pub fn new(note: &str) -> Result<Self, NewMemoError> {
        if note.len() > GiftCodeFundingMemo::NOTE_DATA_LEN {
            return Err(NewMemoError::BadInputs(format!(
                "Note memo cannot be greater than {} bytes",
                GiftCodeFundingMemo::NOTE_DATA_LEN
            )));
        }
        Ok(Self {
            gift_code_tx_out_public_key: None,
            fee: Amount::new(Mob::MINIMUM_FEE, Mob::ID),
            note: note.into(),
            wrote_change_memo: false,
        })
    }
}

impl MemoBuilder for GiftCodeFundingMemoBuilder {
    /// Set the fee
    fn set_fee(&mut self, fee: Amount) -> Result<(), NewMemoError> {
        if self.wrote_change_memo {
            return Err(NewMemoError::FeeAfterChange);
        }
        if fee.value > GiftCodeFundingMemo::MAX_FEE {
            return Err(NewMemoError::MaxFeeExceeded(
                GiftCodeFundingMemo::MAX_FEE,
                fee.value,
            ));
        }
        self.fee = fee;
        Ok(())
    }

    /// This method is called when writing the gift TxOut to the reserved
    /// gift code subaddress and can only be called once. Once called it
    /// will store the public key of the gift code TxOut in the memo
    /// builder.
    fn make_memo_for_output(
        &mut self,
        _amount: Amount,
        _recipient: &PublicAddress,
        memo_context: MemoContext,
    ) -> Result<MemoPayload, NewMemoError> {
        // Only one gift code should be funded
        if self.gift_code_tx_out_public_key.is_some() {
            return Err(NewMemoError::MultipleOutputs);
        }
        if self.wrote_change_memo {
            return Err(NewMemoError::OutputsAfterChange);
        }
        self.gift_code_tx_out_public_key = Some(*memo_context.tx_public_key);
        Ok(UnusedMemo {}.into())
    }

    /// Write the funding memo onto the change output of the gift code TxOut
    fn make_memo_for_change_output(
        &mut self,
        amount: Amount,
        _change_destination: &ReservedSubaddresses,
        memo_context: MemoContext,
    ) -> Result<MemoPayload, NewMemoError> {
        if self.wrote_change_memo {
            return Err(NewMemoError::MultipleChangeOutputs);
        }
        if self.gift_code_tx_out_public_key.as_ref() == Some(memo_context.tx_public_key) {
            return Err(NewMemoError::BadInputs("The public_key in the memo should be the TxOut at the gift code subaddress and not that of the memo TxOut".into()));
        }
        // Fee must be the same token_id as the gift code token_id
        if self.fee.token_id != amount.token_id {
            return Err(NewMemoError::MixedTokenIds);
        }
        if let Some(tx_out_public_key) = self.gift_code_tx_out_public_key.take() {
            self.wrote_change_memo = true;
            Ok(
                GiftCodeFundingMemo::new(&tx_out_public_key, self.fee.value, self.note.as_str())?
                    .into(),
            )
        } else {
            Err(NewMemoError::MissingOutput)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_account_keys::AccountKey;
    use mc_util_from_random::FromRandom;
    use rand::{rngs::StdRng, SeedableRng};

    fn build_gift_code_memos(
        builder: &mut impl MemoBuilder,
        funding_tx_pubkey: &RistrettoPublic,
        fee: Amount,
    ) -> Result<MemoPayload, NewMemoError> {
        // Create simulated context
        let mut rng: StdRng = SeedableRng::from_seed([0u8; 32]);
        let alice = AccountKey::random_with_fog(&mut rng);
        let alice_address_book = ReservedSubaddresses::from(&alice);
        let change_tx_pubkey = RistrettoPublic::from_random(&mut rng);
        let change_amount = Amount::new(1, 0.into());
        let funding_amount = Amount::new(10, 0.into());
        let funding_context = MemoContext {
            tx_public_key: funding_tx_pubkey,
        };
        let change_context = MemoContext {
            tx_public_key: &change_tx_pubkey,
        };

        builder.set_fee(fee).unwrap();
        // Build blank output memo for TxOut at gift code address & funding memo to
        // change output
        builder
            .make_memo_for_output(
                funding_amount,
                &alice_address_book.gift_code_subaddress,
                funding_context,
            )
            .unwrap();
        builder.make_memo_for_change_output(change_amount, &alice_address_book, change_context)
    }

    #[test]
    fn test_gift_code_funding_memo_built_successfully_with_note() {
        // Create Memo Builder with note
        let mut rng: StdRng = SeedableRng::from_seed([0u8; 32]);
        let gift_code_public_key = RistrettoPublic::from_random(&mut rng);
        let note = "It's MEMO TIME!!";
        let mut builder = GiftCodeFundingMemoBuilder::new(note).unwrap();
        let fee = Amount::new(1, 0.into());

        // Build the memo payload
        let memo_payload = build_gift_code_memos(&mut builder, &gift_code_public_key, fee).unwrap();

        // Verify memo data
        let memo = GiftCodeFundingMemo::from(memo_payload.get_memo_data());
        let derived_note = memo.funding_note().unwrap();
        let derived_fee = memo.get_fee();
        assert_eq!(fee.value, derived_fee);
        assert_eq!(note, derived_note);
        assert!(memo.public_key_matches(&gift_code_public_key));
    }

    #[test]
    fn test_gift_code_funding_memo_built_successfully_with_edge_case_notes() {
        // Create blank notes and notes near max length
        let blank_note = "";
        let note_minus_one =
            std::str::from_utf8(&[b'6'; GiftCodeFundingMemo::NOTE_DATA_LEN - 1]).unwrap();
        let note_exact = std::str::from_utf8(&[b'6'; GiftCodeFundingMemo::NOTE_DATA_LEN]).unwrap();
        let mut rng: StdRng = SeedableRng::from_seed([0u8; 32]);
        let gift_code_public_key = RistrettoPublic::from_random(&mut rng);
        let fee = Amount::new(1, 0.into());
        // Test blank note is okay
        {
            let mut builder = GiftCodeFundingMemoBuilder::new(blank_note).unwrap();

            // Build the memo payload
            let memo_payload =
                build_gift_code_memos(&mut builder, &gift_code_public_key, fee).unwrap();

            // Verify memo data
            let memo = GiftCodeFundingMemo::from(memo_payload.get_memo_data());
            let derived_note = memo.funding_note().unwrap();
            assert_eq!(blank_note, derived_note);
            let derived_fee = memo.get_fee();
            assert_eq!(fee.value, derived_fee);
            assert!(memo.public_key_matches(&gift_code_public_key));
        }

        // Test note with max length minus one is okay
        {
            let mut builder = GiftCodeFundingMemoBuilder::new(note_minus_one).unwrap();

            // Build the memo payload
            let memo_payload =
                build_gift_code_memos(&mut builder, &gift_code_public_key, fee).unwrap();

            // Verify memo data
            let memo = GiftCodeFundingMemo::from(memo_payload.get_memo_data());
            let derived_note = memo.funding_note().unwrap();
            assert_eq!(note_minus_one, derived_note);
            let derived_fee = memo.get_fee();
            assert_eq!(fee.value, derived_fee);
            assert!(memo.public_key_matches(&gift_code_public_key));
        }

        // Test max length note is okay
        {
            let mut builder = GiftCodeFundingMemoBuilder::new(note_exact).unwrap();

            // Build the memo payload
            let memo_payload =
                build_gift_code_memos(&mut builder, &gift_code_public_key, fee).unwrap();

            // Verify memo data
            let memo = GiftCodeFundingMemo::from(memo_payload.get_memo_data());
            let derived_note = memo.funding_note().unwrap();
            assert_eq!(note_exact, derived_note);
            let derived_fee = memo.get_fee();
            assert_eq!(fee.value, derived_fee);
            assert!(memo.public_key_matches(&gift_code_public_key));
        }
    }

    #[test]
    fn test_gift_code_funding_memo_fails_to_build_if_key_matches_change_memo_public_key() {
        // Create memo builder with note
        let mut rng: StdRng = SeedableRng::from_seed([0u8; 32]);
        let note = "It's MEMO TIME!!";
        let fee = Amount::new(1, 0.into());
        let mut builder = GiftCodeFundingMemoBuilder::new(note).unwrap();
        builder.set_fee(fee).unwrap();

        // Build a memo
        let alice = AccountKey::random_with_fog(&mut rng);
        let alice_address_book = ReservedSubaddresses::from(&alice);
        let change_amount = Amount::new(666, 666.into());

        // Erroneously set funding TxOut pubkey to the change TxOut pubkey
        let change_tx_public_key = RistrettoPublic::from_random(&mut rng);

        builder
            .make_memo_for_output(
                change_amount,
                &alice_address_book.gift_code_subaddress,
                MemoContext {
                    tx_public_key: &change_tx_public_key,
                },
            )
            .unwrap();
        let memo_payload = builder.make_memo_for_change_output(
            change_amount,
            &alice_address_book,
            MemoContext {
                tx_public_key: &change_tx_public_key,
            },
        );

        // Assert memo creation fails
        assert!(matches!(memo_payload, Err(NewMemoError::BadInputs(_))));
    }

    #[test]
    fn test_gift_code_funding_memos_fail_for_multiple_change_memos() {
        // Create memo builder with note
        let mut rng: StdRng = SeedableRng::from_seed([0u8; 32]);
        let note = "It's MEMO TIME!!";
        let mut builder = GiftCodeFundingMemoBuilder::new(note).unwrap();
        let fee = Amount::new(1, 0.into());
        builder.set_fee(fee).unwrap();

        // Build a memo
        let alice = AccountKey::random_with_fog(&mut rng);
        let alice_address_book = ReservedSubaddresses::from(&alice);
        let change_amount = Amount::new(666, 0.into());

        // Write 2 change outputs
        let funding_tx_out_public_key = RistrettoPublic::from_random(&mut rng);
        let change_tx_public_key = RistrettoPublic::from_random(&mut rng);
        let change_tx_public_key_2 = RistrettoPublic::from_random(&mut rng);

        builder
            .make_memo_for_output(
                change_amount,
                &alice_address_book.gift_code_subaddress,
                MemoContext {
                    tx_public_key: &funding_tx_out_public_key,
                },
            )
            .unwrap();
        builder
            .make_memo_for_change_output(
                change_amount,
                &alice_address_book,
                MemoContext {
                    tx_public_key: &change_tx_public_key,
                },
            )
            .unwrap();
        let memo_payload = builder.make_memo_for_change_output(
            change_amount,
            &alice_address_book,
            MemoContext {
                tx_public_key: &change_tx_public_key_2,
            },
        );

        // Assert memo creation fails for second change output
        assert!(matches!(
            memo_payload,
            Err(NewMemoError::MultipleChangeOutputs)
        ));
    }

    #[test]
    fn test_gift_code_funding_memo_builder_creation_fails_with_invalid_note() {
        // Create Memo Builder with note length exceeding max length
        let note_bytes = [b'6'; GiftCodeFundingMemo::NOTE_DATA_LEN + 1];
        let note = std::str::from_utf8(&note_bytes).unwrap();
        let builder = GiftCodeFundingMemoBuilder::new(note);

        //Assert memo creation fails
        assert!(matches!(builder, Err(NewMemoError::BadInputs(_))));
    }

    #[test]
    fn test_gift_code_funding_memo_builder_fee_token_cannot_be_different_from_change_token() {
        let mut rng: StdRng = SeedableRng::from_seed([0u8; 32]);
        let gift_code_public_key = RistrettoPublic::from_random(&mut rng);
        let note = "It's MEMO TIME!!";
        let mut builder = GiftCodeFundingMemoBuilder::new(note).unwrap();
        let fee = Amount::new(1, 9001.into());

        // Set a fee with a different token id
        builder.set_fee(fee).unwrap();

        // Attempt to build the memo
        let memo_payload = build_gift_code_memos(&mut builder, &gift_code_public_key, fee);

        // Ensure memo creation fails
        assert!(matches!(memo_payload, Err(NewMemoError::MixedTokenIds)))
    }

    #[test]
    fn test_gift_code_funding_memo_builder_set_fee_fails_when_exceeding_max_fee() {
        let note = "It's MEMO TIME!!";
        let mut builder = GiftCodeFundingMemoBuilder::new(note).unwrap();
        let fee = Amount::new(u64::MAX, 0.into());

        // Try to set a fee above max allowed
        let result = builder.set_fee(fee);
        assert_eq!(
            result,
            Err(NewMemoError::MaxFeeExceeded(
                GiftCodeFundingMemo::MAX_FEE,
                fee.value
            ))
        );
    }
}
