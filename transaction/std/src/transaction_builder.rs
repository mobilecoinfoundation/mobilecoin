// Copyright (c) 2018-2020 MobileCoin Inc.

//! Utility for building and signing a transaction.
//!
//! See https://cryptonote.org/img/cryptonote_transaction.png

use crate::{InputCredentials, TxBuilderError};
use curve25519_dalek::scalar::Scalar;
use mc_account_keys::PublicAddress;
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPrivate, RistrettoPublic};
use mc_transaction_core::{
    constants::MINIMUM_FEE,
    encrypted_fog_hint::EncryptedFogHint,
    fog_hint::FogHint,
    onetime_keys::compute_shared_secret,
    ring_signature::SignatureRctBulletproofs,
    tx::{Tx, TxIn, TxOut, TxOutConfirmationNumber, TxPrefix},
    CompressedCommitment,
};
use mc_util_from_random::FromRandom;
use rand_core::{CryptoRng, RngCore};
use std::collections::HashSet;

/// Helper utility for building and signing a CryptoNote-style transaction.
#[derive(Debug)]
pub struct TransactionBuilder {
    input_credentials: Vec<InputCredentials>,
    outputs_and_shared_secrets: Vec<(TxOut, RistrettoPublic)>,
    tombstone_block: u64,
    pub fee: u64,
}

impl TransactionBuilder {
    /// Initializes a new TransactionBuilder.
    pub fn new() -> Self {
        TransactionBuilder {
            input_credentials: Vec::new(),
            outputs_and_shared_secrets: Vec::new(),
            tombstone_block: u64::max_value(),
            fee: MINIMUM_FEE,
        }
    }

    /// Add an Input to the transaction.
    ///
    /// # Arguments
    /// * `input_credentials` - Credentials required to construct a ring signature for an input.
    pub fn add_input(&mut self, input_credentials: InputCredentials) {
        self.input_credentials.push(input_credentials);
    }

    /// Add an output to the transaction.
    ///
    /// # Arguments
    /// * `value` - The value of this output, in picoMOB.
    /// * `recipient` - The recipient's public address
    /// * `recipient_fog_ingest_key` - The recipient's fog server's public key
    /// * `rng` - RNG used to generate blinding for commitment
    ///
    pub fn add_output<RNG: CryptoRng + RngCore>(
        &mut self,
        value: u64,
        recipient: &PublicAddress,
        recipient_fog_ingest_key: Option<&RistrettoPublic>,
        rng: &mut RNG,
    ) -> Result<(TxOut, TxOutConfirmationNumber), TxBuilderError> {
        let (tx_out, shared_secret) =
            create_output(value, recipient, recipient_fog_ingest_key, rng)?;

        self.outputs_and_shared_secrets
            .push((tx_out.clone(), shared_secret));

        let confirmation = TxOutConfirmationNumber::from(&shared_secret);

        Ok((tx_out, confirmation))
    }

    /// Sets the tombstone block.
    ///
    /// # Arguments
    /// * `tombstone_block` - Tombstone block number.
    pub fn set_tombstone_block(&mut self, tombstone_block: u64) {
        self.tombstone_block = tombstone_block;
    }

    /// Sets the transaction fee.
    ///
    /// # Arguments
    /// * `fee` - Transaction fee, in picoMOB.
    pub fn set_fee(&mut self, fee: u64) {
        self.fee = fee;
    }

    /// Consume the builder and return the transaction.
    pub fn build<RNG: CryptoRng + RngCore>(mut self, rng: &mut RNG) -> Result<Tx, TxBuilderError> {
        if self.input_credentials.is_empty() {
            return Err(TxBuilderError::NoInputs);
        }

        // All inputs must have rings of the same size.
        {
            let ring_sizes: HashSet<usize> = self
                .input_credentials
                .iter()
                .map(|input| input.ring.len())
                .collect();
            if ring_sizes.len() > 1 {
                return Err(TxBuilderError::InvalidRingSize);
            }
        }

        // Construct a list of sorted inputs.
        // Inputs are sorted by the first ring element's public key. Note that each ring is also
        // sorted.
        self.input_credentials
            .sort_by(|a, b| a.ring[0].public_key.cmp(&b.ring[0].public_key));

        let inputs: Vec<TxIn> = self
            .input_credentials
            .iter()
            .map(|input_credential| TxIn {
                ring: input_credential.ring.clone(),
                proofs: input_credential.membership_proofs.clone(),
            })
            .collect();

        // Sort outputs by public key.
        self.outputs_and_shared_secrets
            .sort_by(|(a, _), (b, _)| a.public_key.cmp(&b.public_key));

        let output_values_and_blindings: Vec<(u64, Scalar)> = self
            .outputs_and_shared_secrets
            .iter()
            .map(|(tx_out, shared_secret)| {
                let amount = &tx_out.amount;
                let (value, blinding) = amount
                    .get_value(shared_secret)
                    .expect("TransactionBuilder created an invalid Amount");
                (value, blinding)
            })
            .collect();

        let (outputs, _shared_serets): (Vec<TxOut>, Vec<_>) =
            self.outputs_and_shared_secrets.into_iter().unzip();

        let tx_prefix = TxPrefix::new(inputs, outputs, self.fee, self.tombstone_block);

        let mut rings: Vec<Vec<(CompressedRistrettoPublic, CompressedCommitment)>> = Vec::new();
        for input in &tx_prefix.inputs {
            let ring: Vec<(CompressedRistrettoPublic, CompressedCommitment)> = input
                .ring
                .iter()
                .map(|tx_out| (tx_out.target_key, tx_out.amount.commitment))
                .collect();
            rings.push(ring);
        }

        let real_input_indices: Vec<usize> = self
            .input_credentials
            .iter()
            .map(|input_credential| input_credential.real_index)
            .collect();

        // One-time private key, amount value, and amount blinding for each real input.
        let mut input_secrets: Vec<(RistrettoPrivate, u64, Scalar)> = Vec::new();
        for input_credential in &self.input_credentials {
            let onetime_private_key = input_credential.onetime_private_key;
            let amount = &input_credential.ring[input_credential.real_index].amount;
            let shared_secret = compute_shared_secret(
                &input_credential.real_output_public_key,
                &input_credential.view_private_key,
            );
            let (value, blinding) = amount.get_value(&shared_secret)?;
            input_secrets.push((onetime_private_key, value, blinding));
        }

        let message = tx_prefix.hash().0;
        let signature = SignatureRctBulletproofs::sign(
            &message,
            &rings,
            &real_input_indices,
            &input_secrets,
            &output_values_and_blindings,
            self.fee,
            rng,
        )?;

        Ok(Tx {
            prefix: tx_prefix,
            signature,
        })
    }
}

// This appeases clippy's new_without_default rule.
impl Default for TransactionBuilder {
    fn default() -> Self {
        TransactionBuilder::new()
    }
}

/// Creates a TxOut that sends `value` to `recipient`.
///
/// # Arguments
/// * `value` - Value of the output, in picoMOB.
/// * `recipient` - Recipient's address.
/// * `ingest_pubkey` - The public key for the recipients fog server, if any
/// * `rng` -
fn create_output<RNG: CryptoRng + RngCore>(
    value: u64,
    recipient: &PublicAddress,
    ingest_pubkey: Option<&RistrettoPublic>,
    rng: &mut RNG,
) -> Result<(TxOut, RistrettoPublic), TxBuilderError> {
    let private_key = RistrettoPrivate::from_random(rng);
    let hint = create_fog_hint(recipient, ingest_pubkey, rng)?;
    let tx_out = TxOut::new(value, recipient, &private_key, hint, rng)?;
    let shared_secret = compute_shared_secret(recipient.view_public_key(), &private_key);
    Ok((tx_out, shared_secret))
}

/// Creates an Encrypted Fog Hint for a recipient
fn create_fog_hint<RNG: CryptoRng + RngCore>(
    recipient: &PublicAddress,
    maybe_ingest_pubkey: Option<&RistrettoPublic>,
    rng: &mut RNG,
) -> Result<EncryptedFogHint, TxBuilderError> {
    match maybe_ingest_pubkey {
        Some(ingest_pubkey) => {
            if recipient.fog_report_url().is_none() {
                return Err(TxBuilderError::IngestPubkeyUnexpectedlyProvided);
            }
            Ok(FogHint::from(recipient).encrypt(ingest_pubkey, rng))
        }
        None => {
            if recipient.fog_report_url().is_some() {
                return Err(TxBuilderError::IngestPubkeyNotProvided);
            }
            Ok(EncryptedFogHint::fake_onetime_hint(rng))
        }
    }
}

#[cfg(test)]
pub mod transaction_builder_tests {
    use super::*;
    use mc_account_keys::{AccountKey, DEFAULT_SUBADDRESS_INDEX};
    use mc_transaction_core::{
        constants::{MAX_INPUTS, MAX_OUTPUTS, MILLIMOB_TO_PICOMOB},
        onetime_keys::*,
        ring_signature::KeyImage,
        tx::TxOutMembershipProof,
        validation::validate_signature,
    };
    use rand::{rngs::StdRng, SeedableRng};
    use std::convert::TryFrom;

    /// Creates a ring of of TxOuts.
    ///
    /// # Arguments
    /// * `ring_size` - Number of elements in the ring.
    /// * `account` - Owner of one of the ring elements.
    /// * `value` - Value of the real element.
    /// * `rng` - Randomness.
    ///
    /// Returns (ring, real_index)
    fn get_ring<RNG: CryptoRng + RngCore>(
        ring_size: usize,
        account: &AccountKey,
        value: u64,
        rng: &mut RNG,
    ) -> (Vec<TxOut>, usize) {
        let mut ring: Vec<TxOut> = Vec::new();

        // Create ring_size - 1 mixins.
        for _i in 0..ring_size - 1 {
            let address = AccountKey::random(rng).default_subaddress();
            let (tx_out, _) = create_output(value, &address, None, rng).unwrap();
            ring.push(tx_out);
        }

        // Insert the real element.
        let real_index = (rng.next_u64() % ring_size as u64) as usize;
        let (tx_out, _) = create_output(value, &account.default_subaddress(), None, rng).unwrap();
        ring.insert(real_index, tx_out);
        assert_eq!(ring.len(), ring_size);

        (ring, real_index)
    }

    // Uses TransactionBuilder to build a transaction.
    fn get_transaction<RNG: RngCore + CryptoRng>(
        num_inputs: usize,
        num_outputs: usize,
        sender: &AccountKey,
        recipient: &AccountKey,
        rng: &mut RNG,
    ) -> Result<Tx, TxBuilderError> {
        let mut transaction_builder = TransactionBuilder::new();
        let input_value = 1000;
        let output_value = 10;

        // Inputs
        for _i in 0..num_inputs {
            let (ring, real_index) = get_ring(3, sender, input_value, rng);
            let real_output = ring[real_index].clone();

            let onetime_private_key = recover_onetime_private_key(
                &RistrettoPublic::try_from(&real_output.public_key).unwrap(),
                &sender.view_private_key(),
                &sender.subaddress_spend_private(DEFAULT_SUBADDRESS_INDEX),
            );

            let membership_proofs: Vec<TxOutMembershipProof> = ring
                .iter()
                .map(|_tx_out| {
                    // TransactionBuilder does not validate membership proofs, but does require one
                    // for each ring member.
                    TxOutMembershipProof::default()
                })
                .collect();

            let input_credentials = InputCredentials::new(
                ring,
                membership_proofs.clone(),
                real_index,
                onetime_private_key,
                *sender.view_private_key(),
            )
            .unwrap();
            transaction_builder.add_input(input_credentials);
        }

        // Outputs
        for _i in 0..num_outputs {
            transaction_builder
                .add_output(output_value, &recipient.default_subaddress(), None, rng)
                .unwrap();
        }

        // Set the fee so that sum(inputs) = sum(outputs) + fee.
        let fee = num_inputs as u64 * input_value - num_outputs as u64 * output_value;
        transaction_builder.set_fee(fee);

        transaction_builder.build(rng)
    }

    #[test]
    // Spend a single input and send its full value to a single recipient.
    fn test_simple_transaction() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let sender = AccountKey::random(&mut rng);
        let recipient = AccountKey::random(&mut rng);
        let value = 1475 * MILLIMOB_TO_PICOMOB;

        // Mint an initial collection of outputs, including one belonging to Alice.
        let (ring, real_index) = get_ring(3, &sender, value, &mut rng);
        let real_output = ring[real_index].clone();

        let onetime_private_key = recover_onetime_private_key(
            &RistrettoPublic::try_from(&real_output.public_key).unwrap(),
            &sender.view_private_key(),
            &sender.subaddress_spend_private(DEFAULT_SUBADDRESS_INDEX),
        );

        let key_image = KeyImage::from(&onetime_private_key);

        let membership_proofs: Vec<TxOutMembershipProof> = ring
            .iter()
            .map(|_tx_out| {
                // TransactionBuilder does not validate membership proofs, but does require one
                // for each ring member.
                TxOutMembershipProof::default()
            })
            .collect();

        let input_credentials = InputCredentials::new(
            ring,
            membership_proofs.clone(),
            real_index,
            onetime_private_key,
            *sender.view_private_key(),
        )
        .unwrap();

        let mut transaction_builder = TransactionBuilder::new();

        transaction_builder.add_input(input_credentials);
        let (_txout, confirmation) = transaction_builder
            .add_output(
                value - MINIMUM_FEE,
                &recipient.default_subaddress(),
                None,
                &mut rng,
            )
            .unwrap();

        let tx = transaction_builder.build(&mut rng).unwrap();

        // The transaction should have a single input.
        assert_eq!(tx.prefix.inputs.len(), 1);

        assert_eq!(tx.prefix.inputs[0].proofs.len(), membership_proofs.len());

        let expected_key_images = vec![key_image];
        assert_eq!(tx.key_images(), expected_key_images);

        // The transaction should have one output.
        assert_eq!(tx.prefix.outputs.len(), 1);

        let output: &TxOut = tx.prefix.outputs.get(0).unwrap();

        // The output should belong to the correct recipient.
        {
            assert!(view_key_matches_output(
                &recipient.view_key(),
                &RistrettoPublic::try_from(&output.target_key).unwrap(),
                &RistrettoPublic::try_from(&output.public_key).unwrap()
            ));
        }

        // The output should have the correct value and confirmation number
        {
            let public_key = RistrettoPublic::try_from(&output.public_key).unwrap();
            assert!(confirmation.validate(&public_key, &recipient.view_private_key()));
        }

        // The transaction should have a valid signature.
        assert!(validate_signature(&tx, &mut rng).is_ok());
    }

    #[test]
    #[ignore]
    // `build` should return an error if the inputs contain rings of different sizes.
    fn test_inputs_with_different_ring_sizes() {
        unimplemented!()
    }

    #[test]
    // `build` should return an error if the sum of inputs does not equal the sum of outputs and the fee.
    fn test_inputs_do_not_equal_outputs() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let alice = AccountKey::random(&mut rng);
        let bob = AccountKey::random(&mut rng);
        let value = 1475;

        // Mint an initial collection of outputs, including one belonging to Alice.
        let (ring, real_index) = get_ring(3, &alice, value, &mut rng);
        let real_output = ring[real_index].clone();

        let onetime_private_key = recover_onetime_private_key(
            &RistrettoPublic::try_from(&real_output.public_key).unwrap(),
            &alice.view_private_key(),
            &alice.subaddress_spend_private(DEFAULT_SUBADDRESS_INDEX),
        );

        let membership_proofs: Vec<TxOutMembershipProof> = ring
            .iter()
            .map(|_tx_out| {
                // TransactionBuilder does not validate membership proofs, but does require one
                // for each ring member.
                TxOutMembershipProof::default()
            })
            .collect();

        let input_credentials = InputCredentials::new(
            ring,
            membership_proofs.clone(),
            real_index,
            onetime_private_key,
            *alice.view_private_key(),
        )
        .unwrap();

        let mut transaction_builder = TransactionBuilder::new();
        transaction_builder.add_input(input_credentials);

        let wrong_value = 999;
        transaction_builder
            .add_output(wrong_value, &bob.default_subaddress(), None, &mut rng)
            .unwrap();

        let result = transaction_builder.build(&mut rng);
        // Signing should fail if value is not conserved.
        match result {
            Err(TxBuilderError::RingSignatureFailed) => {} // Expected.
            _ => panic!("Unexpected result {:?}", result),
        }
    }

    #[test]
    // `build` should succeed with MAX_INPUTS and MAX_OUTPUTS.
    fn test_max_transaction_size() {
        let mut rng: StdRng = SeedableRng::from_seed([18u8; 32]);
        let sender = AccountKey::random(&mut rng);
        let recipient = AccountKey::random(&mut rng);
        let tx = get_transaction(
            MAX_INPUTS as usize,
            MAX_OUTPUTS as usize,
            &sender,
            &recipient,
            &mut rng,
        )
        .unwrap();
        assert_eq!(tx.prefix.inputs.len(), MAX_INPUTS as usize);
        assert_eq!(tx.prefix.outputs.len(), MAX_OUTPUTS as usize);
    }

    #[test]
    // Ring elements should be sorted by tx_out.public_key
    fn test_ring_elements_are_sorted() {
        let mut rng: StdRng = SeedableRng::from_seed([97u8; 32]);
        let sender = AccountKey::random(&mut rng);
        let recipient = AccountKey::random(&mut rng);
        let num_inputs = 3;
        let num_outputs = 11;
        let tx = get_transaction(num_inputs, num_outputs, &sender, &recipient, &mut rng).unwrap();

        for tx_in in &tx.prefix.inputs {
            assert!(tx_in
                .ring
                .windows(2)
                .all(|w| w[0].public_key < w[1].public_key));
        }
    }

    #[test]
    // Transaction outputs should be sorted by public key.
    fn test_outputs_are_sorted() {
        let mut rng: StdRng = SeedableRng::from_seed([92u8; 32]);
        let sender = AccountKey::random(&mut rng);
        let recipient = AccountKey::random(&mut rng);
        let num_inputs = 3;
        let num_outputs = 11;
        let tx = get_transaction(num_inputs, num_outputs, &sender, &recipient, &mut rng).unwrap();

        let outputs = tx.prefix.outputs;
        let mut expected_outputs = outputs.clone();
        expected_outputs.sort_by(|a, b| a.public_key.cmp(&b.public_key));
        assert_eq!(outputs, expected_outputs);
    }

    #[test]
    // Transaction inputs should be sorted by the public key of the first ring element.
    fn test_inputs_are_sorted() {
        let mut rng: StdRng = SeedableRng::from_seed([92u8; 32]);
        let sender = AccountKey::random(&mut rng);
        let recipient = AccountKey::random(&mut rng);
        let num_inputs = 3;
        let num_outputs = 11;
        let tx = get_transaction(num_inputs, num_outputs, &sender, &recipient, &mut rng).unwrap();

        let inputs = tx.prefix.inputs;
        let mut expected_inputs = inputs.clone();
        expected_inputs.sort_by(|a, b| a.ring[0].public_key.cmp(&b.ring[0].public_key));
        assert_eq!(inputs, expected_inputs);
    }
}
