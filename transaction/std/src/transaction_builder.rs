// Copyright (c) 2018-2020 MobileCoin Inc.

//! Utility for building and signing a transaction.
//!
//! See https://cryptonote.org/img/cryptonote_transaction.png

use keys::{CompressedRistrettoPublic, FromRandom, RistrettoPrivate, RistrettoPublic};
use std::collections::HashSet;

use crate::{InputCredentials, TxBuilderError};
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use transaction::{
    account_keys::PublicAddress,
    constants::BASE_FEE,
    encrypted_fog_hint::EncryptedFogHint,
    fog_hint::FogHint,
    onetime_keys::compute_shared_secret,
    ring_signature::SignatureRctBulletproofs,
    tx::{Tx, TxIn, TxOut, TxPrefix},
    CompressedCommitment,
};

/// Helper utility for building and signing a CryptoNote-style transaction.
#[derive(Debug)]
pub struct TransactionBuilder {
    input_credentials: Vec<InputCredentials>,
    outputs: Vec<TxOut>,
    output_shared_secrets: Vec<RistrettoPublic>,
    tombstone_block: u64,
    pub fee: u64,
}

impl TransactionBuilder {
    /// Initializes a new TransactionBuilder.
    pub fn new() -> Self {
        TransactionBuilder {
            input_credentials: Vec::new(),
            outputs: Vec::new(),
            output_shared_secrets: Vec::new(),
            tombstone_block: u64::max_value(),
            fee: BASE_FEE,
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
    /// * `value` - The value of this output.
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
    ) -> Result<TxOut, TxBuilderError> {
        let (tx_out, shared_secret) =
            create_output(value, recipient, recipient_fog_ingest_key, rng)?;

        self.outputs.push(tx_out.clone());
        self.output_shared_secrets.push(shared_secret);

        Ok(tx_out)
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
    /// * `fee` - Transaction fee.
    pub fn set_fee(&mut self, fee: u64) {
        self.fee = fee;
    }

    /// Consume the builder and return the transaction.
    pub fn build<RNG: CryptoRng + RngCore>(&mut self, rng: &mut RNG) -> Result<Tx, TxBuilderError> {
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

        let inputs: Vec<TxIn> = self
            .input_credentials
            .iter()
            .map(|input_credential| TxIn {
                ring: input_credential.ring.clone(),
                proofs: input_credential.membership_proofs.clone(),
            })
            .collect();

        let tx_prefix = TxPrefix::new(inputs, self.outputs.clone(), self.fee);

        let tx_prefix_hash = tx_prefix.hash();
        let message = tx_prefix_hash.as_bytes();

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
            input_secrets.push((onetime_private_key, value, blinding.into()));
        }

        let mut output_values_and_blindings: Vec<(u64, Scalar)> = tx_prefix
            .outputs
            .iter()
            .enumerate()
            .map(|(index, tx_out)| {
                let amount = &tx_out.amount;
                let shared_secret = &self.output_shared_secrets[index];
                let (value, blinding) = amount
                    .get_value(shared_secret)
                    .expect("TransactionBuilder created an invalid Amount");
                (value, blinding.into())
            })
            .collect();

        // The fee output is implicit in the tx_prefix.
        output_values_and_blindings.push(tx_prefix.fee_value_and_blinding());

        let signature = SignatureRctBulletproofs::sign(
            message,
            &rings,
            &real_input_indices,
            &input_secrets,
            &output_values_and_blindings,
            rng,
        )?;

        Ok(Tx {
            prefix: tx_prefix,
            tombstone_block: self.tombstone_block,
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
/// * `value` - Value of the output.
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
            if recipient.fog_url().is_none() {
                return Err(TxBuilderError::IngestPubkeyUnexpectedlyProvided);
            }
            Ok(FogHint::from(recipient).encrypt(ingest_pubkey, rng))
        }
        None => {
            if recipient.fog_url().is_some() {
                return Err(TxBuilderError::IngestPubkeyNotProvided);
            }
            Ok(EncryptedFogHint::fake_onetime_hint(rng))
        }
    }
}

#[cfg(test)]
pub mod transaction_builder_tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};
    use std::convert::TryFrom;
    use transaction::{
        account_keys::{AccountKey, DEFAULT_SUBADDRESS_INDEX},
        onetime_keys::*,
        tx::TxOutMembershipProof,
        validation::validate_transaction_signature,
    };

    #[test]
    // Spend a single input and send its full value to a single recipient.
    fn test_simple_transaction() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let alice = AccountKey::random(&mut rng);
        let bob = AccountKey::random(&mut rng);

        // Mint an initial collection of outputs, including one belonging to Alice.
        let minted_outputs: Vec<TxOut> = {
            let mut recipient_and_amounts: Vec<(PublicAddress, u64)> = Vec::new();
            recipient_and_amounts.push((alice.default_subaddress(), 65536));

            // Some outputs belonging to this account will be used as mix-ins.
            let other_account = AccountKey::random(&mut rng);
            recipient_and_amounts.push((other_account.default_subaddress(), 65536));
            recipient_and_amounts.push((other_account.default_subaddress(), 65536));

            recipient_and_amounts
                .iter()
                .map(|(recipient, amount)| {
                    let (tx_out, _shared_secret) =
                        create_output(*amount, &recipient, None, &mut rng).unwrap();
                    tx_out
                })
                .collect()
        };

        let ring = minted_outputs;
        // Spend the first minted_output
        let real_index: usize = 0;
        let real_output = ring[real_index as usize].clone();

        let onetime_private_key = recover_onetime_private_key(
            &RistrettoPublic::try_from(&real_output.public_key).unwrap(),
            &alice.view_private_key(),
            &alice.subaddress_spend_key(DEFAULT_SUBADDRESS_INDEX),
        );

        let key_image = compute_key_image(&onetime_private_key);

        let membership_proofs: Vec<TxOutMembershipProof> = ring
            .iter()
            .map(|_tx_out| {
                // TransactionBuilder does not validate membership proofs, but does require one
                // for each ring member.
                TxOutMembershipProof::new(0, 0, Default::default())
            })
            .collect();

        let input_credentials = InputCredentials::new(
            ring,
            membership_proofs.clone(),
            real_index,
            onetime_private_key,
            *alice.view_private_key(),
            &mut rng,
        )
        .unwrap();

        let mut transaction_builder = TransactionBuilder::new();
        transaction_builder.add_input(input_credentials);
        transaction_builder
            .add_output(65536 - BASE_FEE, &bob.default_subaddress(), None, &mut rng)
            .unwrap();

        let tx = transaction_builder.build(&mut rng).unwrap();

        // The transaction should have a single input.
        assert_eq!(tx.prefix.inputs.len(), 1);

        assert_eq!(tx.prefix.inputs[0].proofs.len(), membership_proofs.len());

        let expected_key_images = vec![key_image];
        assert_eq!(tx.key_images(), expected_key_images);

        // The transaction should have one output.
        assert_eq!(tx.prefix.outputs.len(), 1);

        // The output should belong to the correct recipient.
        {
            let tx_out: &TxOut = tx.prefix.outputs.get(0).unwrap();
            assert!(view_key_matches_output(
                &bob.view_key(),
                &RistrettoPublic::try_from(&tx_out.target_key).unwrap(),
                &RistrettoPublic::try_from(&tx_out.public_key).unwrap()
            ));
        }

        // The transaction should have a valid signature.
        assert!(validate_transaction_signature(&tx, &mut rng).is_ok());
    }

    #[test]
    #[ignore]
    // `build` should return an error if the inputs contain rings of different sizes.
    fn test_inputs_with_different_ring_sizes() {
        unimplemented!()
    }
}
