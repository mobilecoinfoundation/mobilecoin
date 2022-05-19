// Copyright (c) 2018-2022 The MobileCoin Foundation

//! An RCT_TYPE_BULLETPROOFS_2 signature.
//!
//! # References
//! * [Ring Confidential Transactions](https://eprint.iacr.org/2015/1098.pdf)
//! * [Bulletproofs](https://eprint.iacr.org/2017/1066.pdf)

extern crate alloc;

use alloc::{collections::BTreeSet, vec, vec::Vec};
use bulletproofs_og::RangeProof;
use core::convert::TryFrom;
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    traits::Identity,
};
use mc_common::HashSet;
use mc_crypto_digestible::{DigestTranscript, Digestible, MerlinTranscript};
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPrivate};
use mc_util_serial::prost::Message;
use mc_util_zip_exact::zip_exact;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::{
    constants::FEE_BLINDING,
    domain_separators::EXTENDED_MESSAGE_DOMAIN_TAG,
    range_proofs::{check_range_proofs, generate_range_proofs},
    ring_signature::{mlsag::RingMLSAG, Error, GeneratorCache, KeyImage, Scalar},
    Amount, BlockVersion, Commitment, CompressedCommitment,
};

/// A representation of the part of the input ring needed to create an MLSAG
#[derive(Clone, Debug)]
pub struct SignableInputRing {
    /// A reduced representation of the TxOut's in the ring. For each ring
    /// member we have only:
    /// * The onetime-address (tx_out.target_key)
    /// * The compressed commitment (tx_out.amount.commitment)
    pub members: Vec<(CompressedRistrettoPublic, CompressedCommitment)>,

    /// The index of the real input among these ring members
    pub real_input_index: usize,

    /// The secrets needed to sign that input
    pub input_secret: InputSecret,
}

/// A presigned RingMLSAG and ancillary data needed to incorporate it into a
/// signature
#[derive(Clone, Debug)]
pub struct PresignedInputRing {
    /// The mlsag signature authorizing the spending of an input
    pub mlsag: RingMLSAG,
    /// The amount and blinding factor of the pseudo output
    pub pseudo_output_secret: OutputSecret,
}

/// An enum which is either a PresignedInputRing or a SignableInputRing
///
/// This enum is needed because all TxIn's are required to appear in sorted
/// order, regardless of if they are presigned. This gives the signer a way to
/// control the order in which they will appear.
#[derive(Clone, Debug)]
pub enum InputRing {
    /// A signable input ring
    Signable(SignableInputRing),
    /// A presigned input ring
    Presigned(PresignedInputRing),
}

impl InputRing {
    /// Get the amount of the pseudo-output of this ring
    pub fn amount(&self) -> &Amount {
        match self {
            InputRing::Signable(ring) => &ring.input_secret.amount,
            InputRing::Presigned(ring) => &ring.pseudo_output_secret.amount,
        }
    }
}

/// The secrets needed to create a signature that spends an existing output as
/// an input
#[derive(Clone, Debug, Zeroize)]
#[zeroize(drop)]
pub struct InputSecret {
    /// The one-time private key for the output we are trying to spend
    pub onetime_private_key: RistrettoPrivate,
    /// The amount of the output
    pub amount: Amount,
    /// The blinding factor of the output we are trying to spend
    pub blinding: Scalar,
}

/// The secrets corresponding to an output that we are trying to authorize
/// creation of
#[derive(Clone, Debug, Zeroize)]
#[zeroize(drop)]
pub struct OutputSecret {
    /// The amount of the output we are creating
    pub amount: Amount,
    /// The blinding factor of the output we are creating
    pub blinding: Scalar,
}

/// The parts of a TxIn needed to validate a corresponding MLSAG
#[derive(Clone, Debug)]
pub struct SignedInputRing {
    /// A reduced representation of the TxOut's in the ring. For each ring
    /// member we have only:
    /// * The onetime-address (tx_out.target_key)
    /// * The compressed commitment (tx_out.amount.commitment)
    pub members: Vec<(CompressedRistrettoPublic, CompressedCommitment)>,

    /// The digest that this signature is supposed to have signed.
    /// If omitted, then the entire extended message digest should have been
    /// signed. If the input has rules, then a reduced digest is signed
    /// instead. (See MCIP #31 for rationale)
    pub signed_digest: Option<[u8; 32]>,
}

/// An RCT_TYPE_BULLETPROOFS_2 signature
#[derive(Clone, Digestible, Eq, PartialEq, Serialize, Deserialize, Message)]
pub struct SignatureRctBulletproofs {
    /// Signature for each input ring.
    #[prost(message, repeated, tag = "1")]
    pub ring_signatures: Vec<RingMLSAG>,

    /// Commitments of value equal to each real input.
    #[prost(message, repeated, tag = "2")]
    pub pseudo_output_commitments: Vec<CompressedCommitment>,

    /// Proof that all pseudo_outputs and transaction outputs are in [0, 2^64).
    /// This contains range_proof.to_bytes(). It is stored this way so that this
    /// struct may derive Default, which is a requirement for serializing
    /// with Prost.
    ///
    /// Note: This is EMPTY if mixed transactions are enabled
    #[prost(bytes, tag = "3")]
    #[digestible(never_omit)]
    pub range_proof_bytes: Vec<u8>,

    /// A range proof, one for each token id that is used in the transaction.
    ///
    /// The range proofs correspond to the sorted order of token ids used.
    ///
    /// Note: This is EMPTY if mixed transactions is not enabled
    #[prost(bytes, repeated, tag = "4")]
    pub range_proofs: Vec<Vec<u8>>,

    /// Token id for each pseudo_output. This must have the same length as
    /// `pseudo_output_commitments`, after mixed transactions feature.
    #[prost(fixed64, repeated, tag = "5")]
    pub pseudo_output_token_ids: Vec<u64>,

    /// Token id for each output. This must have the same length as
    /// `prefix.outputs`, after mixed transactions feature
    #[prost(fixed64, repeated, tag = "6")]
    pub output_token_ids: Vec<u64>,
}

impl SignatureRctBulletproofs {
    /// Sign.
    ///
    /// # Arguments
    /// * `block_version` - This may influence details of the signature
    /// * `message` - The messages to be signed, e.g. Hash(TxPrefix).
    /// * `rings` - One or more rings of one-time addresses and amount
    ///   commitments.
    /// * `real_input_indices` - The index of the real input in each ring.
    /// * `input_secrets` - One-time private key, amount value, and amount
    ///   blinding for each real input.
    /// * `output_values_and_blindings` - Value and blinding for each output
    ///   amount commitment.
    /// * `fee` - Value of the implicit fee output.
    /// * `token id` - This determines the pedersen generator for commitments
    pub fn sign<CSPRNG: RngCore + CryptoRng>(
        block_version: BlockVersion,
        message: &[u8; 32],
        input_rings: &[InputRing],
        output_secrets: &[OutputSecret],
        fee: Amount,
        rng: &mut CSPRNG,
    ) -> Result<Self, Error> {
        sign_with_balance_check(
            block_version,
            message,
            input_rings,
            output_secrets,
            fee,
            true,
            rng,
        )
    }

    /// Verify.
    ///
    /// # Arguments
    /// * `block_version` - This may influence details of the signature
    /// * `message` - The message which was signed
    /// * `rings` - One or more rings which were signed to create this signature
    /// * `output_commitments` - Output amount commitments.
    /// * `fee` - Amount of the implicit fee output. commitment
    /// * `rng` - randomness
    pub fn verify<CSPRNG: RngCore + CryptoRng>(
        &self,
        block_version: BlockVersion,
        message: &[u8; 32],
        rings: &[SignedInputRing],
        output_commitments: &[CompressedCommitment],
        fee: Amount,
        rng: &mut CSPRNG,
    ) -> Result<(), Error> {
        if !block_version.masked_token_id_feature_is_supported() && fee.token_id != 0 {
            return Err(Error::TokenIdNotAllowed);
        }

        if rings.iter().all(|ring| ring.signed_digest.is_some()) {
            return Err(Error::AllRingsPresigned);
        }

        // Signature must contain one ring signature for each ring.
        if rings.len() != self.ring_signatures.len() {
            return Err(Error::LengthMismatch(
                rings.len(),
                self.ring_signatures.len(),
            ));
        }

        // Signature must contain one pseudo_output for each ring.
        if rings.len() != self.pseudo_output_commitments.len() {
            return Err(Error::LengthMismatch(
                rings.len(),
                self.pseudo_output_commitments.len(),
            ));
        }

        // pseudo output token ids must be provided if mixed transactions is enabled
        if block_version.mixed_transactions_are_supported() {
            if self.pseudo_output_commitments.len() != self.pseudo_output_token_ids.len() {
                return Err(Error::MissingPseudoOutputTokenIds);
            }
            if output_commitments.len() != self.output_token_ids.len() {
                return Err(Error::MissingOutputTokenIds);
            }
        } else {
            if !self.pseudo_output_token_ids.is_empty() {
                return Err(Error::PseudoOutputTokenIdsNotAllowed);
            }
            if !self.output_token_ids.is_empty() {
                return Err(Error::OutputTokenIdsNotAllowed);
            }
        }

        // Key images must be unique.
        {
            let key_images_are_unique = {
                let mut uniq = HashSet::default();
                self.key_images().into_iter().all(move |x| uniq.insert(x))
            };
            if !key_images_are_unique {
                return Err(Error::DuplicateKeyImage);
            }
        }

        // output_commitments must decompress.
        // This ensures that each commitment encodes a valid Ristretto point.
        let mut decompressed_output_commitments: Vec<Commitment> = Vec::new();
        for output_commitment in output_commitments {
            let commitment = Commitment::try_from(output_commitment)?;
            decompressed_output_commitments.push(commitment);
        }

        // pseudo_output_commitments must decompress.
        // This ensures that each commitment encodes a valid Ristretto point.
        let mut decompressed_pseudo_output_commitments: Vec<Commitment> = Vec::new();
        for pseudo_output in &self.pseudo_output_commitments {
            let commitment = Commitment::try_from(pseudo_output)?;
            decompressed_pseudo_output_commitments.push(commitment);
        }

        // Collect list of of unique token ids
        let token_ids = {
            let mut token_ids = BTreeSet::default();
            token_ids.insert(fee.token_id);
            for token_id in &self.output_token_ids {
                token_ids.insert(token_id.into());
            }
            for token_id in &self.pseudo_output_token_ids {
                token_ids.insert(token_id.into());
            }
            token_ids
        };

        // Get a generator cache
        let mut generator_cache = GeneratorCache::default();

        // pseudo_output_commitments and output commitments must be in [0, 2^64).
        // this is done differently depending on if mixed transactions are supported
        if !block_version.mixed_transactions_are_supported() {
            // Before mixed transactions, we expect the range proof to appear in
            // self.range_proof_bytes, not self.range_proofs
            if !self.range_proofs.is_empty() {
                return Err(Error::TooManyRangeProofs);
            }

            let generator = generator_cache.get(fee.token_id);
            let commitments: Vec<CompressedRistretto> = self
                .pseudo_output_commitments
                .iter()
                .chain(output_commitments.iter())
                .map(|compressed_commitment| compressed_commitment.point)
                .collect();

            let range_proof = RangeProof::from_bytes(&self.range_proof_bytes)
                .map_err(|_e| Error::RangeProofDeserialization)?;

            check_range_proofs(&range_proof, &commitments, generator, rng)?
        } else {
            // When mixed transactions are supported, self.range_proofs should contain
            // a range proof corresponding to each token id used in the transaction, in
            // sorted order. range_proof_bytes should be empty
            if !self.range_proof_bytes.is_empty() {
                return Err(Error::UnexpectedRangeProof);
            }
            if token_ids.len() != self.range_proofs.len() {
                return Err(Error::MissingRangeProofs(
                    token_ids.len(),
                    self.range_proofs.len(),
                ));
            }

            // For each used token id, and range proof, we have to pick out the matching
            // outputs and pseudo outputs and verify the range proof.
            for (token_id, range_proof) in zip_exact(token_ids.iter(), self.range_proofs.iter())? {
                let generator = generator_cache.get(*token_id);

                let commitments: Vec<CompressedRistretto> = zip_exact(
                    self.pseudo_output_commitments.iter(),
                    self.pseudo_output_token_ids.iter(),
                )?
                .chain(zip_exact(
                    output_commitments.iter(),
                    self.output_token_ids.iter(),
                )?)
                .filter_map(|(compressed_commitment, this_token_id)| {
                    if token_id == this_token_id {
                        Some(compressed_commitment.point)
                    } else {
                        None
                    }
                })
                .collect();

                if commitments.is_empty() {
                    return Err(Error::NoCommitmentsForTokenId(*token_id));
                }

                let range_proof = RangeProof::from_bytes(range_proof)
                    .map_err(|_e| Error::RangeProofDeserialization)?;

                check_range_proofs(&range_proof, &commitments, generator, rng)?
            }
        }

        // Transaction must be balanced (not create or destroy value).
        //
        // Output commitments - pseudo_outputs must be zero.
        //
        // Note: Why does this imply that the transaction is balanced?
        //
        // Each input is a Pedersen commitment v_i H_j + b_i G
        //
        // Here v_i is the i'th value, b_i is the i'th blinding factor, H_j is
        // the base for j'th token id, G is the base for the blinding factors.
        //
        // If we expand and collect terms, then output commitments - pseudo output
        // commitments can be thought of as a vector:
        //
        // sum_j w_j H_j + (sum of output blinding factors - sum of pseudo-output
        // blinding factors) G
        //
        // where w_j = sum of output values - sum of pseudo output values in token id j.
        //
        // We are checking that this sum is equal to the zero point (zero vector).
        //
        // At this point, we appeal to the "orthogonality" of the bases G, H_1, H_2, ...
        // We assume that it is infeasible for anyone to find a nontrivial linear
        // relation between them.
        //
        // (See generators
        // module doc for justification of this, but basically it's because we hash to
        // curve.)
        //
        // Therefore, if someone submits a transaction where this sum is zero, and they
        // cannot not know any "nontrivial" linear combination of G, H_1, ...
        // then this must be a trivial linear combination.
        // A trivial linear combination is one where all the coefficients are zero.
        // This implies that w_j = 0 for all j, which implies that value was not created
        // or destroyed in any token id, as required.
        //
        // So we don't need to do a separate loop here once per token id, we can just
        // add everything together and check for zero.
        {
            // Compute sum of pseudo outputs
            let sum_of_pseudo_output_commitments: RistrettoPoint =
                decompressed_pseudo_output_commitments
                    .iter()
                    .map(|commitment| commitment.point)
                    .sum();
            let sum_of_output_commitments: RistrettoPoint = decompressed_output_commitments
                .iter()
                .map(|commitment| commitment.point)
                .sum();

            // The implicit fee output.
            let generator = generator_cache.get(fee.token_id);
            let fee_commitment = generator.commit(Scalar::from(fee.value), *FEE_BLINDING);
            let difference =
                sum_of_output_commitments + fee_commitment - sum_of_pseudo_output_commitments;
            // RistrettoPoint::identity() is the zero point of Ristretto group, this is the
            // same as generator.commit(Zero, Zero) and is faster.
            if difference != RistrettoPoint::identity() {
                return Err(Error::ValueNotConserved);
            }
        }

        // Extend the message with the range proof and pseudo_output_commitments.
        let extended_message_digest = compute_extended_message_either_version(
            block_version,
            message,
            &self.pseudo_output_commitments,
            &self.range_proof_bytes,
            &self.range_proofs,
        );

        // Each MLSAG must be valid.
        for (i, ring) in rings.iter().enumerate() {
            // Normally, the ring signature is made over the entire extended messages
            // digest. If there are input rules, then the signature is over a
            // reduced digest. See MCIP #31 for rationale
            let this_was_signed: &[u8] = if let Some(signed_digest) = ring.signed_digest.as_ref() {
                &signed_digest[..]
            } else {
                &extended_message_digest
            };

            let ring_signature = &self.ring_signatures[i];
            let pseudo_output = self.pseudo_output_commitments[i];
            ring_signature.verify(this_was_signed, &ring.members, &pseudo_output)?;
        }

        // Signature is valid.
        Ok(())
    }

    /// Key images spent by this signature.
    pub fn key_images(&self) -> Vec<KeyImage> {
        self.ring_signatures
            .iter()
            .map(|mlsag| mlsag.key_image)
            .collect()
    }
}

/// Sign, with optional check for inputs = outputs.
///
/// # Arguments
/// * `block_version` - This may influence details of the signature
/// * `message` - The messages to be signed, e.g. Hash(TxPrefix).
/// * `rings` - One or more rings of one-time addresses and amount commitments,
///   with secrets for the real input
/// * `output_secrets` - Output secret for each output amount commitment.
/// * `fee` - Amount of the implicit fee output.
/// * `check_value_is_preserved` - If true, check that the value of inputs
/// * `rng` - randomness
fn sign_with_balance_check<CSPRNG: RngCore + CryptoRng>(
    block_version: BlockVersion,
    message: &[u8; 32],
    rings: &[InputRing],
    output_secrets: &[OutputSecret],
    fee: Amount,
    check_value_is_preserved: bool,
    rng: &mut CSPRNG,
) -> Result<SignatureRctBulletproofs, Error> {
    if !block_version.masked_token_id_feature_is_supported() && fee.token_id != 0 {
        return Err(Error::TokenIdNotAllowed);
    }

    // input and output token ids must match fee_token_id if mixed transactions is
    // not enabled
    if !block_version.mixed_transactions_are_supported() {
        if rings
            .iter()
            .any(|ring| ring.amount().token_id != fee.token_id)
        {
            return Err(Error::MixedTransactionsNotAllowed);
        }
        if output_secrets
            .iter()
            .any(|sec| sec.amount.token_id != fee.token_id)
        {
            return Err(Error::MixedTransactionsNotAllowed);
        }
    }

    // Presigned rings and input rules cannot be used if signed input rules are not
    // enabled
    if !block_version.signed_input_rules_are_supported() {
        for ring in rings {
            match ring {
                InputRing::Presigned(_) => {
                    return Err(Error::SignedInputRulesNotAllowed);
                }
                InputRing::Signable(_) => {}
            };
        }
    }

    if rings.is_empty() {
        return Err(Error::NoInputs);
    }
    let ring_size = rings
        .iter()
        .find_map(|ring| {
            if let InputRing::Signable(ring) = ring {
                Some(ring.members.len())
            } else {
                None
            }
        })
        .ok_or(Error::AllRingsPresigned)?;

    if ring_size == 0 {
        return Err(Error::InvalidRingSize(0));
    }

    for ring in rings {
        if let InputRing::Signable(ring) = ring {
            // Each ring must have the same size.
            if ring.members.len() != ring_size {
                return Err(Error::InvalidRingSize(ring.members.len()));
            }
            // Each `real_input_index` must be in [0,ring_size - 1].
            if ring.real_input_index >= ring_size {
                return Err(Error::IndexOutOfBounds);
            }
        }
    }

    // This computes a sequence of appropriate pseudo output blindings, one for each
    // ring. For Signable rings, this will be a random number, but the last is
    // chosen so that the sum of all blinding factors is zero.
    // For pre-signed rings, we cannot change blinding, so we have to use what was
    // signed.
    let pseudo_output_blindings = compute_pseudo_output_blindings(rings, output_secrets, rng)?;

    // Create Range proofs for outputs and pseudo-outputs.
    let pseudo_output_values_and_blindings: Vec<(u64, Scalar)> = rings
        .iter()
        .zip(pseudo_output_blindings.iter())
        .map(|(ring, blinding)| (ring.amount().value, *blinding))
        .collect();

    // Create a pedersen generator cache
    let mut generator_cache = GeneratorCache::default();

    // Range proof is present when mixed transactions are not supported, the set of
    // range proofs is present when they are.
    let (range_proof, range_proofs) = if !block_version.mixed_transactions_are_supported() {
        // The implicit fee output is omitted from the range proof because it is known.
        let generator = generator_cache.get(fee.token_id);

        let (values, blindings): (Vec<_>, Vec<_>) = pseudo_output_values_and_blindings
            .iter()
            .cloned()
            .chain(
                output_secrets
                    .iter()
                    .map(|secret| (secret.amount.value, secret.blinding)),
            )
            .unzip();
        let (range_proof, _commitments) =
            generate_range_proofs(&values, &blindings, generator, rng)?;

        (range_proof.to_bytes().to_vec(), vec![])
    } else {
        let mut range_proofs = Vec::default();

        // Collect list of of unique token ids
        let token_ids = {
            let mut token_ids = BTreeSet::default();
            token_ids.insert(fee.token_id);
            for ring in rings {
                token_ids.insert(ring.amount().token_id);
            }
            for secret in output_secrets {
                token_ids.insert(secret.amount.token_id);
            }
            token_ids
        };

        for token_id in token_ids {
            let generator = generator_cache.get(token_id);

            // The input blinding is not the same as corresponding pseudo-output blinding
            let (values, blindings): (Vec<_>, Vec<_>) =
                zip_exact(rings.iter(), pseudo_output_blindings.iter())?
                    .filter_map(|(ring, blinding)| {
                        if ring.amount().token_id == token_id {
                            Some((ring.amount().value, *blinding))
                        } else {
                            None
                        }
                    })
                    .chain(output_secrets.iter().filter_map(|secret| {
                        if secret.amount.token_id == token_id {
                            Some((secret.amount.value, secret.blinding))
                        } else {
                            None
                        }
                    }))
                    .unzip();

            if values.is_empty() {
                return Err(Error::NoCommitmentsForTokenId(token_id));
            }

            let (range_proof, _commitments) =
                generate_range_proofs(&values, &blindings, generator, rng)?;

            range_proofs.push(range_proof.to_bytes());
        }

        (vec![], range_proofs)
    };

    // The actual pseudo output commitments use the blindings from
    // `pseudo_output_blinding` and not the original true input.
    let pseudo_output_commitments: Vec<RistrettoPoint> =
        zip_exact(rings.iter(), pseudo_output_blindings.iter())?
            .map(|(ring, blinding)| {
                generator_cache
                    .get(ring.amount().token_id)
                    .commit(Scalar::from(ring.amount().value), *blinding)
            })
            .collect();

    if check_value_is_preserved {
        let sum_of_output_commitments: RistrettoPoint = output_secrets
            .iter()
            .map(|secret| {
                generator_cache
                    .get(secret.amount.token_id)
                    .commit(Scalar::from(secret.amount.value), secret.blinding)
            })
            .sum();

        let sum_of_pseudo_output_commitments: RistrettoPoint =
            pseudo_output_commitments.iter().sum();

        // The implicit fee output.
        let generator = generator_cache.get(fee.token_id);
        let fee_commitment = generator.commit(Scalar::from(fee.value), *FEE_BLINDING);

        let difference =
            sum_of_output_commitments + fee_commitment - sum_of_pseudo_output_commitments;
        // RistrettoPoint::identity() is the zero point of Ristretto group, this is the
        // same as generator.commit(Zero, Zero) and is faster.
        if difference != RistrettoPoint::identity() {
            return Err(Error::ValueNotConserved);
        }
    }

    // The actual pseudo output commitments use the blindings from
    // `pseudo_output_blinding` and not the original true input.
    let pseudo_output_commitments: Vec<CompressedCommitment> = pseudo_output_commitments
        .into_iter()
        .map(|point| CompressedCommitment::from(&point.compress()))
        .collect();

    // Extend the message with the range proof and pseudo_output_commitments.
    // This ensures that they are signed by each RingMLSAG.
    let extended_message_digest = compute_extended_message_either_version(
        block_version,
        message,
        &pseudo_output_commitments,
        &range_proof,
        &range_proofs,
    );

    // Prove that the signer is allowed to spend a public key in each ring, and that
    // the input's value equals the value of the pseudo_output.
    let ring_signatures: Vec<RingMLSAG> = rings
        .iter()
        .zip(pseudo_output_blindings)
        .map(
            |(ring, pseudo_output_blinding)| -> Result<RingMLSAG, Error> {
                Ok(match ring {
                    InputRing::Signable(ring) => {
                        let generator = generator_cache.get(ring.input_secret.amount.token_id);
                        RingMLSAG::sign(
                            &extended_message_digest,
                            &ring.members,
                            ring.real_input_index,
                            &ring.input_secret.onetime_private_key,
                            ring.input_secret.amount.value,
                            &ring.input_secret.blinding,
                            &pseudo_output_blinding,
                            generator,
                            rng,
                        )?
                    }
                    InputRing::Presigned(ring) => ring.mlsag.clone(),
                })
            },
        )
        .collect::<Result<_, _>>()?;

    let mut pseudo_output_token_ids: Vec<u64> =
        rings.iter().map(|ring| *ring.amount().token_id).collect();
    let mut output_token_ids: Vec<u64> = output_secrets
        .iter()
        .map(|secret| *secret.amount.token_id)
        .collect();

    if !block_version.mixed_transactions_are_supported() {
        pseudo_output_token_ids.clear();
        output_token_ids.clear();
        assert!(!range_proof.is_empty());
        assert!(range_proofs.is_empty());
    } else {
        assert!(range_proof.is_empty());
        assert!(!range_proofs.is_empty());
    }

    Ok(SignatureRctBulletproofs {
        ring_signatures,
        pseudo_output_commitments,
        range_proof_bytes: range_proof,
        range_proofs,
        pseudo_output_token_ids,
        output_token_ids,
    })
}

/// Computes appropriate pseudo-output blinding values for each input ring.
///
/// Arguments:
/// * The input rings, both pre-signed and signable.
/// * The output secrets
///
/// Returns:
/// * The blinding factor for each pseudo output, corresponding to each ring.
///
/// Requirements:
/// * At least one ring must not be pre-signed.
///
/// Post-conditions:
/// * The sum_of_output blindings - sum_of_pseudo_output blindings = 0
fn compute_pseudo_output_blindings<CSPRNG: RngCore + CryptoRng>(
    rings: &[InputRing],
    output_secrets: &[OutputSecret],
    rng: &mut CSPRNG,
) -> Result<Vec<Scalar>, Error> {
    // The implicit fee output is ommitted because its blinding is zero.
    //
    // Note: This implicit fee output is not the same as the accumulated fee output
    // produced by the enclave -- the blinding of that output is not zero.
    let sum_of_output_blindings: Scalar = output_secrets.iter().map(|secret| secret.blinding).sum();
    let sum_of_presigned_pseudo_output_blindings: Scalar = rings
        .iter()
        .filter_map(|ring| {
            if let InputRing::Presigned(ring) = ring {
                Some(ring.pseudo_output_secret.blinding)
            } else {
                None
            }
        })
        .sum();

    let last_unsigned_ring_index = rings
        .iter()
        .rposition(|x| matches!(x, InputRing::Signable(_)))
        .ok_or(Error::AllRingsPresigned)?;

    // The sum of all presigned pseudo output blindings, plus any that we have
    // chosen randomly for signable pseudo outputs.
    let mut running_sum = sum_of_presigned_pseudo_output_blindings;

    // Blindings for pseudo_outputs. All but the last are random.
    // Constructing blindings in this way ensures that sum_of_outputs -
    // sum_of_pseudo_outputs = 0 if the sum of outputs and the sum of
    // pseudo_outputs have equal value.
    Ok(rings
        .iter()
        .enumerate()
        .map(|(idx, ring)| {
            match ring {
                InputRing::Signable(_ring) => {
                    if idx == last_unsigned_ring_index {
                        // At this point, the running sum is the sum of all pseudo output blindings,
                        // except this one.
                        sum_of_output_blindings - running_sum
                    } else {
                        let random = Scalar::random(rng);
                        running_sum += random;
                        random
                    }
                }
                InputRing::Presigned(ring) => ring.pseudo_output_secret.blinding,
            }
        })
        .collect())
}

/// Toggles between old-style and new-style extended message
fn compute_extended_message_either_version(
    block_version: BlockVersion,
    message: &[u8],
    pseudo_output_commitments: &[CompressedCommitment],
    range_proof_bytes: &[u8],
    range_proofs: &[Vec<u8>],
) -> Vec<u8> {
    if block_version.mlsags_sign_extended_message_digest() {
        // New-style extended message using merlin
        digest_extended_message(
            message,
            pseudo_output_commitments,
            range_proof_bytes,
            range_proofs,
        )
        .to_vec()
    } else {
        // Old-style extended message
        extend_message(message, pseudo_output_commitments, range_proof_bytes)
    }
}

/// Computes a merlin digest of message, pseudo_output_commitments, range proof
fn digest_extended_message(
    message: &[u8],
    pseudo_output_commitments: &[CompressedCommitment],
    range_proof_bytes: &[u8],
    range_proofs: &[Vec<u8>],
) -> [u8; 32] {
    let mut transcript = MerlinTranscript::new(EXTENDED_MESSAGE_DOMAIN_TAG.as_bytes());
    message.append_to_transcript(b"message", &mut transcript);
    pseudo_output_commitments.append_to_transcript(b"pseudo_output_commitments", &mut transcript);
    range_proof_bytes.append_to_transcript_allow_omit(b"range_proof_bytes", &mut transcript);
    range_proofs.append_to_transcript_allow_omit(b"range_proofs", &mut transcript);

    let mut output = [0u8; 32];
    transcript.extract_digest(&mut output);
    output
}

/// Concatenates [message || pseudo_output_commitments || range_proof].
/// (Used before block version two)
fn extend_message(
    message: &[u8],
    pseudo_output_commitments: &[CompressedCommitment],
    range_proof_bytes: &[u8],
) -> Vec<u8> {
    let mut extended_message: Vec<u8> = Vec::with_capacity(
        message.len() + pseudo_output_commitments.len() * 32 + range_proof_bytes.len(),
    );
    extended_message.extend_from_slice(message);
    for commitment in pseudo_output_commitments {
        extended_message.extend_from_slice(commitment.as_ref());
    }
    extended_message.extend_from_slice(range_proof_bytes);
    extended_message
}

impl From<&SignableInputRing> for SignedInputRing {
    fn from(src: &SignableInputRing) -> SignedInputRing {
        SignedInputRing {
            members: src.members.clone(),
            signed_digest: None,
        }
    }
}

#[cfg(test)]
mod rct_bulletproofs_tests {
    use super::*;
    use crate::{
        range_proofs::generate_range_proofs,
        ring_signature::{generators, Error, KeyImage, PedersenGens},
        CompressedCommitment, TokenId,
    };
    use alloc::vec::Vec;
    use assert_matches::assert_matches;
    use core::convert::TryInto;
    use curve25519_dalek::scalar::Scalar;
    use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPrivate, RistrettoPublic};
    use mc_util_from_random::FromRandom;
    use proptest::prelude::*;
    use rand::{rngs::StdRng, CryptoRng, SeedableRng};
    use rand_core::RngCore;

    extern crate std;

    struct SignatureParams {
        /// Message to be signed.
        message: [u8; 32],

        /// Rings of input onetime addresses and amount commitments.
        rings: Vec<SignableInputRing>,

        /// Value and blinding for each output amount commitment.
        output_secrets: Vec<OutputSecret>,

        /// Block Version
        block_version: BlockVersion,

        /// Token id
        fee_token_id: TokenId,
    }

    impl SignatureParams {
        fn generator(&self) -> PedersenGens {
            generators(*self.fee_token_id)
        }

        fn random<RNG: RngCore + CryptoRng>(
            block_version: BlockVersion,
            num_inputs: usize,
            num_mixins: usize,
            rng: &mut RNG,
        ) -> Self {
            Self::random_mixed(block_version, num_inputs, num_mixins, 1, rng)
        }

        fn random_mixed<RNG: RngCore + CryptoRng>(
            block_version: BlockVersion,
            num_inputs: usize,
            num_mixins: usize,
            num_token_ids: usize,
            rng: &mut RNG,
        ) -> Self {
            let mut message = [0u8; 32];
            rng.fill_bytes(&mut message);

            if !block_version.mixed_transactions_are_supported() && num_token_ids != 1 {
                panic!("more than one token id not supported at this block version");
            }

            let mut token_ids: Vec<u64> = (0..num_token_ids).map(|_| rng.next_u64()).collect();

            if !block_version.masked_token_id_feature_is_supported() {
                token_ids[0] = 0;
            }

            // First token id is the fee
            let fee_token_id = TokenId::from(token_ids[0]);

            let mut generator_cache = GeneratorCache::default();

            let mut rings = Vec::new();

            for i in 0..num_inputs {
                let mut ring_members: Vec<(CompressedRistrettoPublic, CompressedCommitment)> =
                    Vec::new();
                // Create random mixins.
                for _i in 0..num_mixins {
                    let generator = generator_cache.get(fee_token_id);
                    let address =
                        CompressedRistrettoPublic::from(RistrettoPublic::from_random(rng));
                    let commitment = {
                        let value = rng.next_u64();
                        let blinding = Scalar::random(rng);
                        CompressedCommitment::new(value, blinding, generator)
                    };
                    ring_members.push((address, commitment));
                }
                // The real input.
                let onetime_private_key = RistrettoPrivate::from_random(rng);
                let onetime_public_key =
                    CompressedRistrettoPublic::from(RistrettoPublic::from(&onetime_private_key));

                let value = rng.next_u64();
                let blinding = Scalar::random(rng);

                let token_id = TokenId::from(token_ids[i % token_ids.len()]);
                let generator = generator_cache.get(token_id);

                let commitment = CompressedCommitment::new(value, blinding, generator);

                let real_input_index = rng.next_u64() as usize % (num_mixins + 1);
                ring_members.insert(real_input_index, (onetime_public_key, commitment));

                rings.push(SignableInputRing {
                    members: ring_members,
                    real_input_index,
                    input_secret: InputSecret {
                        onetime_private_key,
                        amount: Amount::new(value, token_id),
                        blinding,
                    },
                });
            }

            // Create one output with the same value as each input.
            let output_secrets: Vec<_> = rings
                .iter()
                .map(|ring| {
                    let blinding = Scalar::random(rng);
                    OutputSecret {
                        amount: ring.input_secret.amount,
                        blinding,
                    }
                })
                .collect();

            SignatureParams {
                message,
                rings,
                output_secrets,
                block_version,
                fee_token_id,
            }
        }

        fn get_output_commitments(&self) -> Vec<CompressedCommitment> {
            self.output_secrets
                .iter()
                .map(|secret| {
                    CompressedCommitment::new(
                        secret.amount.value,
                        secret.blinding,
                        &generators(*secret.amount.token_id),
                    )
                })
                .collect()
        }

        fn get_signed_input_rings(&self) -> Vec<SignedInputRing> {
            self.rings.iter().map(SignedInputRing::from).collect()
        }

        fn get_input_rings(&self) -> Vec<InputRing> {
            self.rings
                .iter()
                .cloned()
                .map(InputRing::Signable)
                .collect()
        }

        fn sign<RNG: RngCore + CryptoRng>(
            &self,
            fee: u64,
            rng: &mut RNG,
        ) -> Result<SignatureRctBulletproofs, Error> {
            SignatureRctBulletproofs::sign(
                self.block_version,
                &self.message,
                &self.get_input_rings(),
                &self.output_secrets,
                Amount::new(fee, self.fee_token_id),
                rng,
            )
        }

        fn sign_without_balance_check<RNG: RngCore + CryptoRng>(
            &self,
            fee: u64,
            rng: &mut RNG,
        ) -> Result<SignatureRctBulletproofs, Error> {
            sign_with_balance_check(
                self.block_version,
                &self.message,
                &self.get_input_rings(),
                &self.output_secrets,
                Amount::new(fee, self.fee_token_id),
                false,
                rng,
            )
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(6))]

        #[test]
        // `sign`should return an error if `rings` is empty.
        fn sign_rejects_empty_rings(
            num_inputs in 1..8usize,
            num_mixins in 1..17usize,
            seed in any::<[u8; 32]>(),
            block_version in 1..=3u32,
        ) {
            let block_version: BlockVersion = block_version.try_into().unwrap();
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let mut params = SignatureParams::random(block_version, num_inputs, num_mixins, &mut rng);
            params.rings = Vec::new();

            let result = params.sign(0, &mut rng);

            match result {
                Err(Error::NoInputs) => {} // OK,
                _ => panic!(),
            }
        }

        #[test]
        // `sign`should return an error if `rings[0]` is empty.
        // The first ring is used to infer the ring size.
        fn sign_rejects_empty_rings_zero(
            num_inputs in 1..8usize,
            num_mixins in 1..17usize,
            seed in any::<[u8; 32]>(),
            block_version in 1..=3u32,
        ) {
            let block_version: BlockVersion = block_version.try_into().unwrap();
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let mut params = SignatureParams::random(block_version, num_inputs, num_mixins, &mut rng);
            params.rings[0].members = Vec::new();

            let result = params.sign(0, &mut rng);

            match result {
                Err(Error::InvalidRingSize(0)) => {} // OK,
                _ => panic!(),
            }
        }

        #[test]
        // `sign` should produce a signature with one ring signature and one pseudo-output per input.
        fn sign_signature_has_correct_lengths(
            num_inputs in 1..8usize,
            num_mixins in 1..17usize,
            seed in any::<[u8; 32]>(),
            block_version in 1..=3u32,
        ) {
            let block_version: BlockVersion = block_version.try_into().unwrap();
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let params = SignatureParams::random(block_version, num_inputs, num_mixins, &mut rng);
            let signature = params.sign(0, &mut rng).unwrap();

            // The signature must contain one ring signature per input.
            assert_eq!(signature.ring_signatures.len(), num_inputs);

            // The signature must contain one pseudo-output per input.
            assert_eq!(signature.pseudo_output_commitments.len(), num_inputs);

            let ring_size = num_mixins + 1;
            for ring_signature in &signature.ring_signatures {
                assert_eq!(ring_signature.responses.len(), 2 * ring_size);
            }
        }

        #[test]
        // `verify` should accept valid signatures.
        fn verify_accepts_valid_signatures(
            num_inputs in 1..8usize,
            num_mixins in 1..17usize,
            seed in any::<[u8; 32]>(),
            block_version in 1..=3u32,
        ) {
            let block_version: BlockVersion = block_version.try_into().unwrap();
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let params = SignatureParams::random(block_version, num_inputs, num_mixins, &mut rng);
            let fee = 0;
            let signature = params.sign(fee, &mut rng).unwrap();

            let result = signature.verify(
                block_version,
                &params.message,
                &params.get_signed_input_rings(),
                &params.get_output_commitments(),
                Amount::new(fee, params.fee_token_id),
                &mut rng,
            );
            result.unwrap();
        }

        #[test]
        // `verify` should accept valid signatures with mixed token ids.
        fn verify_accepts_valid_signatures_mixed_token_ids(
            num_inputs in 1..8usize,
            num_mixins in 1..17usize,
            num_token_ids in 2..4usize,
            seed in any::<[u8; 32]>(),
            block_version in 3..=3u32,
        ) {
            let block_version: BlockVersion = block_version.try_into().unwrap();
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let params = SignatureParams::random_mixed(block_version, num_inputs, num_mixins, num_token_ids, &mut rng);
            let fee = 0;
            let signature = params.sign(fee, &mut rng).unwrap();

            let result = signature.verify(
                block_version,
                &params.message,
                &params.get_signed_input_rings(),
                &params.get_output_commitments(),
                Amount::new(fee, params.fee_token_id),
                &mut rng,
            );
            result.unwrap();
        }

        #[test]
        // `verify` should reject a signature that contains an invalid MLSAG signature.
        fn test_verify_rejects_signature_signed_with_invalid_mlsag(
            num_inputs in 1..8usize,
            num_mixins in 1..17usize,
            seed in any::<[u8; 32]>(),
            block_version in 1..=3u32,
        ) {
            let block_version: BlockVersion = block_version.try_into().unwrap();
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let params = SignatureParams::random(block_version, num_inputs, num_mixins, &mut rng);
            let fee = 0;

            let mut signature = params.sign(fee, &mut rng).unwrap();

            // Modify an MLSAG ring signature
            let index = rng.next_u64() as usize % (num_inputs);
            signature.ring_signatures[index].key_image = KeyImage::from(rng.next_u64());

            let result = signature.verify(
                block_version,
                &params.message,
                &params.get_signed_input_rings(),
                &params.get_output_commitments(),
                Amount::new(fee, params.fee_token_id),
                &mut rng,
            );

            assert_eq!(result, Err(Error::InvalidSignature));
        }

        #[test]
        // `verify` rejects a signature if the sum of the outputs minus the sum of the pseudo-outputs is not zero.
        fn test_verify_rejects_signature_when_value_not_conserved(
            num_inputs in 1..8usize,
            num_mixins in 1..17usize,
            seed in any::<[u8; 32]>(),
            block_version in 1..=3u32,
        ) {
            let block_version: BlockVersion = block_version.try_into().unwrap();
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let mut params = SignatureParams::random(block_version, num_inputs, num_mixins, &mut rng);
            let fee = 0;
            // Modify an output value
            {
                let index = rng.next_u64() as usize % (num_inputs);
                params.output_secrets[index].amount.value = rng.next_u64();
            }

            // Sign, without checking that value is preserved.
            let invalid_signature = params.sign_without_balance_check(fee, &mut rng).unwrap();

            let result = invalid_signature.verify(
                block_version,
                &params.message,
                &params.get_signed_input_rings(),
                &params.get_output_commitments(),
                Amount::new(fee, params.fee_token_id),
                &mut rng,
            );

            assert_eq!(result, Err(Error::ValueNotConserved));
        }

        #[test]
        // `verify` rejects a signature with invalid range proof.
        fn test_verify_rejects_signature_with_invalid_range_proof(
            num_inputs in 1..8usize,
            num_mixins in 1..17usize,
            seed in any::<[u8; 32]>(),
            block_version in 1..=2u32,
        ) {
            let block_version: BlockVersion = block_version.try_into().unwrap();
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let params = SignatureParams::random(block_version, num_inputs, num_mixins, &mut rng);
            let fee = 0;
            let mut signature = params.sign(fee, &mut rng).unwrap();

            // Modify the range proof
            let wrong_range_proof = {
                let values = [13; 6];
                let blindings: Vec<Scalar> = values
                    .iter()
                    .map(|_value| Scalar::random(&mut rng))
                    .collect();
                let (range_proof, _commitments) =
                    generate_range_proofs(&values, &blindings, &params.generator(), &mut rng).unwrap();
                range_proof
            };

            signature.range_proof_bytes = wrong_range_proof.to_bytes();

            let result = signature.verify(
                block_version,
                &params.message,
                &params.get_signed_input_rings(),
                &params.get_output_commitments(),
                Amount::new(fee, params.fee_token_id),
                &mut rng,
            );

            assert_matches!(result, Err(Error::RangeProof(_)));
        }

        #[test]
        // `verify` rejects a signature with invalid range proof, block version >=3.
        fn test_verify_rejects_signature_with_invalid_range_proof_block_version3(
            num_inputs in 1..8usize,
            num_mixins in 1..17usize,
            seed in any::<[u8; 32]>(),
            block_version in 3..=3u32,
        ) {
            let block_version: BlockVersion = block_version.try_into().unwrap();
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let params = SignatureParams::random(block_version, num_inputs, num_mixins, &mut rng);
            let fee = 0;
            let mut signature = params.sign(fee, &mut rng).unwrap();

            // Modify the range proof
            let wrong_range_proof = {
                let values = [13; 6];
                let blindings: Vec<Scalar> = values
                    .iter()
                    .map(|_value| Scalar::random(&mut rng))
                    .collect();
                let (range_proof, _commitments) =
                    generate_range_proofs(&values, &blindings, &params.generator(), &mut rng).unwrap();
                range_proof
            };

            signature.range_proofs[0] = wrong_range_proof.to_bytes();

            let result = signature.verify(
                block_version,
                &params.message,
                &params.get_signed_input_rings(),
                &params.get_output_commitments(),
                Amount::new(fee, params.fee_token_id),
                &mut rng,
            );


            assert_matches!(result, Err(Error::RangeProof(_)));
        }

        #[test]
        // `verify` rejects a signature that spends the same input in two different rings.
        fn test_verify_rejects_signature_with_duplicate_key_images(
            num_inputs in 4..8usize,
            num_mixins in 1..17usize,
            seed in any::<[u8; 32]>(),
            block_version in 1..=3u32,
        ) {
            let block_version: BlockVersion = block_version.try_into().unwrap();
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let mut params = SignatureParams::random(block_version, num_inputs, num_mixins, &mut rng);
            let fee = 0;

            // Duplicate one of the rings.
            params.rings[2] = params.rings[3].clone();
            // Duplicate the corresponding output also, so we don't get "value not conserved" error
            params.output_secrets[2].amount = params.output_secrets[3].amount;

            let signature = params.sign(fee, &mut rng).unwrap();

            let result = signature.verify(
                block_version,
                &params.message,
                &params.get_signed_input_rings(),
                &params.get_output_commitments(),
                Amount::new(fee, params.fee_token_id),
                &mut rng,
            );

            assert_eq!(result, Err(Error::DuplicateKeyImage));
        }

        #[test]
        // decode(encode(&signature)) should be the identity function.
        fn test_encode_decode(
            num_inputs in 4..8usize,
            num_mixins in 1..17usize,
            seed in any::<[u8; 32]>(),
            block_version in 1..=3u32,
        ) {
            let block_version: BlockVersion = block_version.try_into().unwrap();
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let params = SignatureParams::random(block_version, num_inputs, num_mixins, &mut rng);
            let fee = 0;
            let signature = params.sign(fee, &mut rng).unwrap();

            use mc_util_serial::prost::Message;

            // The encoded bytes should have the correct length.
            let bytes = mc_util_serial::encode(&signature);
            assert_eq!(bytes.len(), signature.encoded_len());

            // decode(encode(&signature)) should be the identity function.
            let recovered_signature : SignatureRctBulletproofs = mc_util_serial::decode(&bytes).unwrap();
            assert_eq!(signature, recovered_signature);
        }

        #[test]
        // `verify` should accept valid signatures with correct fee.
        fn verify_with_fee(
            num_inputs in 2..8usize,
            num_mixins in 1..17usize,
            seed in any::<[u8; 32]>(),
            block_version in 1..=3u32,
        ) {
            let block_version: BlockVersion = block_version.try_into().unwrap();
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let mut params = SignatureParams::random(block_version, num_inputs, num_mixins, &mut rng);
            // Remove one of the outputs, and use its value as the fee. This conserves value.
            let popped_secret = params.output_secrets.pop().unwrap();
            let fee = popped_secret.amount.value;

            let signature = params.sign(fee, &mut rng).unwrap();

            let result = signature.verify(
                block_version,
                &params.message,
                &params.get_signed_input_rings(),
                &params.get_output_commitments(),
                Amount::new(fee, params.fee_token_id),
                &mut rng,
            );
            result.unwrap();

            // Verify should fail if the signature disagrees with the fee.
            let wrong_fee = fee + 1;
            match signature.verify(
                block_version,
                &params.message,
                &params.get_signed_input_rings(),
                &params.get_output_commitments(),
                Amount::new(wrong_fee, params.fee_token_id),
                &mut rng,
            ) {
                Err(Error::ValueNotConserved) => {} // Expected
                Err(e) => {
                    panic!("Unexpected error {}", e);
                }
                _ => panic!("Unexpected success")
            }
        }

        #[test]
        // block version one signatures should not validate at block version two
        fn validate_block_version_one_as_two_should_fail(
            num_inputs in 2..8usize,
            num_mixins in 1..17usize,
            seed in any::<[u8; 32]>(),
        ) {
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let mut params = SignatureParams::random(BlockVersion::ONE, num_inputs, num_mixins, &mut rng);
            // Remove one of the outputs, and use its value as the fee. This conserves value.
            let popped_secret = params.output_secrets.pop().unwrap();
            let fee = popped_secret.amount.value;

            let signature = params.sign(fee, &mut rng).unwrap();

            let result = signature.verify(
                BlockVersion::TWO,
                &params.message,
                &params.get_signed_input_rings(),
                &params.get_output_commitments(),
                Amount::new(fee, params.fee_token_id),
                &mut rng,
            );
            assert!(result.is_err());
        }

        #[test]
        // block version two signatures should not validate at block version one
        fn validate_block_version_two_as_one_should_fail(
            num_inputs in 2..8usize,
            num_mixins in 1..17usize,
            seed in any::<[u8; 32]>(),
        ) {
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let mut params = SignatureParams::random(BlockVersion::TWO, num_inputs, num_mixins, &mut rng);
            // Remove one of the outputs, and use its value as the fee. This conserves value.
            let popped_secret = params.output_secrets.pop().unwrap();
            let fee = popped_secret.amount.value;

            let signature = params.sign(fee, &mut rng).unwrap();

            let result = signature.verify(
                BlockVersion::ONE,
                &params.message,
                &params.get_signed_input_rings(),
                &params.get_output_commitments(),
                Amount::new(fee, params.fee_token_id),
                &mut rng,
            );
            assert!(result.is_err());
        }

        #[test]
        // block version two signatures should not validate if we change the token id
        fn validate_block_version_two_with_changed_token_id_should_fail(
            num_inputs in 2..8usize,
            num_mixins in 1..17usize,
            seed in any::<[u8; 32]>(),
        ) {
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let mut params = SignatureParams::random(BlockVersion::TWO, num_inputs, num_mixins, &mut rng);
            // Remove one of the outputs, and use its value as the fee. This conserves value.
            let popped_secret = params.output_secrets.pop().unwrap();
            let fee = popped_secret.amount.value;

            let signature = params.sign(fee, &mut rng).unwrap();

            signature.verify(
                BlockVersion::TWO,
                &params.message,
                &params.get_signed_input_rings(),
                &params.get_output_commitments(),
                Amount::new(fee, params.fee_token_id),
                &mut rng,
            ).unwrap();


            let result = signature.verify(
                BlockVersion::TWO,
                &params.message,
                &params.get_signed_input_rings(),
                &params.get_output_commitments(),
                Amount::new(fee, TokenId::from(*params.fee_token_id + 1)),
                &mut rng,
            );

            assert_matches!(result, Err(Error::RangeProof(_)));
        }

        #[test]
        // block version one signatures should not work if token id is not zero
        fn validate_block_version_one_with_token_id_should_fail(
            num_inputs in 2..8usize,
            num_mixins in 1..17usize,
            seed in any::<[u8; 32]>(),
        ) {
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let mut params = SignatureParams::random(BlockVersion::ONE, num_inputs, num_mixins, &mut rng);
            // Remove one of the outputs, and use its value as the fee. This conserves value.
            let popped_secret = params.output_secrets.pop().unwrap();
            let fee = popped_secret.amount.value;

            params.fee_token_id = 1.into();

            assert_eq!(params.sign(fee, &mut rng), Err(Error::TokenIdNotAllowed));
        }

        #[test]
        // signatures with mixed tokens should not work if the output token ids are tampered with
        fn test_verify_signature_rejects_change_to_output_token_id(
            num_inputs in 2..8usize,
            num_mixins in 1..17usize,
            num_token_ids in 2..4usize,
            seed in any::<[u8; 32]>(),
            block_version in 3..=3u32,
        ) {
            let block_version = BlockVersion::try_from(block_version).unwrap();
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let params = SignatureParams::random_mixed(block_version, num_inputs, num_mixins,num_token_ids, &mut rng);

            let fee = 0;
            let mut signature = params.sign(fee, &mut rng).unwrap();

            signature.verify(
                block_version,
                &params.message,
                &params.get_signed_input_rings(),
                &params.get_output_commitments(),
                Amount::new(fee, params.fee_token_id),
                &mut rng,
            ).unwrap();

            signature.output_token_ids[0] = signature.output_token_ids[1];

            let result = signature.verify(
                block_version,
                &params.message,
                &params.get_signed_input_rings(),
                &params.get_output_commitments(),
                Amount::new(fee, params.fee_token_id),
                &mut rng,
            );

            assert_matches!(result, Err(Error::RangeProof(_)));
        }

        #[test]
        // signatures with mixed tokens should not work if the pseudo-output token ids are tampered with
        fn test_verify_signature_rejects_change_to_pseudo_output_token_id(
            num_inputs in 2..8usize,
            num_mixins in 1..17usize,
            num_token_ids in 2..4usize,
            seed in any::<[u8; 32]>(),
            block_version in 3..=3u32,
        ) {
            let block_version = BlockVersion::try_from(block_version).unwrap();
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            let params = SignatureParams::random_mixed(block_version, num_inputs, num_mixins, num_token_ids, &mut rng);

            let fee = 0;
            let mut signature = params.sign(fee, &mut rng).unwrap();

            signature.verify(
                block_version,
                &params.message,
                &params.get_signed_input_rings(),
                &params.get_output_commitments(),
                Amount::new(fee, params.fee_token_id),
                &mut rng,
            ).unwrap();

            signature.pseudo_output_token_ids[0] = signature.pseudo_output_token_ids[1];

            let result = signature.verify(
                block_version,
                &params.message,
                &params.get_signed_input_rings(),
                &params.get_output_commitments(),
                Amount::new(fee, params.fee_token_id),
                &mut rng,
            );

            assert_matches!(result, Err(Error::RangeProof(_)));
        }

    } // end proptest
}
