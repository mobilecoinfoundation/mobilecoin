// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Multi-signature implementation: A multi-signature is a protocol that allows
//! a group of signers, each possessing a distinct private/public keypair, to
//! produce a joint signature on a common message. The simplest multi-signature
//! of a message is just a set of signatures containing one signature over the
//! message from each member of the signing group. We say that a multi-signature
//! is a m-of-n threshold signature if only k valid signatures are required from
//! a signing group of size n.

#![cfg_attr(not(test), no_std)]
#![deny(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;
use core::hash::Hash;
use mc_crypto_digestible::Digestible;
use mc_crypto_keys::{PublicKey, Signature, SignatureError, Verifier};
use prost::Message;
use serde::{Deserialize, Serialize};

/// The maximum number of signatures that can be included in a multi-signature.
pub const MAX_SIGNATURES: usize = 10;

/// A multi-signature: a collection of one or more signatures.
#[derive(
    Clone, Deserialize, Digestible, Eq, Hash, Message, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct MultiSig<
    S: Clone
        + Default
        + Digestible
        + Eq
        + Hash
        + Message
        + Ord
        + PartialEq
        + PartialOrd
        + Serialize
        + Signature,
> {
    #[prost(message, repeated, tag = "1")]
    signatures: Vec<S>,
}

impl<
        S: Clone
            + Default
            + Digestible
            + Eq
            + Hash
            + Message
            + Ord
            + PartialEq
            + PartialOrd
            + Serialize
            + Signature,
    > MultiSig<S>
{
    /// Construct a new multi-signature from a collection of signatures.
    pub fn new(signatures: Vec<S>) -> Self {
        Self { signatures }
    }

    /// Get signatures
    pub fn signatures(&self) -> &[S] {
        &self.signatures
    }
}

/// A set of M-out-of-N signer identities, where a signer identity can be either
/// a public key or a nested M-out-of-N set of identities.
#[derive(
    Clone, Deserialize, Digestible, Eq, Hash, Message, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(bound = "")]
pub struct SignerSet<P: Default + PublicKey + Message> {
    /// List of potential individual signers.
    #[prost(message, repeated, tag = "1")]
    #[digestible(name = "signers")]
    individual_signers: Vec<P>,

    /// List of potential sets of signers. This allows us to declare a nested
    /// multi-signature scheme. Ideally the two arrays in this struct would be
    /// combined into a single one that holds an enum of (IndividualSigner,
    /// MultiSignerSet), but since this feature was added after we went live
    /// and instances of SignerSet made their way into the ledger, it is not
    /// possible to change the array type without breaking backwards
    /// compatibility. This is also the reason the tag numbers in the struct
    /// are not sequential.
    #[prost(message, repeated, tag = "3")]
    multi_signers: Vec<SignerSet<P>>,

    /// Minimum number of signers required. The potential signers are the union
    /// of `sigenrs` and `signer_sets` This implies that the upper limit
    /// (the total number of possible signers) is `signers.len() +
    /// signer_sets.len()`).
    #[prost(uint32, tag = "2")]
    threshold: u32,
}

impl<P: Default + PublicKey + Message> SignerSet<P> {
    /// Construct a new `SignerSet` from a list of public keys and threshold.
    pub fn new(individual_signers: Vec<P>, multi_signers: Vec<Self>, threshold: u32) -> Self {
        Self {
            individual_signers,
            multi_signers,
            threshold,
        }
    }

    /// Get the list of potential individual signers.
    pub fn individual_signers(&self) -> &[P] {
        &self.individual_signers
    }

    /// Get the list of potential multi signers.
    pub fn multi_signers(&self) -> &[SignerSet<P>] {
        &self.multi_signers
    }

    /// Get the total number of signers in this set.
    /// This is the sum of the number of individual signers and the number of
    /// signer sets.
    pub fn num_signers(&self) -> usize {
        self.individual_signers.len() + self.multi_signers.len()
    }

    /// Get the threshold.
    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    /// Check if this signer set is valid.
    /// A signer set is considered valid if:
    /// - All nested signer sets underneath it are also valid
    /// - It has a threshold of at least one
    /// - The number of signers is greater than or equal to the threshold.
    pub fn is_valid(&self) -> bool {
        // All nested sets must be valid
        for signer_set in &self.multi_signers {
            if !signer_set.is_valid() {
                return false;
            }
        }

        0 < self.threshold && self.threshold as usize <= self.num_signers()
    }

    /// Verify a message against a multi-signature, returning the list of
    /// signers that signed it.
    pub fn verify<
        S: Clone
            + Default
            + Digestible
            + Eq
            + Hash
            + Message
            + Ord
            + PartialEq
            + PartialOrd
            + Serialize
            + Signature,
    >(
        &self,
        message: &[u8],
        multi_sig: &MultiSig<S>,
    ) -> Result<Vec<P>, SignatureError>
    where
        P: Verifier<S>,
    {
        // Refuse to validate anything if we have an invalid signer set.
        if !self.is_valid() {
            return Err(SignatureError::new());
        }

        // If the signature contains less than the threshold number of signers or more
        // than the hardcoded limit, there's no point in trying.
        if multi_sig.signatures.len() < self.threshold as usize
            || multi_sig.signatures.len() > MAX_SIGNATURES
        {
            return Err(SignatureError::new());
        }

        // Sort and dedup the list of signers and signatures.
        // While the verification code below should be immune to duplicate signers or
        // signatures, the overhead of deduping them is negligible and being
        // extra-safe is a good idea.
        let mut potential_individual_signers = self.individual_signers.clone();
        potential_individual_signers.sort();
        potential_individual_signers.dedup();

        let mut potential_multi_signers = self.multi_signers.clone();
        potential_multi_signers.sort();
        potential_multi_signers.dedup();

        let mut signatures = multi_sig.signatures.clone();
        signatures.sort_by(|a, b| a.as_ref().cmp(b.as_ref()));
        signatures.dedup();

        // Collect individual signer identities that signed the message, and count how
        // many signers we successfully matched.
        let mut matched_signer_identities = Vec::new();
        let mut num_matches = 0;

        for individual_signer in potential_individual_signers {
            if signatures
                .iter()
                .any(|sig| individual_signer.verify(message, sig).is_ok())
            {
                num_matches += 1;
                matched_signer_identities.push(individual_signer);
            }
        }

        // See if any multi-signer sets signed the message.
        for signer_set in potential_multi_signers {
            if let Ok(signer_identities) = signer_set.verify(message, multi_sig) {
                matched_signer_identities.extend(signer_identities);
                num_matches += 1;
            }
        }

        // Did we pass the threshold of verified signatures?
        if num_matches < self.threshold as usize {
            return Err(SignatureError::new());
        }

        Ok(matched_signer_identities)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::vec;
    use mc_crypto_keys::{Ed25519Pair, Ed25519Public, Signer};
    use mc_util_from_random::FromRandom;
    use rand_core::SeedableRng;
    use rand_hc::Hc128Rng;

    /// Helper method for comparing two signers list.
    /// In other places in the code we might convert to a HashSet first and then
    /// compare, but that would hide duplicate elements and we want to catch
    /// that.
    #[track_caller]
    fn assert_eq_ignore_order(mut a: Vec<Ed25519Public>, mut b: Vec<Ed25519Public>) {
        a.sort();
        b.sort();

        assert_eq!(a, b);
    }

    #[test]
    fn ed25519_verify_signers_sanity_k_equals_3() {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);
        let signer1 = Ed25519Pair::from_random(&mut rng);
        let signer2 = Ed25519Pair::from_random(&mut rng);
        let signer3 = Ed25519Pair::from_random(&mut rng);
        let signer4 = Ed25519Pair::from_random(&mut rng);
        let signer5 = Ed25519Pair::from_random(&mut rng);

        let signer_set = SignerSet::new(
            vec![
                signer1.public_key(),
                signer2.public_key(),
                signer3.public_key(),
            ],
            vec![],
            2,
        );
        let message = b"this is a test";

        // Try with just one valid signature, we should fail to verify.
        let multi_sig = MultiSig::new(vec![signer1.try_sign(message.as_ref()).unwrap()]);
        assert!(signer_set.verify(message.as_ref(), &multi_sig).is_err());

        // With two valid signatures we should succeed to verify and get the correct
        // keys back.
        let multi_sig = MultiSig::new(vec![
            signer1.try_sign(message.as_ref()).unwrap(),
            signer3.try_sign(message.as_ref()).unwrap(),
        ]);
        assert_eq_ignore_order(
            signer_set.verify(message.as_ref(), &multi_sig).unwrap(),
            vec![signer1.public_key(), signer3.public_key()],
        );

        // If we alter the message, we should not pass verification.
        let message2 = b"different message";
        assert!(signer_set.verify(message2.as_ref(), &multi_sig).is_err());

        // With three valid signatures we should succeed to verify and get the correct
        // keys back.
        let multi_sig = MultiSig::new(vec![
            signer1.try_sign(message.as_ref()).unwrap(),
            signer2.try_sign(message.as_ref()).unwrap(),
            signer3.try_sign(message.as_ref()).unwrap(),
        ]);
        assert_eq_ignore_order(
            signer_set.verify(message.as_ref(), &multi_sig).unwrap(),
            vec![
                signer1.public_key(),
                signer2.public_key(),
                signer3.public_key(),
            ],
        );

        // Trying to cheat by signing twice with the same signer will not work.
        let multi_sig = MultiSig::new(vec![
            signer1.try_sign(message.as_ref()).unwrap(),
            signer1.try_sign(message.as_ref()).unwrap(),
        ]);
        assert!(signer_set.verify(message.as_ref(), &multi_sig).is_err());

        // Using an unknown signer should not allow us to verify is we are under the
        // threshold
        let multi_sig = MultiSig::new(vec![
            signer1.try_sign(message.as_ref()).unwrap(),
            signer4.try_sign(message.as_ref()).unwrap(),
        ]);
        assert!(signer_set.verify(message.as_ref(), &multi_sig).is_err());

        // Using an unknown signer does not get in the way of verifiying a valid set.
        let multi_sig = MultiSig::new(vec![
            signer1.try_sign(message.as_ref()).unwrap(),
            signer3.try_sign(message.as_ref()).unwrap(),
            signer4.try_sign(message.as_ref()).unwrap(),
        ]);
        assert_eq_ignore_order(
            signer_set.verify(message.as_ref(), &multi_sig).unwrap(),
            vec![signer1.public_key(), signer3.public_key()],
        );

        // Bunch of duplicate signers and signatures, all do not match.
        let multi_sig = MultiSig::new(vec![
            signer4.try_sign(message.as_ref()).unwrap(),
            signer4.try_sign(message.as_ref()).unwrap(),
            signer5.try_sign(message.as_ref()).unwrap(),
            signer5.try_sign(message.as_ref()).unwrap(),
            signer4.try_sign(message.as_ref()).unwrap(),
        ]);
        assert!(signer_set.verify(message.as_ref(), &multi_sig).is_err());
    }

    #[test]
    fn ed25519_verify_signers_sanity_k_equals_1() {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);
        let signer1 = Ed25519Pair::from_random(&mut rng);
        let signer2 = Ed25519Pair::from_random(&mut rng);
        let signer3 = Ed25519Pair::from_random(&mut rng);
        let signer4 = Ed25519Pair::from_random(&mut rng);
        let signer5 = Ed25519Pair::from_random(&mut rng);

        let signer_set = SignerSet::new(
            vec![
                signer1.public_key(),
                signer2.public_key(),
                signer3.public_key(),
            ],
            vec![],
            1,
        );
        let message = b"this is a test";

        // Try with just no valid signatures, we should fail to verify.
        let multi_sig = MultiSig::new(vec![signer4.try_sign(message.as_ref()).unwrap()]);
        assert!(signer_set.verify(message.as_ref(), &multi_sig).is_err());

        let multi_sig = MultiSig::new(vec![
            signer4.try_sign(message.as_ref()).unwrap(),
            signer4.try_sign(message.as_ref()).unwrap(),
        ]);
        assert!(signer_set.verify(message.as_ref(), &multi_sig).is_err());

        let multi_sig = MultiSig::new(vec![
            signer4.try_sign(message.as_ref()).unwrap(),
            signer5.try_sign(message.as_ref()).unwrap(),
        ]);
        assert!(signer_set.verify(message.as_ref(), &multi_sig).is_err());

        // Add a valid signer, we should now verify successfully.
        let multi_sig = MultiSig::new(vec![
            signer4.try_sign(message.as_ref()).unwrap(),
            signer5.try_sign(message.as_ref()).unwrap(),
            signer1.try_sign(message.as_ref()).unwrap(),
        ]);
        assert_eq_ignore_order(
            signer_set.verify(message.as_ref(), &multi_sig).unwrap(),
            vec![signer1.public_key()],
        );

        // With two valid signers we should get both back.
        let multi_sig = MultiSig::new(vec![
            signer4.try_sign(message.as_ref()).unwrap(),
            signer5.try_sign(message.as_ref()).unwrap(),
            signer1.try_sign(message.as_ref()).unwrap(),
            signer2.try_sign(message.as_ref()).unwrap(),
        ]);
        assert_eq_ignore_order(
            signer_set.verify(message.as_ref(), &multi_sig).unwrap(),
            vec![signer1.public_key(), signer2.public_key()],
        );

        // Add the same valid signers, they should not be returned twice.
        let multi_sig = MultiSig::new(vec![
            signer1.try_sign(message.as_ref()).unwrap(),
            signer2.try_sign(message.as_ref()).unwrap(),
            signer4.try_sign(message.as_ref()).unwrap(),
            signer5.try_sign(message.as_ref()).unwrap(),
            signer1.try_sign(message.as_ref()).unwrap(),
            signer2.try_sign(message.as_ref()).unwrap(),
            signer1.try_sign(message.as_ref()).unwrap(),
            signer2.try_sign(message.as_ref()).unwrap(),
        ]);
        assert_eq_ignore_order(
            signer_set.verify(message.as_ref(), &multi_sig).unwrap(),
            vec![signer1.public_key(), signer2.public_key()],
        );
    }

    #[test]
    fn ed25519_verify_with_duplicate_signers() {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);
        let signer1 = Ed25519Pair::from_random(&mut rng);
        let signer2 = Ed25519Pair::from_random(&mut rng);
        let signer3 = Ed25519Pair::from_random(&mut rng);
        let signer4 = Ed25519Pair::from_random(&mut rng);
        let signer5 = Ed25519Pair::from_random(&mut rng);

        // This signer set contains duplicate public keys but when verifying we should
        // not see the same key twice.
        let signer_set = SignerSet::new(
            vec![
                signer1.public_key(),
                signer2.public_key(),
                signer1.public_key(),
                signer2.public_key(),
                signer3.public_key(),
                signer1.public_key(),
                signer2.public_key(),
            ],
            vec![],
            1,
        );
        let message = b"this is a test";

        // Try with just no valid signatures, we should fail to verify.
        let multi_sig = MultiSig::new(vec![signer4.try_sign(message.as_ref()).unwrap()]);
        assert!(signer_set.verify(message.as_ref(), &multi_sig).is_err());

        let multi_sig = MultiSig::new(vec![
            signer4.try_sign(message.as_ref()).unwrap(),
            signer4.try_sign(message.as_ref()).unwrap(),
        ]);
        assert!(signer_set.verify(message.as_ref(), &multi_sig).is_err());

        let multi_sig = MultiSig::new(vec![
            signer4.try_sign(message.as_ref()).unwrap(),
            signer5.try_sign(message.as_ref()).unwrap(),
        ]);
        assert!(signer_set.verify(message.as_ref(), &multi_sig).is_err());

        // Add a valid signer, we should now verify successfully.
        let multi_sig = MultiSig::new(vec![
            signer4.try_sign(message.as_ref()).unwrap(),
            signer5.try_sign(message.as_ref()).unwrap(),
            signer1.try_sign(message.as_ref()).unwrap(),
        ]);
        assert_eq_ignore_order(
            signer_set.verify(message.as_ref(), &multi_sig).unwrap(),
            vec![signer1.public_key()],
        );

        // With two valid signers we should get both back.
        let multi_sig = MultiSig::new(vec![
            signer4.try_sign(message.as_ref()).unwrap(),
            signer5.try_sign(message.as_ref()).unwrap(),
            signer1.try_sign(message.as_ref()).unwrap(),
            signer2.try_sign(message.as_ref()).unwrap(),
        ]);
        assert_eq_ignore_order(
            signer_set.verify(message.as_ref(), &multi_sig).unwrap(),
            vec![signer1.public_key(), signer2.public_key()],
        );

        // Add the same valid signers, they should not be returned twice.
        let multi_sig = MultiSig::new(vec![
            signer1.try_sign(message.as_ref()).unwrap(),
            signer2.try_sign(message.as_ref()).unwrap(),
            signer4.try_sign(message.as_ref()).unwrap(),
            signer5.try_sign(message.as_ref()).unwrap(),
            signer1.try_sign(message.as_ref()).unwrap(),
            signer2.try_sign(message.as_ref()).unwrap(),
            signer1.try_sign(message.as_ref()).unwrap(),
            signer2.try_sign(message.as_ref()).unwrap(),
        ]);
        assert_eq_ignore_order(
            signer_set.verify(message.as_ref(), &multi_sig).unwrap(),
            vec![signer1.public_key(), signer2.public_key()],
        );
    }

    #[test]
    fn ed25519_verify_with_nested_signer_sets() {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);
        let message = b"this is a test";

        let org1_signer1 = Ed25519Pair::from_random(&mut rng);
        let org1_signer2 = Ed25519Pair::from_random(&mut rng);

        let org2_signer1 = Ed25519Pair::from_random(&mut rng);
        let org2_signer2 = Ed25519Pair::from_random(&mut rng);
        let org2_signer3 = Ed25519Pair::from_random(&mut rng);

        let individual_signer = Ed25519Pair::from_random(&mut rng);

        // Org 1 requires 2-out-of-2
        let org1_signer_set = SignerSet::new(
            vec![org1_signer1.public_key(), org1_signer2.public_key()],
            vec![],
            2,
        );

        // Org 2 requires 2-out-of-3
        let org2_signer_set = SignerSet::new(
            vec![
                org2_signer1.public_key(),
                org2_signer2.public_key(),
                org2_signer3.public_key(),
            ],
            vec![],
            2,
        );

        // Test a signer set that requires the two orgs and an individual signer.
        let signer_set = SignerSet::new(
            vec![individual_signer.public_key()],
            vec![org1_signer_set.clone(), org2_signer_set.clone()],
            3,
        );

        let multi_sig = MultiSig::new(vec![
            // Org 1 satisfied
            org1_signer1.try_sign(message.as_ref()).unwrap(),
            org1_signer2.try_sign(message.as_ref()).unwrap(),
            // Org 2 unsatisfied
            org2_signer1.try_sign(message.as_ref()).unwrap(),
            // Individual signer satisfied
            individual_signer.try_sign(message.as_ref()).unwrap(),
        ]);
        assert!(signer_set.verify(message.as_ref(), &multi_sig).is_err());

        let multi_sig = MultiSig::new(vec![
            // Org 1 satisfied
            org1_signer1.try_sign(message.as_ref()).unwrap(),
            org1_signer2.try_sign(message.as_ref()).unwrap(),
            // Org 2 satisfied
            org2_signer1.try_sign(message.as_ref()).unwrap(),
            org2_signer2.try_sign(message.as_ref()).unwrap(),
        ]);
        assert!(signer_set.verify(message.as_ref(), &multi_sig).is_err());

        let multi_sig = MultiSig::new(vec![
            // Org 1 satisfied
            org1_signer1.try_sign(message.as_ref()).unwrap(),
            org1_signer2.try_sign(message.as_ref()).unwrap(),
            // Org 2 satisfied (and has an extra signature, but this still doesn't count towards
            // the top level threshold)
            org2_signer1.try_sign(message.as_ref()).unwrap(),
            org2_signer2.try_sign(message.as_ref()).unwrap(),
            org2_signer3.try_sign(message.as_ref()).unwrap(),
        ]);
        assert!(signer_set.verify(message.as_ref(), &multi_sig).is_err());

        // Providing the same signers multiple times does not change the result.
        let multi_sig = MultiSig::new(vec![
            // Org 1 satisfied
            org1_signer1.try_sign(message.as_ref()).unwrap(),
            org1_signer2.try_sign(message.as_ref()).unwrap(),
            org1_signer2.try_sign(message.as_ref()).unwrap(),
            org1_signer2.try_sign(message.as_ref()).unwrap(),
            // Org 2 satisfied
            org2_signer1.try_sign(message.as_ref()).unwrap(),
            org2_signer2.try_sign(message.as_ref()).unwrap(),
            org2_signer1.try_sign(message.as_ref()).unwrap(),
            org2_signer2.try_sign(message.as_ref()).unwrap(),
        ]);
        assert!(signer_set.verify(message.as_ref(), &multi_sig).is_err());

        let multi_sig = MultiSig::new(vec![
            // Org 1 satisfied
            org1_signer1.try_sign(message.as_ref()).unwrap(),
            org1_signer2.try_sign(message.as_ref()).unwrap(),
            // Org 2 satisfied
            org2_signer1.try_sign(message.as_ref()).unwrap(),
            org2_signer2.try_sign(message.as_ref()).unwrap(),
            // Individual signer satisfied
            individual_signer.try_sign(message.as_ref()).unwrap(),
        ]);
        assert_eq_ignore_order(
            signer_set.verify(message.as_ref(), &multi_sig).unwrap(),
            vec![
                org1_signer1.public_key(),
                org1_signer2.public_key(),
                org2_signer1.public_key(),
                org2_signer2.public_key(),
                individual_signer.public_key(),
            ],
        );

        // Test a signer set that requires 1 of 2 orgs.
        let signer_set = SignerSet::new(vec![], vec![org1_signer_set, org2_signer_set], 1);

        let multi_sig = MultiSig::new(vec![
            // Org 1 satisfied
            org1_signer1.try_sign(message.as_ref()).unwrap(),
            org1_signer2.try_sign(message.as_ref()).unwrap(),
            // Org 2 satisfied
            org2_signer1.try_sign(message.as_ref()).unwrap(),
            org2_signer3.try_sign(message.as_ref()).unwrap(),
        ]);
        assert_eq_ignore_order(
            signer_set.verify(message.as_ref(), &multi_sig).unwrap(),
            vec![
                org1_signer1.public_key(),
                org1_signer2.public_key(),
                org2_signer1.public_key(),
                org2_signer3.public_key(),
            ],
        );

        let multi_sig = MultiSig::new(vec![
            // Org 1 satisfied
            org1_signer1.try_sign(message.as_ref()).unwrap(),
            org1_signer2.try_sign(message.as_ref()).unwrap(),
            // Org 2 not satisfied
            org2_signer1.try_sign(message.as_ref()).unwrap(),
        ]);
        assert_eq_ignore_order(
            signer_set.verify(message.as_ref(), &multi_sig).unwrap(),
            vec![org1_signer1.public_key(), org1_signer2.public_key()],
        );
    }

    #[test]
    fn test_serde_works() {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);
        let signer1 = Ed25519Pair::from_random(&mut rng);
        let signer2 = Ed25519Pair::from_random(&mut rng);
        let signer3 = Ed25519Pair::from_random(&mut rng);

        let signer_set = SignerSet::new(
            vec![
                signer1.public_key(),
                signer2.public_key(),
                signer3.public_key(),
            ],
            vec![
                SignerSet::new(vec![signer1.public_key(), signer2.public_key()], vec![], 2),
                SignerSet::new(
                    vec![signer1.public_key(), signer2.public_key()],
                    vec![SignerSet::new(
                        vec![
                            signer1.public_key(),
                            signer2.public_key(),
                            signer3.public_key(),
                        ],
                        vec![],
                        3,
                    )],
                    2,
                ),
            ],
            2,
        );

        assert_eq!(
            signer_set,
            mc_util_serial::deserialize(&mc_util_serial::serialize(&signer_set).unwrap()).unwrap(),
        );

        let message = b"this is a test";
        let multi_sig = MultiSig::new(vec![signer1.try_sign(message.as_ref()).unwrap()]);
        assert_eq!(
            multi_sig,
            mc_util_serial::deserialize(&mc_util_serial::serialize(&multi_sig).unwrap()).unwrap(),
        );
    }

    #[test]
    fn test_prost_works() {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);
        let signer1 = Ed25519Pair::from_random(&mut rng);
        let signer2 = Ed25519Pair::from_random(&mut rng);
        let signer3 = Ed25519Pair::from_random(&mut rng);

        let signer_set = SignerSet::new(
            vec![
                signer1.public_key(),
                signer2.public_key(),
                signer3.public_key(),
            ],
            vec![
                SignerSet::new(vec![signer1.public_key(), signer2.public_key()], vec![], 2),
                SignerSet::new(
                    vec![signer1.public_key(), signer2.public_key()],
                    vec![SignerSet::new(
                        vec![
                            signer1.public_key(),
                            signer2.public_key(),
                            signer3.public_key(),
                        ],
                        vec![],
                        3,
                    )],
                    2,
                ),
            ],
            2,
        );

        assert_eq!(
            signer_set,
            mc_util_serial::decode(&mc_util_serial::encode(&signer_set)).unwrap(),
        );

        let message = b"this is a test";
        let multi_sig = MultiSig::new(vec![signer1.try_sign(message.as_ref()).unwrap()]);
        assert_eq!(
            multi_sig,
            mc_util_serial::decode(&mc_util_serial::encode(&multi_sig)).unwrap(),
        );
    }

    #[test]
    fn test_is_valid() {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);
        let signer1 = Ed25519Pair::from_random(&mut rng);
        let signer2 = Ed25519Pair::from_random(&mut rng);
        let signer3 = Ed25519Pair::from_random(&mut rng);

        let valid_flat_signer_set = SignerSet::new(
            vec![
                signer1.public_key(),
                signer2.public_key(),
                signer3.public_key(),
            ],
            vec![],
            2,
        );
        assert!(valid_flat_signer_set.is_valid());

        // Signer set with threshold = 0 is invalid
        assert!(!SignerSet::new(
            vec![
                signer1.public_key(),
                signer2.public_key(),
                signer3.public_key(),
            ],
            vec![valid_flat_signer_set.clone()],
            0,
        )
        .is_valid());

        // Signer set with threshold > number of signers is invalid
        assert!(!SignerSet::new(
            vec![
                signer1.public_key(),
                signer2.public_key(),
                signer3.public_key(),
            ],
            vec![],
            4,
        )
        .is_valid());

        assert!(!SignerSet::new(
            vec![signer2.public_key(), signer3.public_key(),],
            vec![valid_flat_signer_set.clone()],
            4,
        )
        .is_valid());

        // Signer set with threshold that is equal the number of signers is valid
        assert!(SignerSet::new(
            vec![
                signer1.public_key(),
                signer2.public_key(),
                signer3.public_key(),
            ],
            vec![],
            3,
        )
        .is_valid());

        assert!(SignerSet::new(
            vec![signer2.public_key(), signer3.public_key(),],
            vec![valid_flat_signer_set.clone()],
            3,
        )
        .is_valid());

        assert!(SignerSet::new(
            vec![],
            vec![
                valid_flat_signer_set.clone(),
                valid_flat_signer_set.clone(),
                valid_flat_signer_set
            ],
            3,
        )
        .is_valid());

        // A signer set with a nested invalid set is also invalid
        let invalid_signer_set = SignerSet::new(vec![signer1.public_key()], vec![], 4);
        assert!(!SignerSet::new(vec![], vec![invalid_signer_set], 1).is_valid());
    }
}
