// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A multi-signature implementations that supports nesting.
//! This allows us to accommodate a requirement, where for example we want to
//! have 2-out-of-3 organizations signing a transaction, and having each
//! organization require 2-out-of-3 members to sign.

use super::{MultiSig, MAX_SIGNATURES};
use alloc::vec::Vec;
use core::hash::Hash;
use mc_crypto_digestible::Digestible;
use mc_crypto_keys::{PublicKey, Signature, SignatureError, Verifier};
use prost::{Message, Oneof};
use serde::{Deserialize, Serialize};

/// A marker trait for indicating that a type is able to produce signatures.
/// While we do not strictly have to limit ourselves to `PublicKey`, it makes it
/// more obvious what the intent of this trait is.
pub trait SignerIdentity: Default + Message + PublicKey {}

impl<T> SignerIdentity for T where T: Default + Message + PublicKey {}

/// A single entity in a group of signers - can either be a single signer, or a
/// group of m-out-of-n signers.
#[derive(
    Clone, Deserialize, Digestible, Eq, Hash, Oneof, Ord, PartialEq, PartialOrd, Serialize,
)]
// Workaround a Rust compiler bug - see https://github.com/serde-rs/serde/issues/1828
#[serde(bound = "")]
pub enum SignerEntity<S: SignerIdentity> {
    /// A single signer identity (such as a public key)
    #[prost(message, tag = "1")]
    Single(S),

    /// An M-out-of-N group of signers
    #[prost(message, tag = "2")]
    Multi(SignerSetV2<S>),
}

impl<S: SignerIdentity> From<S> for SignerEntity<S> {
    fn from(signer: S) -> Self {
        Self::Single(signer)
    }
}

impl<S: SignerIdentity> From<SignerSetV2<S>> for SignerEntity<S> {
    fn from(signer_set: SignerSetV2<S>) -> Self {
        Self::Multi(signer_set)
    }
}

/// A wrapper object to hold a `SignerEntity`, required because protobuf does
/// not allow repeated `oneof` fields. As such, they need to be wrapped in a
/// message.
#[derive(
    Clone, Deserialize, Digestible, Eq, Hash, Message, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(bound = "")]
pub struct SignerContainer<S: SignerIdentity> {
    /// The underlying signer entity.
    /// This is made optional because of how Prost works. It will be None for
    /// unsupported tags.
    #[prost(oneof = "SignerEntity", tags = "1, 2")]
    pub entity: Option<SignerEntity<S>>,
}

impl<S: SignerIdentity> From<SignerEntity<S>> for SignerContainer<S> {
    fn from(entity: SignerEntity<S>) -> Self {
        Self {
            entity: Some(entity),
        }
    }
}

impl<S: SignerIdentity> From<S> for SignerContainer<S> {
    fn from(signer: S) -> Self {
        SignerEntity::from(signer).into()
    }
}

impl<S: SignerIdentity> From<SignerSetV2<S>> for SignerContainer<S> {
    fn from(signer_set: SignerSetV2<S>) -> Self {
        SignerEntity::from(signer_set).into()
    }
}

/// A set of M-out-of-N signers (either individual signers or m-out-of-n groups
/// of signers).
#[derive(
    Clone, Deserialize, Digestible, Eq, Hash, Message, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(bound = "")]
pub struct SignerSetV2<S: SignerIdentity> {
    #[prost(message, repeated, tag = "1")]
    signers: Vec<SignerContainer<S>>,

    #[prost(uint32, tag = "2")]
    threshold: u32,
}

impl<S: SignerIdentity> SignerSetV2<S> {
    /// Construct a new `SignerSetV2` from a list of signers and threshold.
    pub fn new(signers: Vec<SignerContainer<S>>, threshold: u32) -> Self {
        Self { signers, threshold }
    }

    /// Get the list of potential signers.
    pub fn signers(&self) -> &[SignerContainer<S>] {
        &self.signers
    }

    /// Get the threshold.
    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    /// Verify a message against a multi-signature, returning the list of
    /// signers that signed it.
    ///
    /// Note that a signer is allowed to appear in multiple signer sets. For
    /// example, assume a signer set that requires 2 out of 2 signers, each
    /// being its own signer set:
    ///
    /// 1) SignerSet1: SignerA, SignerB (1 out of 2)
    /// 2) SignerSet2: SignerA, SignerC (1 out of 2)
    /// 3) SignerSetX: SignerSet1, SignerSet2 (2 out of 2)
    ///
    /// When validating SignerSetX, providing just a signature from SignerA will
    /// be enough to satisfy all thresholds. This is acceptable because it
    /// means the rules for verifying a single signer set and a nested one
    /// are the same, and easier to follow. The example above simply shows a
    /// poorly specified signer set.
    pub fn verify<SIG>(
        &self,
        message: &[u8],
        multi_sig: &MultiSig<SIG>,
    ) -> Result<Vec<S>, SignatureError>
    where
        SIG: Clone + Default + Digestible + Eq + Hash + Message + Ord + Serialize + Signature,
        S: Verifier<SIG>,
    {
        if multi_sig.signatures().len() > MAX_SIGNATURES {
            return Err(SignatureError::new());
        }

        // Sort and dedup the list of signatures. Even though we match signers to
        // signatures (and not the other way around), we still deduplicate the
        // list of signatures since it is cheap to do, and a reasonable defensive
        // programming measure.
        let mut signatures = multi_sig.signatures().to_vec();
        signatures.sort();
        signatures.dedup();

        // Verify signatures.
        let mut signer_identities = self.verify_helper(message, &signatures)?;

        // Sort and dedup the list of matched signer identities.
        signer_identities.sort();
        signer_identities.dedup();
        Ok(signer_identities)
    }

    // The code that does the actual signature verification. We separate it from the
    // public `verify` method so that we do not keep re-sorting an already
    // sorted signers/signatures list.
    fn verify_helper<SIG>(
        &self,
        message: &[u8],
        signatures: &[SIG],
    ) -> Result<Vec<S>, SignatureError>
    where
        SIG: Clone + Default + Digestible + Eq + Hash + Message + Ord + Serialize + Signature,
        S: Verifier<SIG>,
    {
        // Sort and dedup the list of signers.
        // We shouldn't be handed a signer set that contains the same signer multiple
        // times, but just in case someone did do this, this will protect us
        // from that.
        let mut signers = self.signers.clone();
        signers.sort();
        signers.dedup();

        // See which signers are satisfied by which signatures.
        let mut matched_signer_identities = Vec::new();
        let mut num_matched_signers = 0;

        for signer in signers.iter() {
            match signer.entity {
                Some(SignerEntity::Single(ref single_signer)) => {
                    // See if any of the signatures match this signer.
                    // Note that we do not need to check if we already encountered this signer,
                    // since we de-duped the list of signers before entering the
                    // outer loop.
                    if signatures
                        .iter()
                        .any(|sig| single_signer.verify(message, sig).is_ok())
                    {
                        matched_signer_identities.push(single_signer.clone());
                        num_matched_signers += 1;
                    }
                }

                Some(SignerEntity::Multi(ref s)) => {
                    if let Ok(signer_identities) = s.verify_helper(message, signatures) {
                        matched_signer_identities.extend(signer_identities);
                        num_matched_signers += 1;
                    }
                }
                None => {}
            }
        }

        // Did we pass the threshold of signers?
        if num_matched_signers < self.threshold as usize {
            return Err(SignatureError::new());
        }

        Ok(matched_signer_identities)
    }
}

#[cfg(test)]
mod test_single_level {
    use super::*;
    use alloc::vec;
    use mc_crypto_keys::{Ed25519Pair, Ed25519Public, Signer};
    use mc_util_from_random::{CryptoRng, FromRandom, RngCore};
    use rand_core::SeedableRng;
    use rand_hc::Hc128Rng;

    /// Helper method for comparing two signers list.
    /// In other places in the code we might convert to a HashSet first and then
    /// compare, but that would hide duplicate elements and we want to catch
    /// that.
    #[track_caller]
    pub fn assert_eq_ignore_order(mut a: Vec<Ed25519Public>, mut b: Vec<Ed25519Public>) {
        a.sort();
        b.sort();

        assert_eq!(a, b);
    }

    /// Helper to construct a non-nested SignerSetV2
    pub fn make_signer_set(
        threshold: u32,
        num_signers: usize,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> (SignerSetV2<Ed25519Public>, Vec<Ed25519Pair>) {
        let signers = (0..num_signers)
            .map(|_| Ed25519Pair::from_random(rng))
            .collect::<Vec<_>>();
        let signer_set = SignerSetV2::new(
            signers
                .iter()
                .map(|signer| signer.public_key().into())
                .collect(),
            threshold,
        );
        (signer_set, signers)
    }

    #[test]
    fn ed25519_verify_signers_sanity_k_equals_3() {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);

        let (signer_set, signers) = make_signer_set(2, 3, &mut rng);
        let (signer1, signer2, signer3) = (&signers[0], &signers[1], &signers[2]);
        let signer4 = Ed25519Pair::from_random(&mut rng);
        let signer5 = Ed25519Pair::from_random(&mut rng);

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

        // Using an unknown signer should not allow us to verify if we are under the
        // threshold
        let multi_sig = MultiSig::new(vec![
            signer1.try_sign(message.as_ref()).unwrap(),
            signer4.try_sign(message.as_ref()).unwrap(),
        ]);
        assert!(signer_set.verify(message.as_ref(), &multi_sig).is_err());

        // Using an unknown signer does not get in the way of verifying a valid set.
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

        let (signer_set, signers) = make_signer_set(1, 3, &mut rng);
        let (signer1, signer2, _signer3) = (&signers[0], &signers[1], &signers[2]);
        let signer4 = Ed25519Pair::from_random(&mut rng);
        let signer5 = Ed25519Pair::from_random(&mut rng);

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
        let signer_set = SignerSetV2::new(
            vec![
                signer1.public_key().into(),
                signer2.public_key().into(),
                signer1.public_key().into(),
                signer2.public_key().into(),
                signer3.public_key().into(),
                signer1.public_key().into(),
                signer2.public_key().into(),
            ],
            1,
        );
        let message = b"this is a test";

        // Add the same valid signers, they should only be returned once.
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
    fn test_serde_works() {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);

        let (signer_set, _signers) = make_signer_set(2, 3, &mut rng);

        assert_eq!(
            signer_set,
            mc_util_serial::deserialize(&mc_util_serial::serialize(&signer_set).unwrap()).unwrap(),
        );
    }

    #[test]
    fn test_prost_works() {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);

        let (signer_set, _signers) = make_signer_set(2, 3, &mut rng);

        assert_eq!(
            signer_set,
            mc_util_serial::decode(&mc_util_serial::encode(&signer_set)).unwrap(),
        );
    }
}

/// Tests for nested k-out-of-n multisigs
#[cfg(test)]
mod test_nested_multisigs {
    use super::{
        test_single_level::{assert_eq_ignore_order, make_signer_set},
        *,
    };
    use alloc::vec;
    use mc_crypto_keys::{Ed25519Pair, Ed25519Public, Ed25519Signature, Signer};
    use mc_util_from_random::FromRandom;
    use rand_core::SeedableRng;
    use rand_hc::Hc128Rng;

    #[test]
    fn ed25519_verify_signers_sanity_one_of_two_orgs() {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);
        let message = b"this is a test";

        // Org 1 requires 2-of-3 signatures
        let (org1_signerset, org1_signers) = make_signer_set(2, 3, &mut rng);
        let (org1_signer1, org1_signer2, org1_signer3) =
            (&org1_signers[0], &org1_signers[1], &org1_signers[2]);

        // Org 2 requires 3-of-3 signatures
        let (org2_signerset, org2_signers) = make_signer_set(3, 3, &mut rng);
        let (org2_signer1, org2_signer2, org2_signer3) =
            (&org2_signers[0], &org2_signers[1], &org2_signers[2]);

        // Sign the message with all of our signers.
        let org1_signer1_sig = org1_signer1.try_sign(message.as_ref()).unwrap();
        let org1_signer2_sig = org1_signer2.try_sign(message.as_ref()).unwrap();
        let org1_signer3_sig = org1_signer3.try_sign(message.as_ref()).unwrap();

        let org2_signer1_sig = org2_signer1.try_sign(message.as_ref()).unwrap();
        let org2_signer2_sig = org2_signer2.try_sign(message.as_ref()).unwrap();
        let org2_signer3_sig = org2_signer3.try_sign(message.as_ref()).unwrap();

        // The top-level multisig requires 1-of-2 signatures
        let signer_set = SignerSetV2::new(vec![org1_signerset.into(), org2_signerset.into()], 1);

        // With no signatures, the multisig should not verify.
        let multi_sig = MultiSig::new(vec![]);
        assert!(signer_set.verify(message.as_ref(), &multi_sig).is_err());

        // Org1 satisfies the threshold, no org2 signatures.
        let multi_sig: MultiSig<Ed25519Signature> =
            MultiSig::new(vec![org1_signer1_sig, org1_signer3_sig]);
        let signers = signer_set
            .verify::<Ed25519Signature>(message.as_ref(), &multi_sig)
            .unwrap();
        assert_eq_ignore_order(
            signers,
            vec![org1_signer1.public_key(), org1_signer3.public_key()],
        );

        // Org2 satisfies the threshold, no org1 signatures.
        let multi_sig = MultiSig::new(vec![org2_signer1_sig, org2_signer2_sig, org2_signer3_sig]);
        let signers = signer_set.verify(message.as_ref(), &multi_sig).unwrap();
        assert_eq_ignore_order(
            signers,
            vec![
                org2_signer1.public_key(),
                org2_signer2.public_key(),
                org2_signer3.public_key(),
            ],
        );

        // Both orgs satisfy the threshold.
        let multi_sig = MultiSig::new(vec![
            org2_signer1_sig,
            org2_signer2_sig,
            org2_signer3_sig,
            org1_signer1_sig,
            org1_signer3_sig,
        ]);
        let signers = signer_set.verify(message.as_ref(), &multi_sig).unwrap();
        assert_eq_ignore_order(
            signers,
            vec![
                org1_signer1.public_key(),
                org1_signer3.public_key(),
                org2_signer1.public_key(),
                org2_signer2.public_key(),
                org2_signer3.public_key(),
            ],
        );

        // Both orgs satisfy the threshold (org1 exceeds it)
        let multi_sig = MultiSig::new(vec![
            org2_signer1_sig,
            org2_signer2_sig,
            org2_signer3_sig,
            org1_signer1_sig,
            org1_signer3_sig,
            org1_signer2_sig,
        ]);
        let signers = signer_set.verify(message.as_ref(), &multi_sig).unwrap();
        assert_eq_ignore_order(
            signers,
            vec![
                org1_signer1.public_key(),
                org1_signer2.public_key(),
                org1_signer3.public_key(),
                org2_signer1.public_key(),
                org2_signer2.public_key(),
                org2_signer3.public_key(),
            ],
        );

        // One org satisfies the threshold and one org does not.
        let multi_sig = MultiSig::new(vec![
            org1_signer1_sig,
            org1_signer3_sig,
            org2_signer1_sig,
            org2_signer2_sig,
        ]);
        let signers = signer_set.verify(message.as_ref(), &multi_sig).unwrap();
        assert_eq_ignore_order(
            signers,
            vec![org1_signer1.public_key(), org1_signer3.public_key()],
        );

        // Neither orgs provides a valid signature
        let multi_sig = MultiSig::new(vec![
            org1_signer1_sig,
            org1_signer1_sig,
            org2_signer1_sig,
            org2_signer1_sig,
            org2_signer1_sig,
        ]);
        assert!(signer_set.verify(message.as_ref(), &multi_sig).is_err());
    }

    #[test]
    fn ed25519_verify_signers_sanity_two_of_two_orgs() {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);
        let message = b"this is a test";

        // Org 1 requires 2-of-3 signatures
        let (org1_signerset, org1_signers) = make_signer_set(2, 3, &mut rng);
        let (org1_signer1, org1_signer2, org1_signer3) =
            (&org1_signers[0], &org1_signers[1], &org1_signers[2]);

        // Org 2 requires 3-of-3 signatures
        let (org2_signerset, org2_signers) = make_signer_set(3, 3, &mut rng);
        let (org2_signer1, org2_signer2, org2_signer3) =
            (&org2_signers[0], &org2_signers[1], &org2_signers[2]);

        // Sign the message with all of our signers.
        let org1_signer1_sig = org1_signer1.try_sign(message.as_ref()).unwrap();
        let org1_signer2_sig = org1_signer2.try_sign(message.as_ref()).unwrap();
        let org1_signer3_sig = org1_signer3.try_sign(message.as_ref()).unwrap();

        let org2_signer1_sig = org2_signer1.try_sign(message.as_ref()).unwrap();
        let org2_signer2_sig = org2_signer2.try_sign(message.as_ref()).unwrap();
        let org2_signer3_sig = org2_signer3.try_sign(message.as_ref()).unwrap();

        // The top-level multisig requires 2-of-2 signatures
        let signer_set = SignerSetV2::new(vec![org1_signerset.into(), org2_signerset.into()], 2);

        // With no signatures, the multisig should not verify.
        let multi_sig = MultiSig::new(vec![]);
        assert!(signer_set.verify(message.as_ref(), &multi_sig).is_err());

        // Org1 satisfies the threshold, no org2 signatures.
        let multi_sig = MultiSig::new(vec![org1_signer2_sig, org1_signer3_sig]);
        assert!(signer_set.verify(message.as_ref(), &multi_sig).is_err());

        // Org2 satisfies the threshold, no org1 signatures.
        let multi_sig = MultiSig::new(vec![org2_signer1_sig, org2_signer2_sig, org2_signer3_sig]);
        assert!(signer_set.verify(message.as_ref(), &multi_sig).is_err());

        // Both orgs satisfy the threshold.
        let multi_sig = MultiSig::new(
            vec![
                org1_signer1_sig,
                org2_signer1_sig,
                org1_signer2_sig,
                org2_signer2_sig,
                org2_signer3_sig,
            ],
        );
        let signers = signer_set.verify(message.as_ref(), &multi_sig).unwrap();
        assert_eq_ignore_order(
            signers,
            vec![
                org1_signer1.public_key(),
                org1_signer2.public_key(),
                org2_signer1.public_key(),
                org2_signer2.public_key(),
                org2_signer3.public_key(),
            ],
        );

        // Org1 exceeds the threshold, org2 satisfies it.
        let multi_sig = MultiSig::new(vec![
            org1_signer1_sig,
            org2_signer1_sig,
            org1_signer2_sig,
            org2_signer2_sig,
            org2_signer3_sig,
            org1_signer3_sig,
        ]);
        let signers = signer_set.verify(message.as_ref(), &multi_sig).unwrap();
        assert_eq_ignore_order(
            signers,
            vec![
                org1_signer1.public_key(),
                org1_signer2.public_key(),
                org1_signer3.public_key(),
                org2_signer1.public_key(),
                org2_signer2.public_key(),
                org2_signer3.public_key(),
            ],
        );

        // One org satisfies the threshold and one org does not.
        let multi_sig = MultiSig::new(vec![
            org1_signer1_sig,
            org1_signer2_sig,
            org2_signer1_sig,
            org2_signer2_sig,
            org2_signer1_sig,
        ]);
        assert!(signer_set.verify(message.as_ref(), &multi_sig).is_err());

        // Neither orgs provides a valid signature
        let multi_sig = MultiSig::new(vec![
            org1_signer1_sig,
            org1_signer1_sig,
            org2_signer1_sig,
            org2_signer1_sig,
            org2_signer2_sig,
        ]);
        assert!(signer_set.verify(message.as_ref(), &multi_sig).is_err());

        // Trying to pass the same org twice doesn't get us to the threshold
        let multi_sig = MultiSig::new(vec![
            org1_signer1_sig,
            org1_signer2_sig,
            org1_signer3_sig,
            org1_signer1_sig,
            org1_signer2_sig,
            org1_signer3_sig,
        ]);
        assert!(signer_set.verify(message.as_ref(), &multi_sig).is_err());

        // Passing multiple valid signatures only matches them once.
        let multi_sig = MultiSig::new(vec![
            org1_signer1_sig,
            org1_signer3_sig,
            org2_signer1_sig,
            org2_signer2_sig,
            org2_signer3_sig,
            org2_signer2_sig,
            org1_signer1_sig,
            org1_signer3_sig,
        ]);
        let signers = signer_set.verify(message.as_ref(), &multi_sig).unwrap();
        assert_eq_ignore_order(
            signers,
            vec![
                org1_signer1.public_key(),
                org1_signer3.public_key(),
                org2_signer1.public_key(),
                org2_signer2.public_key(),
                org2_signer3.public_key(),
            ],
        );
    }

    #[test]
    fn ed25519_duplicate_signer() {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);
        let message = b"this is a test";

        let common_signer = Ed25519Pair::from_random(&mut rng);

        // Org 1 requires 2-of-4 signatures
        let org1_signer1 = Ed25519Pair::from_random(&mut rng);
        let org1_signer2 = Ed25519Pair::from_random(&mut rng);
        let org1_signer3 = Ed25519Pair::from_random(&mut rng);
        let org1_signerset = SignerSetV2::new(
            vec![
                org1_signer1.public_key().into(),
                org1_signer2.public_key().into(),
                org1_signer3.public_key().into(),
                common_signer.public_key().into(),
            ],
            2,
        );

        // Org 2 requires 3-of-4 signatures
        let org2_signer1 = Ed25519Pair::from_random(&mut rng);
        let org2_signer2 = Ed25519Pair::from_random(&mut rng);
        let org2_signer3 = Ed25519Pair::from_random(&mut rng);
        let org2_signerset = SignerSetV2::new(
            vec![
                org2_signer1.public_key().into(),
                org2_signer2.public_key().into(),
                org2_signer3.public_key().into(),
                common_signer.public_key().into(),
            ],
            3,
        );

        // Sign the message with all of our signers.
        let common_signer_sig = common_signer.try_sign(message).unwrap();

        let org1_signer1_sig = org1_signer1.try_sign(message.as_ref()).unwrap();
        let org1_signer2_sig = org1_signer2.try_sign(message.as_ref()).unwrap();
        let org1_signer3_sig = org1_signer3.try_sign(message.as_ref()).unwrap();

        let org2_signer1_sig = org2_signer1.try_sign(message.as_ref()).unwrap();
        let org2_signer2_sig = org2_signer2.try_sign(message.as_ref()).unwrap();
        let org2_signer3_sig = org2_signer3.try_sign(message.as_ref()).unwrap();

        // The top-level multisig requires 1-of-2 signatures
        let signer_set = SignerSetV2::new(vec![org1_signerset.into(), org2_signerset.into()], 1);

        // Using the common signer as part of the org1 signer set results in only org1
        // being matched.
        let multi_sig = MultiSig::new(vec![common_signer_sig, org1_signer1_sig]);
        let signers = signer_set
            .verify::<Ed25519Signature>(message.as_ref(), &multi_sig)
            .unwrap();
        assert_eq_ignore_order(
            signers,
            vec![
                common_signer.public_key(),
                org1_signer1.public_key(),
            ],
        );

        // Using the common signer as part of the org2 signer set results in only org2
        // being matched.
        let multi_sig = MultiSig::new(vec![common_signer_sig, org2_signer1_sig, org2_signer2_sig]);
        let signers = signer_set
            .verify::<Ed25519Signature>(message.as_ref(), &multi_sig)
            .unwrap();
        assert_eq_ignore_order(
            signers,
            vec![
                common_signer.public_key(),
                org2_signer1.public_key(),
                org2_signer2.public_key(),
            ],
        );

        );
    }

    #[test]
    fn ed25519_mixed_single_and_multi() {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);
        let message = b"this is a test";

        // Org 1 requires 2-of-3 signatures
        let (org1_signerset, org1_signers) = make_signer_set(2, 3, &mut rng);
        let (org1_signer1, org1_signer2, org1_signer3) =
            (&org1_signers[0], &org1_signers[1], &org1_signers[2]);

        // Org 2 requires 3-of-3 signatures
        let (org2_signerset, org2_signers) = make_signer_set(3, 3, &mut rng);
        let (org2_signer1, org2_signer2, org2_signer3) =
            (&org2_signers[0], &org2_signers[1], &org2_signers[2]);

        // Two single signers
        let single_signer1 = Ed25519Pair::from_random(&mut rng);
        let single_signer2 = Ed25519Pair::from_random(&mut rng);

        // Sign the message with all of our signers.
        let org1_signer1_sig = org1_signer1.try_sign(message.as_ref()).unwrap();
        let org1_signer2_sig = org1_signer2.try_sign(message.as_ref()).unwrap();
        let org1_signer3_sig = org1_signer3.try_sign(message.as_ref()).unwrap();

        let org2_signer1_sig = org2_signer1.try_sign(message.as_ref()).unwrap();
        let org2_signer2_sig = org2_signer2.try_sign(message.as_ref()).unwrap();
        let org2_signer3_sig = org2_signer3.try_sign(message.as_ref()).unwrap();

        let single_signer1_sig = single_signer1.try_sign(message.as_ref()).unwrap();
        let single_signer2_sig = single_signer2.try_sign(message.as_ref()).unwrap();

        // The top-level multisig requires 3-of-4 signatures
        let signer_set = SignerSetV2::new(
            vec![
                org1_signerset.into(),
                org2_signerset.into(),
                single_signer1.public_key().into(),
                single_signer2.public_key().into(),
            ],
            3,
        );

        // Signing with less than the threshold doesn't verify.
        let multi_sig = MultiSig::new(vec![
            // Valid org1 signature
            org1_signer1_sig,
            org1_signer2_sig,
            // Invalid org2 signature
            org2_signer1_sig,
            org2_signer2_sig,
            // One of the single signers
            single_signer1_sig,
        ]);
        assert!(signer_set.verify(message.as_ref(), &multi_sig).is_err());

        // Providing 3 valid signatures verifies.
        let multi_sig = MultiSig::new(vec![
            // Valid org1 signature
            org1_signer1_sig,
            org1_signer2_sig,
            // Two valid single signers
            single_signer1_sig,
            single_signer2_sig,
            // Partial but invalid org2 signature
            org2_signer1_sig,
        ]);
        let signers = signer_set
            .verify::<Ed25519Signature>(message.as_ref(), &multi_sig)
            .unwrap();

        assert_eq_ignore_order(
            signers,
            vec![
                org1_signer1.public_key(),
                org1_signer2.public_key(),
                single_signer1.public_key(),
                single_signer2.public_key(),
            ],
        );

        // Providing 4 valid signatures verifies.
        let multi_sig = MultiSig::new(vec![
            // Valid org1 signature
            org1_signer1_sig,
            org1_signer2_sig,
            // Two valid singler signers
            single_signer1_sig,
            single_signer2_sig,
            // Valid org2 signature
            org2_signer1_sig,
            org2_signer2_sig,
            org2_signer3_sig,
        ]);
        let signers = signer_set
            .verify::<Ed25519Signature>(message.as_ref(), &multi_sig)
            .unwrap();

        assert_eq_ignore_order(
            signers,
            vec![
                org1_signer1.public_key(),
                org1_signer2.public_key(),
                org2_signer1.public_key(),
                org2_signer2.public_key(),
                org2_signer3.public_key(),
                single_signer1.public_key(),
                single_signer2.public_key(),
            ],
        );
    }

    #[test]
    fn test_serde_works() {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);

        // Org 1 requires 2-of-3 signatures
        let (org1_signerset, _org1_signers) = make_signer_set(2, 3, &mut rng);

        // Org 2 requires 3-of-3 signatures
        let (org2_signerset, _org2_signers) = make_signer_set(3, 3, &mut rng);

        assert_eq!(
            org1_signerset,
            mc_util_serial::deserialize(&mc_util_serial::serialize(&org1_signerset).unwrap())
                .unwrap(),
        );
        assert_eq!(
            org2_signerset,
            mc_util_serial::deserialize(&mc_util_serial::serialize(&org2_signerset).unwrap())
                .unwrap(),
        );

        // Combined signer set
        let signer_set = SignerSetV2::<Ed25519Public>::new(
            vec![org1_signerset.into(), org2_signerset.into()],
            2,
        );

        assert_eq!(
            signer_set,
            mc_util_serial::deserialize(&mc_util_serial::serialize(&signer_set).unwrap()).unwrap(),
        );
    }

    #[test]
    fn test_prost_works() {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);

        // Org 1 requires 2-of-3 signatures
        let (org1_signerset, _org1_signers) = make_signer_set(2, 3, &mut rng);

        // Org 2 requires 3-of-3 signatures
        let (org2_signerset, _org2_signers) = make_signer_set(3, 3, &mut rng);

        assert_eq!(
            org1_signerset,
            mc_util_serial::decode(&mc_util_serial::encode(&org1_signerset)).unwrap(),
        );
        assert_eq!(
            org2_signerset,
            mc_util_serial::decode(&mc_util_serial::encode(&org2_signerset)).unwrap(),
        );

        // Combined signer set
        let signer_set = SignerSetV2::<Ed25519Public>::new(
            vec![org1_signerset.into(), org2_signerset.into()],
            2,
        );

        assert_eq!(
            signer_set,
            mc_util_serial::decode(&mc_util_serial::encode(&signer_set)).unwrap(),
        );
    }
}
