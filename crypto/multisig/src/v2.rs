// Copyright (c) 2018-2022 The MobileCoin Foundation

//! TODO

use super::MultiSig;
use alloc::vec::Vec;
use core::hash::Hash;
use mc_crypto_digestible::Digestible;
use mc_crypto_keys::{Signature, SignatureError, Verifier};
use prost::{Message, Oneof};
use serde::{Deserialize, Serialize};

/// The maximum number of signatures that can be included in a multi-signature.
pub const MAX_SIGNATURES: usize = 10;

pub trait Signer:
    Clone + Default + Digestible + Eq + Hash + Message + Ord + PartialEq + PartialOrd + Serialize
// TODO why is this here
{
}

impl<T> Signer for T where
    T: Clone
        + Default
        + Digestible
        + Eq
        + Hash
        + Message
        + Ord
        + PartialEq
        + PartialOrd
        + Serialize
{
}

#[derive(
    Clone, Deserialize, Digestible, Eq, Hash, Oneof, Ord, PartialEq, PartialOrd, Serialize,
)]
pub enum SignerEntity<S: Signer> {
    #[prost(message, tag = "1")]
    Single(S),

    #[prost(message, tag = "2")]
    Multi(SignerSetV2<S>),
}

impl<S: Signer> From<S> for SignerEntity<S> {
    fn from(signer: S) -> Self {
        Self::Single(signer)
    }
}

impl<S: Signer> From<SignerSetV2<S>> for SignerEntity<S> {
    fn from(signer_set: SignerSetV2<S>) -> Self {
        Self::Multi(signer_set)
    }
}

#[derive(
    Clone, Deserialize, Digestible, Eq, Hash, Message, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct SignerContainer<S: Signer> {
    #[prost(oneof = "SignerEntity", tags = "1, 2")]
    pub entity: Option<SignerEntity<S>>,
}

impl<S: Signer> From<SignerEntity<S>> for SignerContainer<S> {
    fn from(entity: SignerEntity<S>) -> Self {
        Self {
            entity: Some(entity),
        }
    }
}

impl<S: Signer> From<S> for SignerContainer<S> {
    fn from(signer: S) -> Self {
        Self {
            entity: Some(SignerEntity::Single(signer)),
        }
    }
}

impl<S: Signer> From<SignerSetV2<S>> for SignerContainer<S> {
    fn from(signer_set: SignerSetV2<S>) -> Self {
        Self {
            entity: Some(SignerEntity::Multi(signer_set)),
        }
    }
}

#[derive(
    Clone, Deserialize, Digestible, Eq, Hash, Message, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct SignerSetV2<S: Signer> {
    #[prost(message, repeated, tag = "1")]
    pub signers: Vec<SignerContainer<S>>,

    #[prost(uint32, tag = "2")]
    pub threshold: u32,
}

impl<S: Signer> SignerSetV2<S> {
    pub fn new(signers: Vec<SignerContainer<S>>, threshold: u32) -> Self {
        Self { signers, threshold }
    }

    pub fn verify<
        SIG: Clone
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
        multi_sig: &MultiSig<SIG>,
    ) -> Result<Vec<S>, SignatureError>
    where
        S: Verifier<SIG>,
    {
        if multi_sig.signatures().len() > MAX_SIGNATURES {
            return Err(SignatureError::new());
        }

        // Sort and dedup the list of signers.
        let mut signatures = multi_sig.signatures.clone();
        signatures.sort_by(|a, b| a.as_ref().cmp(b.as_ref()));
        signatures.dedup();

        // Verify signatures.
        self.verify_helper(message, &signatures, &[])
    }

    fn verify_helper<
        SIG: Clone
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
        signatures: &[SIG],
        seen_signers: &[S],
    ) -> Result<Vec<S>, SignatureError>
    where
        S: Verifier<SIG>,
    {
        // Sort and dedup the list of signers.
        // While the verification code below should be immune to duplicate signers or
        // signatures, the overhead of deduping them is negligible and being
        // extra-safe is a good idea.
        // TODO --^
        let mut signers = self.signers.clone();
        signers.sort();
        signers.dedup();

        println!("verify_helper ---------------------------------");
        println!("signer set: {:#?}", signers);
        println!("threshold: {}", self.threshold);
        println!("signatures: {:?}", signatures);
        println!("seen_signers: {:?}", seen_signers);

        // See which signers are satisfied by which signatures.
        let mut matched_signers = Vec::new();
        let mut num_matched_entities = 0;

        for signer in signers.iter() {
            match signer.entity {
                Some(SignerEntity::Single(ref s)) => {
                    // If we already encountered this signer, we cannot use it again.
                    if seen_signers.contains(s) {
                        continue;
                    }
                    if matched_signers.contains(s) {
                        continue;
                    }

                    for signature in signatures.iter() {
                        if s.verify(message, signature).is_ok() {
                            matched_signers.push(s.clone());
                            num_matched_entities += 1;
                            break;
                        }
                    }
                }
                Some(SignerEntity::Multi(ref s)) => {
                    let mut ignore_signers = seen_signers.to_vec();
                    ignore_signers.extend(matched_signers.clone());

                    if let Ok(signers) = s.verify_helper(message, signatures, &ignore_signers) {
                        matched_signers.extend(signers);
                        num_matched_entities += 1;
                    }
                }
                None => {}
            }
        }

        // Did we pass the threshold of verified signatures?
        if num_matched_entities < self.threshold as usize {
            println!(
                "no match ---------- {} {}",
                num_matched_entities, self.threshold
            );
            return Err(SignatureError::new());
        }

        println!(
            "---- match {} {} {:?}",
            num_matched_entities, self.threshold, matched_signers
        );
        Ok(matched_signers.to_vec())
    }
}

#[cfg(test)]
mod test_single_level {
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

        let signer_set = SignerSetV2::new(
            vec![
                signer1.public_key().into(),
                signer2.public_key().into(),
                signer3.public_key().into(),
            ],
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

        let signer_set = SignerSetV2::new(
            vec![
                signer1.public_key().into(),
                signer2.public_key().into(),
                signer3.public_key().into(),
            ],
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
        let signer_set = SignerSetV2::new(
            vec![
                signer1.public_key().into(),
                signer2.public_key().into(),
                signer1.public_key().into(),
                signer2.public_key().into(),
                signer3.public_key().into(),
                signer1.public_key().into(),
                signer2.public_key().into(),
            ]
            .into(),
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
    fn test_serde_works() {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);
        let signer1 = Ed25519Pair::from_random(&mut rng);
        let signer2 = Ed25519Pair::from_random(&mut rng);
        let signer3 = Ed25519Pair::from_random(&mut rng);

        let signer_set = SignerSetV2::new(
            vec![
                signer1.public_key().into(),
                signer2.public_key().into(),
                signer3.public_key().into(),
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

        let signer_set = SignerSetV2::new(
            vec![
                signer1.public_key().into(),
                signer2.public_key().into(),
                signer3.public_key().into(),
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
}

/// Tests for nested k-out-of-n multisigs
#[cfg(test)]
mod test_nested_multisigs {
    use super::*;
    use alloc::vec;
    use mc_crypto_keys::{Ed25519Pair, Ed25519Public, Ed25519Signature, Signer};
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
    fn ed25519_verify_signers_sanity_one_of_two_orgs() {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);
        let message = b"this is a test";

        // Org 1 requires 2-of-3 signatures
        let org1_signer1 = Ed25519Pair::from_random(&mut rng);
        let org1_signer2 = Ed25519Pair::from_random(&mut rng);
        let org1_signer3 = Ed25519Pair::from_random(&mut rng);
        let org1_signerset = SignerSetV2::new(
            vec![
                org1_signer1.public_key().into(),
                org1_signer2.public_key().into(),
                org1_signer3.public_key().into(),
            ],
            2,
        );

        // Org 2 requires 3-of-3 signatures
        let org2_signer1 = Ed25519Pair::from_random(&mut rng);
        let org2_signer2 = Ed25519Pair::from_random(&mut rng);
        let org2_signer3 = Ed25519Pair::from_random(&mut rng);
        let org2_signerset = SignerSetV2::new(
            vec![
                org2_signer1.public_key().into(),
                org2_signer2.public_key().into(),
                org2_signer3.public_key().into(),
            ],
            3,
        );

        // Sign the message with all of our signers.
        let org1_signer1_sig = org1_signer1.try_sign(message.as_ref()).unwrap();
        let org1_signer2_sig = org1_signer2.try_sign(message.as_ref()).unwrap();
        let org1_signer3_sig = org1_signer3.try_sign(message.as_ref()).unwrap();

        let org2_signer1_sig = org2_signer1.try_sign(message.as_ref()).unwrap();
        let org2_signer2_sig = org2_signer2.try_sign(message.as_ref()).unwrap();
        let org2_signer3_sig = org2_signer3.try_sign(message.as_ref()).unwrap();

        // The top-level multisig requires 1-of-2 signatures
        let signer_set = SignerSetV2::new(vec![org1_signerset.into(), org2_signerset.into()], 1);

        // With not signatures, the multisig should not verify.
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
        let org1_signer1 = Ed25519Pair::from_random(&mut rng);
        let org1_signer2 = Ed25519Pair::from_random(&mut rng);
        let org1_signer3 = Ed25519Pair::from_random(&mut rng);
        let org1_signerset = SignerSetV2::new(
            vec![
                org1_signer1.public_key().into(),
                org1_signer2.public_key().into(),
                org1_signer3.public_key().into(),
            ],
            2,
        );

        // Org 2 requires 3-of-3 signatures
        let org2_signer1 = Ed25519Pair::from_random(&mut rng);
        let org2_signer2 = Ed25519Pair::from_random(&mut rng);
        let org2_signer3 = Ed25519Pair::from_random(&mut rng);
        let org2_signerset = SignerSetV2::new(
            vec![
                org2_signer1.public_key().into(),
                org2_signer2.public_key().into(),
                org2_signer3.public_key().into(),
            ],
            3,
        );

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
            ], // TODO check sig2 for org1
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

        println!("A");
        // One org satisfies the threshold and one org does not.
        let multi_sig = MultiSig::new(vec![
            org1_signer1_sig,
            org1_signer2_sig,
            org2_signer1_sig,
            org2_signer2_sig,
            org2_signer1_sig,
        ]);
        assert!(signer_set.verify(message.as_ref(), &multi_sig).is_err());

        println!("B");
        // Neither orgs provides a valid signature
        let multi_sig = MultiSig::new(vec![
            org1_signer1_sig,
            org1_signer1_sig,
            org2_signer1_sig,
            org2_signer1_sig,
            org2_signer2_sig,
        ]);
        assert!(signer_set.verify(message.as_ref(), &multi_sig).is_err());
        println!("C");
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

        println!("D");
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
        println!("E");
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
    fn test_serde_works() {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);

        let org1_signer1 = Ed25519Pair::from_random(&mut rng);
        let org1_signer2 = Ed25519Pair::from_random(&mut rng);
        let org1_signer3 = Ed25519Pair::from_random(&mut rng);
        let org1_signerset = SignerSetV2::new(
            vec![
                org1_signer1.public_key().into(),
                org1_signer2.public_key().into(),
                org1_signer3.public_key().into(),
            ],
            2,
        );

        // Org 2 requires 3-of-3 signatures
        let org2_signer1 = Ed25519Pair::from_random(&mut rng);
        let org2_signer2 = Ed25519Pair::from_random(&mut rng);
        let org2_signer3 = Ed25519Pair::from_random(&mut rng);
        let org2_signerset = SignerSetV2::new(
            vec![
                org2_signer1.public_key().into(),
                org2_signer2.public_key().into(),
                org2_signer3.public_key().into(),
            ],
            3,
        );

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

        let org1_signer1 = Ed25519Pair::from_random(&mut rng);
        let org1_signer2 = Ed25519Pair::from_random(&mut rng);
        let org1_signer3 = Ed25519Pair::from_random(&mut rng);
        let org1_signerset = SignerSetV2::new(
            vec![
                org1_signer1.public_key().into(),
                org1_signer2.public_key().into(),
                org1_signer3.public_key().into(),
            ],
            2,
        );

        // Org 2 requires 3-of-3 signatures
        let org2_signer1 = Ed25519Pair::from_random(&mut rng);
        let org2_signer2 = Ed25519Pair::from_random(&mut rng);
        let org2_signer3 = Ed25519Pair::from_random(&mut rng);
        let org2_signerset = SignerSetV2::new(
            vec![
                org2_signer1.public_key().into(),
                org2_signer2.public_key().into(),
                org2_signer3.public_key().into(),
            ],
            3,
        );

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
