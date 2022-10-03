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
use core::{fmt::Debug, hash::Hash};
use mc_crypto_digestible::Digestible;
use mc_crypto_keys::{PublicKey, SignatureError, Verifier};
use prost::Message;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// The maximum number of signatures that can be included in a multi-signature.
pub const MAX_SIGNATURES: usize = 10;

/// Useful base traits we want objects provided by this crate to implement.
pub trait BaseTraits:
    Clone
    + Debug
    + Default
    + DeserializeOwned
    + Digestible
    + Eq
    + PartialEq
    + Ord
    + PartialOrd
    + Hash
    + Message
    + Serialize
{
}
impl<T> BaseTraits for T where
    T: Clone
        + Debug
        + Default
        + DeserializeOwned
        + Digestible
        + Eq
        + PartialEq
        + Ord
        + PartialOrd
        + Hash
        + Message
        + Serialize
{
}

/// A marker trait for types that can be used as a signer in multi-signatures.
pub trait Signer: BaseTraits {}

/// A set of M-out-of-N signers.
#[derive(
    Clone, Deserialize, Digestible, Eq, PartialEq, Ord, PartialOrd, Hash, Message, Serialize,
)]
#[serde(bound = "")]
pub struct SignerSet<S: Signer> {
    /// List of potential signers.
    #[prost(message, repeated, tag = "1")]
    signers: Vec<S>,

    /// Minimum number of signers required.
    #[prost(uint32, tag = "2")]
    threshold: u32,
}
impl<S: Signer> SignerSet<S> {
    /// Construct a new `SignerSet` from a list of public keys and threshold.
    pub fn new(signers: Vec<S>, threshold: u32) -> Self {
        Self { signers, threshold }
    }

    /// Get the list of potential signers.
    pub fn signers(&self) -> &[S] {
        &self.signers
    }

    /// Get the threshold.
    pub fn threshold(&self) -> u32 {
        self.threshold
    }
}

// Blanket implementation of Signer for all public key types.
impl<T> Signer for T where T: BaseTraits + PublicKey {}

// SignerSets can be used as signers - this allows the nested multi-sig
// scenario.
impl<P: Signer> Signer for SignerSet<P> {}

/// A marker trait for individual signatures that can be used in
/// multi-signatures.
pub trait Signature: BaseTraits {}

/// A multi-signature: a collection of one or more signatures.
#[derive(
    Clone, Deserialize, Digestible, Eq, PartialEq, Ord, PartialOrd, Hash, Message, Serialize,
)]
#[serde(bound = "")]
pub struct MultiSig<S: Signature> {
    #[prost(message, repeated, tag = "1")]
    signatures: Vec<S>,
}

impl<S: Signature> MultiSig<S> {
    /// Construct a new multi-signature from a collection of signatures.
    pub fn new(signatures: Vec<S>) -> Self {
        Self { signatures }
    }

    /// Get signatures
    pub fn signatures(&self) -> &[S] {
        &self.signatures
    }
}

// Blanket implementation of Signature for all mc_crypto_keys::Signature types,
// allowing them to be used in multi-sigs.
impl<T> Signature for T where T: BaseTraits + mc_crypto_keys::Signature {}

// A multi-sig can be used as a signature, as is the case when doing nested
// multi-sigs.
impl<S: Signature> Signature for MultiSig<S> {}

/// A trait for objects that can verify a signature.
/// Note that we are not using the `Verifier` trait from mc-crypto-keys here,
/// for two reasons: 1) It requires the signature to implement
/// `mc_crypto_keys::Signature`, which is not    possible since that requires an
/// as_bytes() implementation, which is not possible    since there is no
/// well-established over-the-wire format for our multisigs. 2) We want the
/// verifier to return information about the signing identity that matched the
/// signature.    This allows the high-level multisig verification method to
/// return us a list of the identities    that satisfied the threshold
/// requirement.
pub trait MultiSigVerifier<S: Signature> {
    /// A type that can be used to identify the signer.
    type SignerIdentity: Eq + PartialEq;

    /// Verify a signature `sig` over `message` and if successful return the
    /// signer identity who produced a valig signature.
    fn verify(&self, message: &[u8], sig: &S) -> Result<Self::SignerIdentity, SignatureError>;
}

/// Verifier for underlying mc_crypto_keys types.
impl<S: Signature + mc_crypto_keys::Signature, T: Clone + Eq + PartialEq + Verifier<S>>
    MultiSigVerifier<S> for T
{
    type SignerIdentity = Self;

    fn verify(&self, message: &[u8], sig: &S) -> Result<Self::SignerIdentity, SignatureError> {
        self.verify(message, sig).map(|_| self.clone())
    }
}

/// Verifier for SignerSets.
impl<'a, S: Signature, P: Signer> MultiSigVerifier<MultiSig<S>> for SignerSet<P>
where
    P: MultiSigVerifier<S>,
{
    // In a signer-set verification we will have a list of identities that satisfied
    // the threshold.
    type SignerIdentity = Vec<<P as MultiSigVerifier<S>>::SignerIdentity>;

    fn verify(
        &self,
        message: &[u8],
        multi_sig: &MultiSig<S>,
    ) -> Result<Self::SignerIdentity, SignatureError> {
        // If the signature contains less than the threshold number of
        // signers or more than the hardcoded limit, there's no point
        // in trying.
        if multi_sig.signatures.len() < self.threshold as usize
            || multi_sig.signatures.len() > MAX_SIGNATURES
        {
            return Err(SignatureError::new());
        }

        // Sort and dedup the list of signers and signatures.
        // While the verification code below should be immune to duplicate
        // signers or signatures, the overhead of deduping them is
        // negligible and being extra-safe is a good idea.
        let mut potential_signers = self.signers.clone();
        potential_signers.sort();
        potential_signers.dedup();

        let mut signatures = multi_sig.signatures.clone();
        signatures.sort_by(|a, b| a.cmp(b));
        signatures.dedup();

        // See which signatures match which signers.
        let mut all_matched_identities = Vec::new();
        for signature in signatures.iter() {
            let matched_signer_and_identities = potential_signers.iter().find_map(|signer| {
                signer
                    .verify(message, signature)
                    .ok()
                    .map(|matched_signer_identities| (signer.clone(), matched_signer_identities))
            });
            if let Some((matched_signer, matched_identities)) = matched_signer_and_identities {
                // Removing the matched signer from the list of potential signers means the same
                // signer cannot be used twice.
                potential_signers.retain(|signer| signer != &matched_signer);
                all_matched_identities.push(matched_identities);
            }
        }

        // Did we pass the threshold of verified signatures?
        if all_matched_identities.len() < self.threshold as usize {
            return Err(SignatureError::new());
        }

        Ok(all_matched_identities)
    }
}

/// Tests for non-nested k-out-of-n multisig
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

        let signer_set = SignerSet::new(
            vec![
                signer1.public_key(),
                signer2.public_key(),
                signer3.public_key(),
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
    use mc_crypto_keys::{Ed25519Pair, Ed25519Public, Signer};
    use mc_util_from_random::FromRandom;
    use rand_core::SeedableRng;
    use rand_hc::Hc128Rng;

    /// Helper method for comparing two signers list.
    /// In other places in the code we might convert to a HashSet first and then
    /// compare, but that would hide duplicate elements and we want to catch
    /// that.
    fn assert_eq_ignore_order(mut a: Vec<Vec<Ed25519Public>>, mut b: Vec<Vec<Ed25519Public>>) {
        for signer in a.iter_mut() {
            signer.sort();
        }

        for signer in b.iter_mut() {
            signer.sort();
        }

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
        let org1_signerset = SignerSet::new(
            vec![
                org1_signer1.public_key(),
                org1_signer2.public_key(),
                org1_signer3.public_key(),
            ],
            2,
        );

        // Org 2 requires 3-of-3 signatures
        let org2_signer1 = Ed25519Pair::from_random(&mut rng);
        let org2_signer2 = Ed25519Pair::from_random(&mut rng);
        let org2_signer3 = Ed25519Pair::from_random(&mut rng);
        let org2_signerset = SignerSet::new(
            vec![
                org2_signer1.public_key(),
                org2_signer2.public_key(),
                org2_signer3.public_key(),
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

        // Some signatures to test with
        let org1_valid_multisig = MultiSig::new(vec![org1_signer1_sig, org1_signer3_sig]);
        let org1_invalid_multisig1 = MultiSig::new(vec![org1_signer1_sig]);
        let org1_invalid_multisig2 = MultiSig::new(vec![org1_signer1_sig, org2_signer1_sig]);
        MultiSig::new(vec![org1_signer1_sig, org1_signer1_sig, org1_signer2_sig]);

        let org2_valid_multisig =
            MultiSig::new(vec![org2_signer1_sig, org2_signer2_sig, org2_signer3_sig]);
        let org2_invalid_multisig1 =
            MultiSig::new(vec![org2_signer1_sig, org2_signer2_sig, org1_signer1_sig]);
        let org2_invalid_multisig2 =
            MultiSig::new(vec![org2_signer1_sig, org2_signer2_sig, org2_signer2_sig]);

        // The top-level multisig requires 1-of-2 signatures
        let signer_set = SignerSet::new(vec![org1_signerset, org2_signerset], 1);

        // With not signatures, the multisig should not verify.
        let multi_sig = MultiSig::new(vec![]);
        assert!(signer_set.verify(message.as_ref(), &multi_sig).is_err());

        // Org1 satisfies the threshold, no org2 signatures.
        let multi_sig = MultiSig::new(vec![org1_valid_multisig.clone()]);
        let signers = signer_set.verify(message.as_ref(), &multi_sig).unwrap();
        assert_eq_ignore_order(
            signers,
            vec![vec![org1_signer1.public_key(), org1_signer3.public_key()]],
        );

        // Org2 satisfies the threshold, no org1 signatures.
        let multi_sig = MultiSig::new(vec![org2_valid_multisig.clone()]);
        let signers = signer_set.verify(message.as_ref(), &multi_sig).unwrap();
        assert_eq_ignore_order(
            signers,
            vec![vec![
                org2_signer1.public_key(),
                org2_signer2.public_key(),
                org2_signer3.public_key(),
            ]],
        );

        // Both orgs satisfy the threshold.
        let multi_sig = MultiSig::new(vec![
            org1_valid_multisig.clone(),
            org2_valid_multisig.clone(),
        ]);
        let signers = signer_set.verify(message.as_ref(), &multi_sig).unwrap();
        assert_eq_ignore_order(
            signers,
            vec![
                vec![org1_signer1.public_key(), org1_signer3.public_key()],
                vec![
                    org2_signer1.public_key(),
                    org2_signer2.public_key(),
                    org2_signer3.public_key(),
                ],
            ],
        );

        // One org satisfies the threshold and one org does not.
        let multi_sig = MultiSig::new(vec![
            org1_valid_multisig.clone(),
            org2_invalid_multisig1.clone(),
            org2_invalid_multisig2.clone(),
        ]);
        let signers = signer_set.verify(message.as_ref(), &multi_sig).unwrap();
        assert_eq_ignore_order(
            signers,
            vec![vec![org1_signer1.public_key(), org1_signer3.public_key()]],
        );

        // Neither orgs provides a valid signature
        let multi_sig = MultiSig::new(vec![
            org1_invalid_multisig1.clone(),
            org1_invalid_multisig2.clone(),
            org2_invalid_multisig1.clone(),
            org2_invalid_multisig2.clone(),
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
        let org1_signerset = SignerSet::new(
            vec![
                org1_signer1.public_key(),
                org1_signer2.public_key(),
                org1_signer3.public_key(),
            ],
            2,
        );

        // Org 2 requires 3-of-3 signatures
        let org2_signer1 = Ed25519Pair::from_random(&mut rng);
        let org2_signer2 = Ed25519Pair::from_random(&mut rng);
        let org2_signer3 = Ed25519Pair::from_random(&mut rng);
        let org2_signerset = SignerSet::new(
            vec![
                org2_signer1.public_key(),
                org2_signer2.public_key(),
                org2_signer3.public_key(),
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

        // Some signatures to test with
        let org1_valid_multisig = MultiSig::new(vec![org1_signer1_sig, org1_signer3_sig]);
        let org1_invalid_multisig1 = MultiSig::new(vec![org1_signer1_sig]);
        let org1_invalid_multisig2 = MultiSig::new(vec![org1_signer1_sig, org2_signer1_sig]);
        MultiSig::new(vec![org1_signer1_sig, org1_signer1_sig, org1_signer2_sig]);

        let org2_valid_multisig =
            MultiSig::new(vec![org2_signer1_sig, org2_signer2_sig, org2_signer3_sig]);
        let org2_invalid_multisig1 =
            MultiSig::new(vec![org2_signer1_sig, org2_signer2_sig, org1_signer1_sig]);
        let org2_invalid_multisig2 =
            MultiSig::new(vec![org2_signer1_sig, org2_signer2_sig, org2_signer2_sig]);

        // The top-level multisig requires 2-of-2 signatures
        let signer_set = SignerSet::new(vec![org1_signerset, org2_signerset], 2);

        // With not signatures, the multisig should not verify.
        let multi_sig = MultiSig::new(vec![]);
        assert!(signer_set.verify(message.as_ref(), &multi_sig).is_err());

        // Org1 satisfies the threshold, no org2 signatures.
        let multi_sig = MultiSig::new(vec![org1_valid_multisig.clone()]);
        assert!(signer_set.verify(message.as_ref(), &multi_sig).is_err());

        // Org2 satisfies the threshold, no org1 signatures.
        let multi_sig = MultiSig::new(vec![org2_valid_multisig.clone()]);
        assert!(signer_set.verify(message.as_ref(), &multi_sig).is_err());

        // Both orgs satisfy the threshold.
        let multi_sig = MultiSig::new(vec![
            org1_valid_multisig.clone(),
            org2_valid_multisig.clone(),
        ]);
        let signers = signer_set.verify(message.as_ref(), &multi_sig).unwrap();
        assert_eq_ignore_order(
            signers,
            vec![
                vec![org1_signer1.public_key(), org1_signer3.public_key()],
                vec![
                    org2_signer1.public_key(),
                    org2_signer2.public_key(),
                    org2_signer3.public_key(),
                ],
            ],
        );

        // One org satisfies the threshold and one org does not.
        let multi_sig = MultiSig::new(vec![
            org1_valid_multisig.clone(),
            org2_invalid_multisig1.clone(),
            org2_invalid_multisig2.clone(),
        ]);
        assert!(signer_set.verify(message.as_ref(), &multi_sig).is_err());

        // Neither orgs provides a valid signature
        let multi_sig = MultiSig::new(vec![
            org1_invalid_multisig1.clone(),
            org1_invalid_multisig2.clone(),
            org2_invalid_multisig1.clone(),
            org2_invalid_multisig2.clone(),
        ]);
        assert!(signer_set.verify(message.as_ref(), &multi_sig).is_err());
    }

    #[test]
    fn test_serde_works() {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);
        let message = b"this is a test";

        let org1_signer1 = Ed25519Pair::from_random(&mut rng);
        let org1_signer2 = Ed25519Pair::from_random(&mut rng);
        let org1_signer3 = Ed25519Pair::from_random(&mut rng);
        let org1_signerset = SignerSet::new(
            vec![
                org1_signer1.public_key(),
                org1_signer2.public_key(),
                org1_signer3.public_key(),
            ],
            2,
        );

        // Org 2 requires 3-of-3 signatures
        let org2_signer1 = Ed25519Pair::from_random(&mut rng);
        let org2_signer2 = Ed25519Pair::from_random(&mut rng);
        let org2_signer3 = Ed25519Pair::from_random(&mut rng);
        let org2_signerset = SignerSet::new(
            vec![
                org2_signer1.public_key(),
                org2_signer2.public_key(),
                org2_signer3.public_key(),
            ],
            3,
        );

        // Sign the message with all of our signers.
        let org1_signer1_sig = org1_signer1.try_sign(message.as_ref()).unwrap();
        let org1_signer2_sig = org1_signer2.try_sign(message.as_ref()).unwrap();

        let org2_signer1_sig = org2_signer1.try_sign(message.as_ref()).unwrap();
        let org2_signer2_sig = org2_signer2.try_sign(message.as_ref()).unwrap();
        let org2_signer3_sig = org2_signer3.try_sign(message.as_ref()).unwrap();

        // Some signatures to test with
        let org1_valid_multisig = MultiSig::new(vec![org1_signer1_sig, org1_signer2_sig]);
        let org2_valid_multisig =
            MultiSig::new(vec![org2_signer1_sig, org2_signer2_sig, org2_signer3_sig]);

        // The top-level multisig requires 2-of-2 signatures
        let multi_sig = MultiSig::new(vec![org1_valid_multisig, org2_valid_multisig]);

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

        assert_eq!(
            multi_sig,
            mc_util_serial::deserialize(&mc_util_serial::serialize(&multi_sig).unwrap()).unwrap(),
        );
    }

    #[test]
    fn test_prost_works() {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);
        let message = b"this is a test";

        let org1_signer1 = Ed25519Pair::from_random(&mut rng);
        let org1_signer2 = Ed25519Pair::from_random(&mut rng);
        let org1_signer3 = Ed25519Pair::from_random(&mut rng);
        let org1_signerset = SignerSet::new(
            vec![
                org1_signer1.public_key(),
                org1_signer2.public_key(),
                org1_signer3.public_key(),
            ],
            2,
        );

        // Org 2 requires 3-of-3 signatures
        let org2_signer1 = Ed25519Pair::from_random(&mut rng);
        let org2_signer2 = Ed25519Pair::from_random(&mut rng);
        let org2_signer3 = Ed25519Pair::from_random(&mut rng);
        let org2_signerset = SignerSet::new(
            vec![
                org2_signer1.public_key(),
                org2_signer2.public_key(),
                org2_signer3.public_key(),
            ],
            3,
        );

        // Sign the message with all of our signers.
        let org1_signer1_sig = org1_signer1.try_sign(message.as_ref()).unwrap();
        let org1_signer2_sig = org1_signer2.try_sign(message.as_ref()).unwrap();

        let org2_signer1_sig = org2_signer1.try_sign(message.as_ref()).unwrap();
        let org2_signer2_sig = org2_signer2.try_sign(message.as_ref()).unwrap();
        let org2_signer3_sig = org2_signer3.try_sign(message.as_ref()).unwrap();

        // Some signatures to test with
        let org1_valid_multisig = MultiSig::new(vec![org1_signer1_sig, org1_signer2_sig]);
        let org2_valid_multisig =
            MultiSig::new(vec![org2_signer1_sig, org2_signer2_sig, org2_signer3_sig]);

        // The top-level multisig requires 2-of-2 signatures
        let multi_sig = MultiSig::new(vec![org1_valid_multisig, org2_valid_multisig]);

        assert_eq!(
            org1_signerset,
            mc_util_serial::decode(&mc_util_serial::encode(&org1_signerset)).unwrap(),
        );
        assert_eq!(
            org2_signerset,
            mc_util_serial::decode(&mc_util_serial::encode(&org2_signerset)).unwrap(),
        );

        assert_eq!(
            multi_sig,
            mc_util_serial::decode(&mc_util_serial::encode(&multi_sig)).unwrap(),
        );
    }
}
