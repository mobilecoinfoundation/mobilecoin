// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Multi-signature implementation: A multi-signature is a protocol that allows
//! a group of signers, each possessing a distinct private/public keypair, to
//! produce a joint signature on a common message. The simplest multi-signature
//! of a message is just a set of signatures containing one signature over the
//! message from each member of the signing group. We say that a multi-signature
//! is a k-of-n threshold signature if only k valid signatures are required from
//! a signing group of size n.

#![cfg_attr(not(test), no_std)]
#![deny(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;
use mc_crypto_digestible::Digestible;
use mc_crypto_keys::{PublicKey, Signature, SignatureError, Verifier};
use prost::Message;
use serde::{Deserialize, Serialize};

/// The maximum number of signatures that can be included in a multi-signature.
pub const MAX_SIGNATURES: usize = 10;

/// A multi-signature: a collection of one or more signatures.
#[derive(Clone, Deserialize, Digestible, Eq, Message, PartialEq, Serialize)]
pub struct MultiSig<
    S: Clone + Default + Digestible + Eq + Message + PartialEq + Serialize + Signature,
> {
    #[prost(message, repeated, tag = "1")]
    signatures: Vec<S>,
}

impl<S: Clone + Default + Digestible + Eq + Message + PartialEq + Serialize + Signature>
    MultiSig<S>
{
    /// Construct a new multi-signature from a collection of signatures.
    pub fn new(signatures: Vec<S>) -> Self {
        Self { signatures }
    }
}

/// A set of K-out-of-N public keys.
#[derive(Clone, Deserialize, Digestible, Eq, Message, PartialEq, Serialize)]
#[serde(bound = "")]
pub struct SignerSet<P: Default + PublicKey + Message> {
    /// List of potential signers.
    #[prost(message, repeated, tag = "1")]
    signers: Vec<P>,

    /// Minimum number of signers required.
    #[prost(uint32, tag = "2")]
    threshold: u32,
}

impl<P: Default + PublicKey + Message> SignerSet<P> {
    /// Construct a new `SignerSet` from a list of public keys and threshold.
    pub fn new(signers: Vec<P>, threshold: u32) -> Self {
        Self { signers, threshold }
    }

    /// Verify a message against a multi-signature, returning the list of
    /// signers that signed it.
    pub fn verify<
        S: Clone + Default + Digestible + Eq + Message + PartialEq + Serialize + Signature,
    >(
        &self,
        message: &[u8],
        multi_sig: &MultiSig<S>,
    ) -> Result<Vec<P>, SignatureError>
    where
        P: Verifier<S>,
    {
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
        let mut potential_signers = self.signers.clone();
        potential_signers.sort();
        potential_signers.dedup();

        let mut signatures = multi_sig.signatures.clone();
        signatures.sort_by(|a, b| a.as_ref().cmp(b.as_ref()));
        signatures.dedup();

        // See which signatures which match signers.
        let mut matched_signers = Vec::new();
        for signature in signatures.iter() {
            let matched_signer = potential_signers.iter().find_map(|signer| {
                signer
                    .verify(message, signature)
                    .ok()
                    .map(|_| signer.clone())
            });
            if let Some(matched_signer) = matched_signer {
                potential_signers.retain(|signer| signer != &matched_signer);
                matched_signers.push(matched_signer);
            }
        }

        // Did we pass the threshold of verified signatures?
        if matched_signers.len() < self.threshold as usize {
            return Err(SignatureError::new());
        }

        Ok(matched_signers)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::vec;
    use core::iter::FromIterator;
    use mc_crypto_keys::{Ed25519Pair, Ed25519Public, Signer};
    use mc_util_from_random::FromRandom;
    use rand_core::SeedableRng;
    use rand_hc::Hc128Rng;
    use std::collections::HashSet;

    #[test]
    fn ed25519_verify_signers_sanity() {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);
        let signer1 = Ed25519Pair::from_random(&mut rng);
        let signer2 = Ed25519Pair::from_random(&mut rng);
        let signer3 = Ed25519Pair::from_random(&mut rng);
        let signer4 = Ed25519Pair::from_random(&mut rng);

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
        assert_eq!(
            HashSet::<Ed25519Public>::from_iter(
                signer_set.verify(message.as_ref(), &multi_sig).unwrap()
            ),
            HashSet::from_iter(vec![signer1.public_key(), signer3.public_key()])
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
        assert_eq!(
            HashSet::<Ed25519Public>::from_iter(
                signer_set.verify(message.as_ref(), &multi_sig).unwrap()
            ),
            HashSet::from_iter(vec![
                signer1.public_key(),
                signer2.public_key(),
                signer3.public_key()
            ])
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
        assert_eq!(
            HashSet::<Ed25519Public>::from_iter(
                signer_set.verify(message.as_ref(), &multi_sig).unwrap()
            ),
            HashSet::from_iter(vec![signer1.public_key(), signer3.public_key()])
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
            mc_util_serial::deserialize(&mc_util_serial::serialize(&signer_set).unwrap()).unwrap()
        );

        let message = b"this is a test";
        let multi_sig = MultiSig::new(vec![signer1.try_sign(message.as_ref()).unwrap()]);
        assert_eq!(
            multi_sig,
            mc_util_serial::deserialize(&mc_util_serial::serialize(&multi_sig).unwrap()).unwrap()
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
            mc_util_serial::decode(&mc_util_serial::encode(&signer_set)).unwrap()
        );

        let message = b"this is a test";
        let multi_sig = MultiSig::new(vec![signer1.try_sign(message.as_ref()).unwrap()]);
        assert_eq!(
            multi_sig,
            mc_util_serial::decode(&mc_util_serial::encode(&multi_sig)).unwrap()
        );
    }
}
