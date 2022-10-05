// Copyright (c) 2018-2022 The MobileCoin Foundation

use alloc::vec::Vec;
use core::hash::Hash;
use mc_crypto_digestible::Digestible;
use mc_crypto_keys::Signature;
use prost::Message;
use serde::{Deserialize, Serialize};

/// A collection of one or more signatures.
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

#[cfg(test)]
mod test {
    use super::*;
    use alloc::vec;
    use mc_crypto_keys::{Ed25519Pair, Signer};
    use mc_util_from_random::FromRandom;
    use rand_core::SeedableRng;
    use rand_hc::Hc128Rng;

    #[test]
    fn test_serde_works() {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);
        let signer1 = Ed25519Pair::from_random(&mut rng);
        let signer2 = Ed25519Pair::from_random(&mut rng);

        let message = b"this is a test";
        let multi_sig = MultiSig::new(vec![
            signer1.try_sign(message.as_ref()).unwrap(),
            signer2.try_sign(message.as_ref()).unwrap(),
        ]);
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

        let message = b"this is a test";
        let multi_sig = MultiSig::new(vec![
            signer1.try_sign(message.as_ref()).unwrap(),
            signer2.try_sign(message.as_ref()).unwrap(),
        ]);
        assert_eq!(
            multi_sig,
            mc_util_serial::decode(&mc_util_serial::encode(&multi_sig)).unwrap(),
        );
    }
}
