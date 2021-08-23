// Copyright (c) 2018-2021 The MobileCoin Foundation

//! This crate provides functionality for creating CSPRNG sequences
//! from the results of key exchanges. The key exchange messages are versioned,
//! so that we can be future proof against the need to change the RNG algorithm.
//! The implementation is also generic over Kex algorithms.

#![no_std]
#![deny(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;
use mc_crypto_keys::Kex;
use prost::Message;
use serde::{Deserialize, Serialize};

mod error;
pub use error::Error;

mod traits;
pub use traits::{BufferedRng, KexRng, KexRngCore, NewFromKex};

mod versioned;

/// The backwards compatible KexRng type.
/// Intended for the client.
pub use versioned::VersionedKexRng;

/// A stable KexRngCore type
pub use versioned::KexRng20201124;
/// The latest KexRngCore type.
pub use versioned::LatestKexRngCore;

/// The key exchange message associated to creating a kex rng
#[derive(Clone, Eq, Hash, PartialEq, Message, Serialize, Deserialize)]
pub struct KexRngPubkey {
    /// A canonical representation of KexAlgo public key
    #[prost(bytes, tag = 1)]
    pub public_key: Vec<u8>,
    /// A version number for the RNG algo.
    /// This is u32 for protobuf compatibility.
    #[prost(uint32, tag = 2)]
    pub version: u32,
}

impl KexRngPubkey {
    /// After performing key exchange, take our public key and Core type,
    /// and produce prosty KexRngPubkey record for client, annotated with
    /// version number.
    pub fn from_public_key<Core, KexAlgo>(public: &KexAlgo::Public) -> Self
    where
        KexAlgo: Kex,
        Core: KexRngCore<KexAlgo>,
    {
        use mc_util_repr_bytes::ReprBytes;
        Self {
            public_key: public.map_bytes(|bytes| bytes.to_vec()),
            version: Core::VERSION_ID,
        }
    }
}

/// A stored, wire-stable representation of a KexRng
#[derive(Clone, Eq, Hash, PartialEq, Message)]
pub struct StoredRng {
    /// A canonical representation of Key exchange secret
    #[prost(bytes, tag = 1)]
    pub secret: Vec<u8>,
    /// A canonical representation of KexRng output buffer
    #[prost(bytes, tag = 2)]
    pub buffer: Vec<u8>,
    /// The internal counter of the KexRng
    #[prost(uint64, tag = 3)]
    pub counter: u64,
    /// A version number for the RNG algo.
    /// This is u32 for protobuf compatibility.
    #[prost(uint32, tag = 4)]
    pub version: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::versioned::BufferedKexRng;
    use alloc::vec;
    use blake2::digest::generic_array::GenericArray;
    use core::convert::TryFrom;
    use mc_crypto_keys::{Ristretto, RistrettoPrivate, RistrettoPublic};
    use mc_util_from_random::FromRandom;

    type LatestKexRng = BufferedKexRng<LatestKexRngCore, Ristretto>;

    // Test that the KexRngCore and VersionedKexRng stay in sync
    #[test]
    fn test_core_versioned_sync() {
        mc_util_test_helper::run_with_several_seeds(|mut rng| {
            let a_sec = RistrettoPrivate::from_random(&mut rng);
            let a_pub = RistrettoPublic::from(&a_sec);

            let b_sec = RistrettoPrivate::from_random(&mut rng);
            let b_pub = RistrettoPublic::from(&b_sec);

            let kex_pubkey = KexRngPubkey::from_public_key::<KexRng20201124, Ristretto>(&a_pub);
            let mut rng2 = VersionedKexRng::try_from_kex_pubkey(&kex_pubkey, &b_sec).unwrap();

            use mc_crypto_keys::KexReusablePrivate;
            let shared_secret = a_sec.key_exchange(&b_pub);

            for counter in 0..5 {
                let rng1_out =
                    KexRng20201124::prf(GenericArray::from_slice(shared_secret.as_ref()), &counter);
                let rng2_out = rng2.next().unwrap();
                assert_eq!(&rng1_out[..], &rng2_out[..]);
            }
        })
    }

    // Test that the LatestKexRng and VersionedKexRng stay in sync
    #[test]
    fn test_latest_versioned_sync() {
        mc_util_test_helper::run_with_several_seeds(|mut rng| {
            let a_sec = RistrettoPrivate::from_random(&mut rng);
            let a_pub = RistrettoPublic::from(&a_sec);

            let (kex_pubkey, mut rng1) = LatestKexRng::new_from_ephemeral_static(&mut rng, &a_pub);
            let mut rng2 = VersionedKexRng::try_from_kex_pubkey(&kex_pubkey, &a_sec).unwrap();

            for _ in 0..5 {
                let rng1_out = rng1.next();
                let rng2_out = rng2.next().unwrap();
                assert_eq!(&rng1_out.unwrap()[..], &rng2_out[..]);
            }
        })
    }

    // Test that the LatestKexRng and a Stored version of it stay in sync
    #[test]
    fn test_latest_stored_sync() {
        mc_util_test_helper::run_with_several_seeds(|mut rng| {
            let a_sec = RistrettoPrivate::from_random(&mut rng);
            let a_pub = RistrettoPublic::from(&a_sec);

            let b_sec = RistrettoPrivate::from_random(&mut rng);

            let (_, mut rng1) = LatestKexRng::new_from_static_static(&b_sec, &a_pub);
            let mut rng2 = rng1.clone();

            for counter in 0..5 {
                let rng1_out = rng1.next();
                let rng2_out = rng2.next();
                assert_eq!(rng1_out, rng2_out);
                // Re-initialize rng2 and advance it again
                let (_, rng2_again) = LatestKexRng::new_from_static_static(&b_sec, &a_pub);
                rng2 = rng2_again;
                for _ in 0..counter + 1 {
                    rng2.advance();
                }
            }
        })
    }

    // Test that the VersionedKexRng and a Stored version of it stay in sync
    #[test]
    fn test_versioned_stored_sync() {
        mc_util_test_helper::run_with_several_seeds(|mut rng| {
            let a_sec = RistrettoPrivate::from_random(&mut rng);
            let a_pub = RistrettoPublic::from(&a_sec);

            let (pubkey, _) = LatestKexRng::new_from_ephemeral_static(&mut rng, &a_pub);
            let mut rng1 = VersionedKexRng::try_from_kex_pubkey(&pubkey, &a_sec).unwrap();
            let mut rng2 = rng1.clone();

            for _ in 0..5 {
                let rng1_out = rng1.next().unwrap();
                let rng2_out = rng2.next().unwrap();
                assert_eq!(rng1_out, rng2_out);
                // Pass rng through serialization / deserialization loop
                rng2 = VersionedKexRng::try_from(Into::<StoredRng>::into(rng2)).unwrap();
            }
        })
    }

    // Test vectors
    #[test]
    fn test_vectors() {
        let sec = RistrettoPrivate::try_from(&[1u8; 32]).unwrap();
        let pubkey = KexRngPubkey {
            public_key: vec![2u8; 32],
            version: 0,
        };

        let mut rng = VersionedKexRng::try_from_kex_pubkey(&pubkey, &sec).unwrap();
        assert_eq!(
            vec![132, 242, 245, 227, 36, 201, 3, 30, 31, 185, 46, 96, 56, 231, 162, 36],
            rng.next().unwrap()
        );
        assert_eq!(
            vec![114, 54, 18, 112, 116, 254, 47, 137, 178, 65, 61, 201, 30, 180, 187, 38],
            rng.next().unwrap()
        );
        assert_eq!(
            vec![65, 89, 38, 51, 173, 51, 43, 231, 169, 23, 180, 166, 18, 201, 238, 178],
            rng.next().unwrap()
        );
        assert_eq!(
            vec![72, 62, 241, 90, 78, 182, 115, 153, 103, 6, 13, 105, 15, 63, 106, 206],
            rng.next().unwrap()
        );
    }

    // Tested expected failure with unknown version number
    #[test]
    fn test_expected_failure() {
        let sec = RistrettoPrivate::try_from(&[1u8; 32]).unwrap();
        let pubkey = KexRngPubkey {
            public_key: vec![2u8; 32],
            version: 100,
        };

        assert!(
            VersionedKexRng::try_from_kex_pubkey(&pubkey, &sec).is_err(),
            "Failure to work with version = 100 was expected"
        );
    }
}
