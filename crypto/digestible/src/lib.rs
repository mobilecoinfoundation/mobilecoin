// Copyright (c) 2018-2020 MobileCoin Inc.

#![no_std]

use cfg_if::cfg_if;
pub use digest::{generic_array, Digest};

/// A trait which structs should implement to ensure digests generate consistent
/// hashes.
/// Implementations should be endian-agnostic, and should protect from length extension attacks.
pub trait Digestible {
    /// Add the data from self to the hasher, with any appropriate padding
    fn digest<D: Digest>(&self, hasher: &mut D);

    /// Simply get a hash using a one-off hasher.
    /// This is like a generalization of `Digest::digest`.
    ///
    /// Not recommended to use this when implementing `digest` on your structs.
    fn digest_with<D: Digest + Default>(
        &self,
    ) -> generic_array::GenericArray<u8, <D as Digest>::OutputSize> {
        let mut hasher = D::default();
        self.digest(&mut hasher);
        hasher.result()
    }
}

/// Builtin types

// Unfortunately, there is a tension between the following things:
//
// - Vec<Digestible> should have a generic implementation that inserts length padding, then iterates
// - Vec<u8> should have a fast implementation that inserts length, then passes the entire slice.
// - u8 should be digestible because it is a builtin primitive.
//
// Because rust does not allow Specialization yet, these three things cannot all implement Digestible.
//
// We have almost no use-cases for putting raw u8's in our structs, and we have lots
// of use cases for Vec<Digestible> and Vec<u8> in our structs, so the simplest thing
// is to not mark u8 as digestible.
//
// We should fix this when rust adds support for specialization.
// impl Digestible for u8 {
//    #[inline]
//    fn digest<D: Digest>(&self, hasher: &mut D) {
//        hasher.input(core::slice::from_ref(self))
//    }
// }

impl Digestible for u16 {
    #[inline]
    fn digest<D: Digest>(&self, hasher: &mut D) {
        hasher.input(&self.to_le_bytes())
    }
}

impl Digestible for u32 {
    #[inline]
    fn digest<D: Digest>(&self, hasher: &mut D) {
        hasher.input(&self.to_le_bytes())
    }
}

impl Digestible for u64 {
    #[inline]
    fn digest<D: Digest>(&self, hasher: &mut D) {
        hasher.input(&self.to_le_bytes())
    }
}

impl Digestible for usize {
    #[inline]
    fn digest<D: Digest>(&self, hasher: &mut D) {
        (*self as u64).digest(hasher)
    }
}

/// Occasionally, a type can be digested by the same implementation it uses for
/// AsRef<[u8]>, and no additional padding or magic for security purposes.
/// This is mainly for some core types, there might be other legitimate use cases.
///
/// This marker trait can be used to mark such types. It provides a blanket
/// impl for digestible in terms of AsRef<u8>.
///
/// Adding the magic bytes / length padding is sort of the point of Digestible crate,
/// and this marker trait somewhat subverts that.
pub trait RawDigestible: AsRef<[u8]> + Sized {}

impl<T: RawDigestible> Digestible for T {
    #[inline]
    fn digest<D: Digest>(&self, hasher: &mut D) {
        hasher.input(self)
    }
}

// Built-in byte arrays
impl RawDigestible for [u8; 1] {}
impl RawDigestible for [u8; 2] {}
impl RawDigestible for [u8; 3] {}
impl RawDigestible for [u8; 4] {}
impl RawDigestible for [u8; 5] {}
impl RawDigestible for [u8; 6] {}
impl RawDigestible for [u8; 7] {}
impl RawDigestible for [u8; 8] {}
impl RawDigestible for [u8; 9] {}
impl RawDigestible for [u8; 10] {}
impl RawDigestible for [u8; 11] {}
impl RawDigestible for [u8; 12] {}
impl RawDigestible for [u8; 13] {}
impl RawDigestible for [u8; 14] {}
impl RawDigestible for [u8; 15] {}
impl RawDigestible for [u8; 16] {}
impl RawDigestible for [u8; 17] {}
impl RawDigestible for [u8; 18] {}
impl RawDigestible for [u8; 19] {}
impl RawDigestible for [u8; 20] {}
impl RawDigestible for [u8; 21] {}
impl RawDigestible for [u8; 22] {}
impl RawDigestible for [u8; 23] {}
impl RawDigestible for [u8; 24] {}
impl RawDigestible for [u8; 25] {}
impl RawDigestible for [u8; 26] {}
impl RawDigestible for [u8; 27] {}
impl RawDigestible for [u8; 28] {}
impl RawDigestible for [u8; 29] {}
impl RawDigestible for [u8; 30] {}
impl RawDigestible for [u8; 31] {}
impl RawDigestible for [u8; 32] {}

impl<Length: generic_array::ArrayLength<u8>> RawDigestible
    for generic_array::GenericArray<u8, Length>
{
}

// Implementation for slices of Digestible
// Note that this includes length, because the size is dynamic so we must protect
// against length extension attacks.
//
// See also core::hash::Hash impl for &[T] where T: Hash,
// which is similar
impl<T: Digestible> Digestible for &[T] {
    #[inline]
    fn digest<D: Digest>(&self, hasher: &mut D) {
        self.len().digest(hasher);
        for elem in self.iter() {
            elem.digest(hasher);
        }
    }
}

// Give the good implementation for &[u8], which will be used for Vec<u8> also
impl Digestible for &[u8] {
    #[inline]
    fn digest<D: Digest>(&self, hasher: &mut D) {
        self.len().digest(hasher);
        hasher.input(self);
    }
}

// Implement for Option<T>
// We just add one byte of magic to distinguish Some and None
impl<T: Digestible> Digestible for Option<T> {
    fn digest<D: Digest>(&self, hasher: &mut D) {
        match self {
            Some(ref val) => {
                hasher.input(&[1u8]);
                val.digest(hasher);
            }
            None => {
                hasher.input(&[0u8]);
            }
        }
    }
}

cfg_if! {
    if #[cfg(feature = "alloc")] {
        extern crate alloc;
        use alloc::vec::Vec;
        use alloc::string::String;
        use alloc::collections::BTreeSet;

        // Forward from Vec<T> to &[T] impl
        impl<T: Digestible> Digestible for Vec<T> {
            #[inline]
            fn digest<D: Digest>(&self, hasher: &mut D) {
                <Self as AsRef<[T]>>::as_ref(self).digest(hasher);
            }
        }

        // Forward from Vec<u8> to &[u8] impl
        impl Digestible for Vec<u8> {
            #[inline]
            fn digest<D: Digest>(&self, hasher: &mut D) {
                <Self as AsRef<[u8]>>::as_ref(self).digest(hasher);
            }
        }

        // Forward from String to &[u8] impl
        impl Digestible for String {
            #[inline]
            fn digest<D: Digest>(&self, hasher: &mut D) {
                self.as_bytes().digest(hasher);
            }
        }

        // Forward from &str to &[u8] impl
        impl Digestible for &str {
            #[inline]
            fn digest<D: Digest>(&self, hasher: &mut D) {
                self.as_bytes().digest(hasher);
            }
        }

        impl<T: Digestible> Digestible for BTreeSet<T> {
            #[inline]
            fn digest<D: Digest>(&self, hasher: &mut D) {
                self.len().digest(hasher);
                for elem in self.iter() {
                    elem.digest(hasher);
                }
            }
        }
    }
}

cfg_if! {
    if #[cfg(feature = "dalek")] {
        /// Add support for Dalek primitives
        ///
        /// We have several new-type wrappers around these in MobileCoin and it
        /// would be nice if we could derive digestible for everything in other
        /// MobileCoin crates.
        use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
        use curve25519_dalek::scalar::Scalar;

        // RistrettoPoint requires compression before it can be hashed
        impl Digestible for RistrettoPoint {
            #[inline]
            fn digest<D: Digest>(&self, hasher: &mut D) {
                self.compress().digest(hasher);
            }
        }

        impl Digestible for CompressedRistretto {
            #[inline]
            fn digest<D: Digest>(&self, hasher: &mut D) {
                hasher.input(&self.as_bytes());
            }
        }

        impl Digestible for Scalar {
            #[inline]
            fn digest<D: Digest>(&self, hasher: &mut D) {
                hasher.input(self.as_bytes())
            }
        }

        impl Digestible for ed25519_dalek::PublicKey {
            #[inline]
            fn digest<D: Digest>(&self, hasher: &mut D) {
                hasher.input(self)
            }
        }

        impl Digestible for x25519_dalek::PublicKey {
            #[inline]
            fn digest<D: Digest>(&self, hasher: &mut D) {
                hasher.input(self.as_bytes())
            }
        }
    }
}

// Re-export #[derive(Digestible)].
// Based on serde's equivalent re-export [1], but enabled by default.
//
// [1]: https://github.com/serde-rs/serde/blob/v1.0.89/serde/src/lib.rs#L245-L256
#[cfg(feature = "derive")]
#[doc(hidden)]
pub use mc_crypto_digestible_derive::*;
