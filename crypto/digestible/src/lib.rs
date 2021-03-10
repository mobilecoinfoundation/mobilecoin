// Copyright (c) 2018-2021 The MobileCoin Foundation

#![no_std]

pub use merlin::Transcript as MerlinTranscript;

use cfg_if::cfg_if;
use generic_array::{ArrayLength, GenericArray};

/// A trait for creating non-malleable digests of objects using merlin
/// transcripts.
///
/// An implementation of the trait brings the DigestTranscript object to the
/// bytes of self in a fixed sequence, adding any appropriate context.
///
/// Intuitively, this is like serializing the object into a series of
/// "append_bytes" calls -- however, the representation must be totally
/// canonical.
///
/// For small objects it likely calls "append_bytes" once.
/// For aggregates it likely calls "append_to_transcript" recursively on the
/// members, passing member names as context. (See digestible-derive crate for
/// specifics.)
///
/// In merlin documentation, having the transcript protocol call itself
/// recursively is called "protocol composition".
/// (We refer the reader to merlin docu for more discussion.)
///
/// Implementations of this trait should generally just call `append_primitive`.
/// The data that they pass should be a canonical representation of the value as
/// bytes. Implementations should not produce results that depends on
/// endianness of the target, should prefer little endian if relevant.
/// Implementations may assume that when calling `append_primitive`, the data
/// will be framed automatically, and need not frame it themselves.
///
/// Implementations of this trait for containers should usually work by calling
/// `append_seq_header` and then iterating over their children and appending
/// them. See `BTreeSet` as an example -- if needed, we could make a macro to
/// reduce the amount of code duplication when doing this.
///
/// Implementations of this trait for structs and enums should generally use
/// `derive(Digestible)`.
///
/// One benefit of this version of Digestible is that it integrates well with
/// Schnorrkel -- a Digestible object can be added directly to the signing
/// transcript, avoiding the overhead of creating multiple merlin transcripts.
pub trait Digestible {
    /// Add the data from self to the transcript
    /// Context should be a string-literal
    fn append_to_transcript<DT: DigestTranscript>(
        &self,
        context: &'static [u8],
        transcript: &mut DT,
    );

    /// Simply get a 32-byte hash using a one-off digest transcript.
    ///
    /// Not recommended to override this
    #[inline]
    fn digest32<DT: DigestTranscript>(&self, context: &'static [u8]) -> [u8; 32] {
        let mut transcript = DT::new();
        self.append_to_transcript(context, &mut transcript);
        let mut result = [0u8; 32];
        transcript.extract_digest(&mut result);
        result
    }

    /// To support schema evolution, in some contexts the generated code for a
    /// Digestible implementation of a compound type should append its
    /// children to the transcript, but allow them to skip themselves if
    /// they are empty. For members of a struct, this is allowed, because
    /// they don't have a fixed set of members but for a variant it isn't
    /// allowed, because the value cannot be omitted.
    ///
    /// The user of the library should normally not call this directly, or
    /// override it. It has special implementations for types like Option.
    #[inline]
    fn append_to_transcript_allow_omit<DT: DigestTranscript>(
        &self,
        context: &'static [u8],
        transcript: &mut DT,
    ) {
        self.append_to_transcript(context, transcript)
    }
}

/// A trait implemented by protocol transcript objects.
/// This represents the functions of merlin::Transcript that we need for
/// digestible to function. By having a trait, we can easily substitute mock
/// objects for tests, etc.,
pub trait DigestTranscript {
    // These low-level calls are needed to implement digest32 etc.,
    // and correspond to raw calls on a MerlinTranscript
    fn new() -> Self;
    fn append_bytes(&mut self, context: &'static [u8], data: impl AsRef<[u8]>);
    fn extract_digest(self, output: &mut [u8; 32]);

    // These high-level calls should be used exclusivley when implementing
    // digestible. These four calls correspond to the four types of nodes in the
    // AST that is being encoded into the digest.
    //
    // Not recommended to override any of these, except for testing purposes

    /// Append a primitive with particular context string, type name, and byte
    /// data.
    ///
    /// The context string comes from the caller context.
    /// If the primitive is a struct member, this is its field name.
    /// If the primitive is an enum member, this is the variant name.
    /// If the primitive is the only thing being digested, the context string
    /// comes from the call to digest32.
    ///
    /// The typename is an arbitrary string representing the type of the data,
    /// for example, `uint`, `int`, `bool`, `bytes`, `str`, `ristretto`
    ///
    /// The data is the canonical bytes representing the primitive.
    /// If the primitive does not have a canonical representation as bytes then
    /// it isn't appropriate to treat it as a primitive in this hashing scheme.
    #[inline]
    fn append_primitive(
        &mut self,
        context: &'static [u8],
        typename: &'static [u8],
        data: impl AsRef<[u8]>,
    ) {
        self.append_bytes(context, ast_domain_separators::PRIMITIVE);
        self.append_bytes(typename, data);
    }

    /// Begin a sequence with a particular context string and length.
    ///
    /// The context string comes from the caller context.
    /// The length is the number of elements you will then append to the
    /// transcript. You must actually append all of these elements, and it
    /// is not okay to omit any of them.
    #[inline]
    fn append_seq_header(&mut self, context: &'static [u8], len: usize) {
        debug_assert!(len != 0, "You should usually use append_none when length is zero, to better support schema evolution");
        self.append_bytes(context, ast_domain_separators::SEQUENCE);
        self.append_bytes(b"len", (len as u64).to_le_bytes());
    }

    /// Begin an aggregate.
    ///
    /// The context string comes from the caller context, the type_name should
    /// normally be the identifier of the struct.
    /// You should then append any elements correpsonding to members of the
    /// struct, with appropriate context strings, then append a matching
    /// aggregate closer.
    #[inline]
    fn append_agg_header(&mut self, context: &'static [u8], type_name: &[u8]) {
        self.append_bytes(context, ast_domain_separators::AGGREGATE);
        self.append_bytes(b"name", type_name);
    }

    /// Close an aggregate
    ///
    /// The context string and type name must match the header that you are
    /// closing.
    #[inline]
    fn append_agg_closer(&mut self, context: &'static [u8], type_name: &[u8]) {
        self.append_bytes(context, ast_domain_separators::AGGREGATE_END);
        self.append_bytes(b"name", type_name);
    }

    /// Create a variant with a particular context string, type_name, and
    /// discriminant.
    ///
    /// You must append one valid AST node after this header to complete the
    /// variant node, and this node must not be omitted.
    #[inline]
    fn append_var_header(&mut self, context: &'static [u8], type_name: &[u8], which: u32) {
        self.append_bytes(context, ast_domain_separators::VARIANT);
        self.append_bytes(b"name", type_name);
        self.append_bytes(b"which", which.to_le_bytes());
    }

    /// Append a node signifying the absence of data.
    ///
    /// This is used with
    /// (1) empty options, when it is not allowed to omit completely
    /// (2) empty sequences, when it is not allowed to omit completely
    /// (3) rust enum without any associated data, because it is not allowed to
    /// omit completely
    #[inline]
    fn append_none(&mut self, context: &'static [u8]) {
        self.append_bytes(context, ast_domain_separators::NONE);
    }
}

impl DigestTranscript for MerlinTranscript {
    #[inline]
    fn new() -> Self {
        Self::new(b"digestible")
    }
    #[inline]
    fn append_bytes(&mut self, context: &'static [u8], data: impl AsRef<[u8]>) {
        self.append_message(context, data.as_ref())
    }
    #[inline]
    fn extract_digest(mut self, output: &mut [u8; 32]) {
        self.challenge_bytes(b"digest32", &mut output[..])
    }
}

// The string constants used as domain separators for the four AST types
pub mod ast_domain_separators {
    pub const PRIMITIVE: &[u8] = b"prim";
    pub const SEQUENCE: &[u8] = b"seq";
    pub const AGGREGATE: &[u8] = b"agg";
    pub const AGGREGATE_END: &[u8] = b"agg-end";
    pub const VARIANT: &[u8] = b"var";
    pub const NONE: &[u8] = b"";
}

/// Builtin types

// Unfortunately, there is a tension between the following things:
//
// - Vec<Digestible> should have a generic implementation that inserts length
//   padding, then iterates
// - Vec<u8> should have a fast implementation that inserts length, then passes
//   the entire slice.
// - u8 should be digestible because it is a builtin primitive.
//
// Because rust does not allow Specialization yet, these three things cannot all
// implement Digestible.
//
// We have almost no use-cases for putting raw u8's in our structs, and we have
// lots of use cases for Vec<Digestible> and Vec<u8> in our structs, so the
// simplest thing is to not mark u8 as digestible.
//
// We should fix this when rust adds support for specialization.
// impl Digestible for u8 {
//    #[inline]
//    fn digest<D: Digest>(&self, hasher: &mut D) {
//        hasher.update(core::slice::from_ref(self))
//    }
// }

impl Digestible for u16 {
    #[inline]
    fn append_to_transcript<DT: DigestTranscript>(
        &self,
        context: &'static [u8],
        transcript: &mut DT,
    ) {
        // Note: encoding of the size of the uint is implicit in merlin's framing
        transcript.append_primitive(context, b"uint", &self.to_le_bytes())
    }
}

impl Digestible for u32 {
    #[inline]
    fn append_to_transcript<DT: DigestTranscript>(
        &self,
        context: &'static [u8],
        transcript: &mut DT,
    ) {
        transcript.append_primitive(context, b"uint", &self.to_le_bytes())
    }
}

impl Digestible for u64 {
    #[inline]
    fn append_to_transcript<DT: DigestTranscript>(
        &self,
        context: &'static [u8],
        transcript: &mut DT,
    ) {
        transcript.append_primitive(context, b"uint", &self.to_le_bytes())
    }
}

impl Digestible for i8 {
    #[inline]
    fn append_to_transcript<DT: DigestTranscript>(
        &self,
        context: &'static [u8],
        transcript: &mut DT,
    ) {
        transcript.append_primitive(context, b"int", &self.to_le_bytes())
    }
}

impl Digestible for i16 {
    #[inline]
    fn append_to_transcript<DT: DigestTranscript>(
        &self,
        context: &'static [u8],
        transcript: &mut DT,
    ) {
        transcript.append_primitive(context, b"int", &self.to_le_bytes())
    }
}

impl Digestible for i32 {
    #[inline]
    fn append_to_transcript<DT: DigestTranscript>(
        &self,
        context: &'static [u8],
        transcript: &mut DT,
    ) {
        transcript.append_primitive(context, b"int", &self.to_le_bytes())
    }
}

impl Digestible for i64 {
    #[inline]
    fn append_to_transcript<DT: DigestTranscript>(
        &self,
        context: &'static [u8],
        transcript: &mut DT,
    ) {
        transcript.append_primitive(context, b"int", &self.to_le_bytes())
    }
}

impl Digestible for usize {
    #[inline]
    fn append_to_transcript<DT: DigestTranscript>(
        &self,
        context: &'static [u8],
        transcript: &mut DT,
    ) {
        (*self as u64).append_to_transcript(context, transcript);
    }
}

impl Digestible for isize {
    #[inline]
    fn append_to_transcript<DT: DigestTranscript>(
        &self,
        context: &'static [u8],
        transcript: &mut DT,
    ) {
        (*self as i64).append_to_transcript(context, transcript);
    }
}

impl Digestible for bool {
    #[inline]
    fn append_to_transcript<DT: DigestTranscript>(
        &self,
        context: &'static [u8],
        transcript: &mut DT,
    ) {
        transcript.append_primitive(context, b"bool", core::slice::from_ref(&(*self as u8)))
    }
}

// Treat &[u8] as a primitive "bytes" types
impl Digestible for &[u8] {
    #[inline]
    fn append_to_transcript<DT: DigestTranscript>(
        &self,
        context: &'static [u8],
        transcript: &mut DT,
    ) {
        transcript.append_primitive(context, b"bytes", self);
    }
}

/// Occasionally, a type can be digested by the same implementation it uses for
/// AsRef<[u8]>, and no additional disambiguating context information or type
/// information.
///
/// This is mainly for some core types that really are just dumb representations
/// of bytes.
///
/// This trait can be used to mark such types. It provides a blanket
/// impl for digestible in terms of AsRef<u8>.
///
/// Don't use this without thinking carefully!
pub trait DigestibleAsBytes: AsRef<[u8]> + Sized {}

impl<T: DigestibleAsBytes> Digestible for T {
    #[inline]
    fn append_to_transcript<DT: DigestTranscript>(
        &self,
        context: &'static [u8],
        transcript: &mut DT,
    ) {
        <Self as AsRef<[u8]>>::as_ref(self).append_to_transcript(context, transcript);
    }
}

// Built-in byte arrays
// FIXME: When const-generics are stable, replace this
impl DigestibleAsBytes for [u8; 1] {}
impl DigestibleAsBytes for [u8; 2] {}
impl DigestibleAsBytes for [u8; 3] {}
impl DigestibleAsBytes for [u8; 4] {}
impl DigestibleAsBytes for [u8; 5] {}
impl DigestibleAsBytes for [u8; 6] {}
impl DigestibleAsBytes for [u8; 7] {}
impl DigestibleAsBytes for [u8; 8] {}
impl DigestibleAsBytes for [u8; 9] {}
impl DigestibleAsBytes for [u8; 10] {}
impl DigestibleAsBytes for [u8; 11] {}
impl DigestibleAsBytes for [u8; 12] {}
impl DigestibleAsBytes for [u8; 13] {}
impl DigestibleAsBytes for [u8; 14] {}
impl DigestibleAsBytes for [u8; 15] {}
impl DigestibleAsBytes for [u8; 16] {}
impl DigestibleAsBytes for [u8; 17] {}
impl DigestibleAsBytes for [u8; 18] {}
impl DigestibleAsBytes for [u8; 19] {}
impl DigestibleAsBytes for [u8; 20] {}
impl DigestibleAsBytes for [u8; 21] {}
impl DigestibleAsBytes for [u8; 22] {}
impl DigestibleAsBytes for [u8; 23] {}
impl DigestibleAsBytes for [u8; 24] {}
impl DigestibleAsBytes for [u8; 25] {}
impl DigestibleAsBytes for [u8; 26] {}
impl DigestibleAsBytes for [u8; 27] {}
impl DigestibleAsBytes for [u8; 28] {}
impl DigestibleAsBytes for [u8; 29] {}
impl DigestibleAsBytes for [u8; 30] {}
impl DigestibleAsBytes for [u8; 31] {}
impl DigestibleAsBytes for [u8; 32] {}

impl<Length: ArrayLength<u8>> DigestibleAsBytes for GenericArray<u8, Length> {}

// Implementation for slices of Digestible
// This is treated as a Seq in the abstract structure hashing schema
//
// Note that this includes length, because the size is dynamic so we must
// protect against length extension attacks.
impl<T: Digestible> Digestible for &[T] {
    #[inline]
    fn append_to_transcript<DT: DigestTranscript>(
        &self,
        context: &'static [u8],
        transcript: &mut DT,
    ) {
        if self.is_empty() {
            // This allows for schema evolution in variant types, it means Vec can be added
            // to a fieldless enum
            transcript.append_none(context);
        } else {
            transcript.append_seq_header(context, self.len());
            for elem in self.iter() {
                elem.append_to_transcript(b"", transcript);
            }
        }
    }

    // When context allows us to omit the element, we omit it if it is empty.
    // This means that, for example, new Vec can be added as structure members,
    // without changing the hash of old structures where the Vec is empty.
    // This is similar to how new "repeated" fields can be added in protobuf.
    #[inline]
    fn append_to_transcript_allow_omit<DT: DigestTranscript>(
        &self,
        context: &'static [u8],
        transcript: &mut DT,
    ) {
        if !self.is_empty() {
            self.append_to_transcript(context, transcript);
        }
    }
}

// Implement for Option<T>
//
// Option has a special implementation because it is used to allow for schema
// evolution, like "optional" fields in protobuf.
//
// When we are allowed to omit ourselves, we don't append anything to transcript
// when we are empty. When we aren't allowed to omit ourselves, we call
// append_none on the transcript if we are empty.
impl<T: Digestible> Digestible for Option<T> {
    #[inline]
    fn append_to_transcript<DT: DigestTranscript>(
        &self,
        context: &'static [u8],
        transcript: &mut DT,
    ) {
        match self {
            None => {
                transcript.append_none(context);
            }
            Some(ref val) => {
                val.append_to_transcript(context, transcript);
            }
        }
    }
    // When we are permitted to omit ourselves, we don't create an AST node at all
    // when we are empty
    #[inline]
    fn append_to_transcript_allow_omit<DT: DigestTranscript>(
        &self,
        context: &'static [u8],
        transcript: &mut DT,
    ) {
        if let Some(ref val) = self {
            val.append_to_transcript_allow_omit(context, transcript);
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
            fn append_to_transcript<DT: DigestTranscript>(&self, context: &'static [u8], transcript: &mut DT) {
                <Self as AsRef<[T]>>::as_ref(self).append_to_transcript(context, transcript);
            }
            #[inline]
            fn append_to_transcript_allow_omit<DT: DigestTranscript>(&self, context: &'static [u8], transcript: &mut DT) {
                <Self as AsRef<[T]>>::as_ref(self).append_to_transcript_allow_omit(context, transcript);
            }
        }

        // Forward from Vec<u8> to &[u8] impl
        impl Digestible for Vec<u8> {
            #[inline]
            fn append_to_transcript<DT: DigestTranscript>(&self, context: &'static [u8], transcript: &mut DT) {
                <Self as AsRef<[u8]>>::as_ref(self).append_to_transcript(context, transcript);
            }
        }

        // Forward from String to &[str] impl
        impl Digestible for String {
            #[inline]
            fn append_to_transcript<DT: DigestTranscript>(&self, context: &'static [u8], transcript: &mut DT) {
                <Self as AsRef<str>>::as_ref(self).append_to_transcript(context, transcript);
            }
        }

        // Forward from &str to &[u8] impl
        impl Digestible for &str {
            #[inline]
            fn append_to_transcript<DT: DigestTranscript>(&self, context: &'static [u8], transcript: &mut DT) {
                transcript.append_primitive(context, b"str", self.as_bytes());
            }
        }

        // Treat a BTreeSet as a (sorted) sequence
        // This implementation should match that for &[T]
        impl<T: Digestible> Digestible for BTreeSet<T> {
            #[inline]
            fn append_to_transcript<DT: DigestTranscript>(&self, context: &'static [u8], transcript: &mut DT) {
                if self.is_empty() {
                    // This allows for schema evolution in variant types, it means Vec can be added to a fieldless enum
                    transcript.append_none(context);
                } else {
                    transcript.append_seq_header(context, self.len());
                    for elem in self.iter() {
                        elem.append_to_transcript(b"", transcript);
                    }
                }
            }
            #[inline]
            fn append_to_transcript_allow_omit<DT: DigestTranscript>(&self, context: &'static [u8], transcript: &mut DT) {
                if !self.is_empty() {
                    self.append_to_transcript(context, transcript);
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
            fn append_to_transcript<DT: DigestTranscript>(&self, context: &'static [u8], transcript: &mut DT) {
                self.compress().append_to_transcript(context, transcript);
            }
        }

        impl Digestible for CompressedRistretto {
            #[inline]
            fn append_to_transcript<DT: DigestTranscript>(&self, context: &'static [u8], transcript: &mut DT) {
                transcript.append_primitive(context, b"ristretto", self.as_bytes())
            }
        }

        impl Digestible for Scalar {
            #[inline]
            fn append_to_transcript<DT: DigestTranscript>(&self, context: &'static [u8], transcript: &mut DT) {
                transcript.append_primitive(context, b"scalar", self.as_bytes())
            }
        }

        impl Digestible for ed25519_dalek::PublicKey {
            #[inline]
            fn append_to_transcript<DT: DigestTranscript>(&self, context: &'static [u8], transcript: &mut DT) {
                transcript.append_primitive(context, b"ed25519", self.as_bytes())
            }
        }

        impl Digestible for x25519_dalek::PublicKey {
            #[inline]
            fn append_to_transcript<DT: DigestTranscript>(&self, context: &'static [u8], transcript: &mut DT) {
                transcript.append_primitive(context, b"x25519", self.as_bytes())
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
