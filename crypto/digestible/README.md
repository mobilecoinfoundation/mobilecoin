mc-crypto-digestible
==========

`mc-crypto-digestible` and its companion crate `mc-crypto-digestible-derive`,
represent a scheme for secure (nonmalleable) hashing of structured data, using
protocol transcript objects like Merlin.

This represents critical infrastructure for
blockchain projects, because if e.g. an attacker can find two different blocks with
the same hash, they can subvert the integrity of the blockchain.

This approach is based on two ideas:
- Use a trait, and define the hashing strategy on a per-type basis.
  This is the `Digestible` trait provided by this crate.
- Use code-gen to generate correct implementations of the trait, to reduce the
  amount of manually-written security critical code to a minimum.
  This is the proc-macro offered by the `mc-crypto-digestible-derive` crate.

Engineering goals:
- The hash must be stable and canonical, not depending on implementation details
  of e.g. a serialization library, which typically do not provide byte-for-byte stability.
- The hash should be portable. It should be straightforward for an engineer with a schema
  for our blockchain and to write a C program, or a python program that loads our blockchain and
  computes the hash successfully. (They might have to call out to the C implementation of Merlin.)
  The hash should certainly not be dependent on details of the Rust programming language.
- The hash scheme should support protobuf-style *schema evolution*. This means,
  it should be possible to add a new optional field to a transaction-related structure,
  without changing the hash of transactions that don't have the field. This gives us a way
  to add new features without breaking ledger compatibility. (We use the rust core `Option` type
  for this, similarly to how `prost` uses `Option` for optional proto members.)
  Similarly, it should be possible to add `repeated` elements to structs without breaking the hash.
  (We use the rust core `Vec` type for this, similarly to how `prost` uses `Vec` for repeated proto members.)
  Simliarly, it must be possible to add new types to enums without changing the hashes of
  the old enum values.

Comparison with other approaches
--------------------------------

Traditionally, blockchains are based directly on a cryptographic hash function,
such as SHA256-d in the case of bitcoin. This hash function takes only bytes.
A canonical method for marshalling a block into bytes-on-the-wire before the hash,
is defined in an RFC, and reviewed by cryptographers. Usually this spec explicitly
mentions every datatype in the blockchain and how to handle it. Then, this spec must
be implemented by engineers.

Because implementing such a spec involves significant labor, and requires
manual changes whenever members are added or removed to the schema, this creates
a lot of friction for development.

In our approach, we have tried to create the spec with the idea that it will be
easily implemented using rust proc macros that won't have to change as the schema
evolves. This makes it a lot easier for non-cryptographers to make significant
changes to the blockchain and transaction data-structures, without creating
tech debt / security problems, and generally eases development.

To achieve this goal, we have to create a simple schema to which all blockchain data structures
are mapped. This schema is language agnostic.

There are 4 types of elements in the schema, which we will discuss later:

- Primitives
- Aggregates
- Sequences
- Variants

The origin of these four types is, the different cases in which we had to add some kind of padding
or framing, in order to prove the security of early drafts of the system.
Primitives are type-length-value encodings of fixed sized elements with
canoncial representations as bytes. The other three are various kinds of compound datatypes.

To implement `Digestible` on a type correctly, first we have to choose which of
these things to interpret it as. Usually, there is only one possibility. Sometimes, it could
have multiple interpretations, but there is usually only one good choice.
The trait implementations and proc macros that come with the crate are meant to do the right thing.

The spec then explains how exactly we should hash any particular AST following this schema. If the
type is a complex type, then this will be specified recursively in terms of how
we hash its constituent elements. This brings us to the next point.

Use of merlin instead of a cryptographic hash function
--------------------------------------------------

Traditionally, blockchain hashing is based on a cryptographic hash function,
which is assumed to be "collision resistant".
This means that it is infeasible for an adversary to find two
strings `x`, `y`, such that `SHA256(x) == SHA256(y)`.

Ultimately, the security of the blockchain hashing strategy must reduce to this
property. If two blocks are not logically equal, then they must not marshall down to the
same bytes before being fed into SHA256. As long as this is the case, then it is
infeasible for the adversary to find two different logical block values with the same hash.

One of the most difficult things in such marshalling schemes is the requirement to
systematically apply domain separation and framing to prevent ambiguity from arising.
It is difficult to create a test that this has been done correctly.

In the `dalek-cryptography` ecosystem, `merlin` has emerged as an alternative approach
to these kinds of domain-separation issues when hashing complex objects.

A *merlin transcript* is superficially like a `Digest` object from the `digest` crate.
It represents a stateful cryptographic primitive of fixed size. Just as bytes can be
fed as "input" to a `Digest`, bytes can be appended to a merlin transcript, which is combined
irreversibly with the current state, using the Keccak primitive.

A `Digest` object generally only produces output when it is finalized. A merlin transcript
in principle can produce output ("challenge bytes") at any time. This is mainly useful
when attempting to perform the Fiat-Shamir transform to create Zero-Knowledge proofs.

Whereas there are many possible cryptographic hash functions that implement `Digest`,
and a hash function is fundamentally a function on byte sequences, a Merlin transcript is not.
Merlin requires the use of context strings whenever bytes are added, and automatically
puts "framing" around the byte string, by prepending the length as a little-endian 4 byte number.
Appending "abcd" to a Merlin transcript is never the same as appending "ab" and then appending "cd",
no matter what context strings are used.

The notion that we recursively walk the AST when computing the digest of a structure,
is referred to more generally as "protocol composition" in the merlin documentation -- the idea
that a larger protocol can define its transcript by recursviely including the transcripts of sub protocols.

`merlin` is also well-integrated with the `schnorrkel` signature crate. Instead of signing
hashes of messages, `Schnorrkel` can consume a merlin transcript and produce a signature of
that without again hashing it, which is arguably simpler overall and more efficient.

Security assumptions around merlin
----------------------------------

The digestible crate requires only the following security assumption around merlin transcripts:

For any merlin transcript (in any particular internal state), it is infeasible to find
two distinct sequences of `append_message` calls such that a final call to `challenge_bytes`
(producing at least 32 challenge bytes, with a particular context string), yields
the same challenge bytes.

We note that
(1) This assumption underlies the use of Merlin for the Fiat-Shamir transform. If this
property doesn't hold, then likely creates a source of malleability in any zero-knoweldge proof schemes based on it.
That is, Merlin was specifically designed to do something stronger than this.
(2) A primitive that does this can be built from any collision resistant hash function.
For instance, if we assume that SHA3 is collision resistant, then a valid implementation
of `DigestTranscript` would be:
- Implement `append_bytes(context, message)` by
  - Encoding context and message using any particular prefix-free encoding of the set of all pairs of byte strings,
  - Inputting this result into the Sha3 digest object.
- Implement `extract_digest` by finalizing the digest object.

Since there are primitives that do this under reasonable assumptions, it is not unreasonable
to assume that Merlin does this. Ultimately Merlin is itself based on the STROBE protocol framework,
which is in turn based on Keccak. If SHA3 has this property at all it seems very likely that merlin
does as well.

In fact, there are certain cases when we WANT to be able to use a traditional digest function
with the `digestible` crate. For instance, if we need to create an ed25519ph signature, then the
API requires us to provide a SHA512 hasher to which the message has already been marshalled. If you need to do this,
you can use the `digestible` trait with the `PseudoMerlin` object in `mc-crypto-hashes`. `PseudoMerlin`
carefully emulates the API of merlin for appending bytes, on top of an arbitrary cryptographic hash function.
If the chosen hash function is strongly collision resistant in the classical sense, then `PseudoMerlin` is suitable
for use with the `Digestible` crate to create non-malleable hashes.

It is recommended not to use `PseudoMerlin`, and to prefer `Merlin` unless something compels you
to use `PseudoMerlin`.

Specification:
===============

First, we must describe the AST which represents what goes into the digest.

- A primitive is a "simple" type (as opposed to a compound type that has a canonical representation as bytes.
- A sequence is a variable length sequence of values of some other type. A sequence has a length known at runtime.
- An aggregate is a fixed-length sequence of values ("fields"), of different types. Each field has a field name.
- A variant is a single value which may be one of several different types. Each possibility has an associated name, in the context of this variant. In the sequel we call this the "variant possibility name".

For each AST node, there is a protocol for adding it to the digest transcript.
(For comparison, see [Merlin transcript protocols](https://merlin.cool/use/protocol.html), or [ASN.1](https://en.wikipedia.org/wiki/ASN.1).)

Recall that the fundamental operation of Merlin is `append_message` which takes a `&'static [u8]` context string, which should generally be a string literal,
and a `&[u8]` data value.

In our protocol, *whenever* an AST node is appended to the transcript, _a context string must be supplied by the caller_.
At the root node of the AST, the user supplies this. When the root node is a compound node, the protocol specifies the context strings
when appending its children.

A *primitive* with given typename is appended to the Merlin transcript as follows:

```
impl DigestTrancript {
    fn append_primitive(&mut self, context: &[u8], typename: &[u8], data: impl AsRef<[u8]>) {
        self.append_bytes(context, "prim");
        self.append_bytes(typename, data);
    }
}

impl Digestible for u32 {
    fn append_to_transcript(&self, context: &[u8], transcript: &mut impl DigestTranscript) {
        transcript.append_primitive(context, b"uint", &self.to_le_bytes())
    }
}
```

An *aggregate* is appended to the Merlin transcript by first appending an aggregate header (which includes the typename),
then appending each field, then appending an aggregate closer. When appending each field, the _field name is used as the context string_.

```
impl DigestTrancript {
    fn append_agg_header(&mut self, context: &[u8], type_name: &[u8]) {
        self.append_bytes(context, "agg");
        self.append_bytes("name", type_name);
    }
    fn append_agg_closer(&mut self, context: &[u8], type_name: &[u8]) {
        self.append_bytes(context, "agg-end");
        self.append_bytes("name", type_name);
    }
}

impl Digestible for MyAggregate {
    fn append_to_transcript(&self, context: &[u8], transcript: &mut DigestTranscript) {
        transcript.append_agg_header(context, "%aggregate_type_name");
        self.%field0.append_to_transcript("%field0", transcript);
        self.%field1.append_to_transcript("%field1", transcript);
        ...
        transcript.append_agg_closer(context, "%aggregate_type_name");
    }
}
```

The choice to use an explicit closer, rather than encoding the
number of members in the aggregate, permits *schema evolution* by the addition of new optional members, without changing the hash
of old objects.

A *sequence* is appended to the Merlin transcript by first appending a sequence header (which includes the length),
and then appending each sequence member. When appending each member, _the empty string is used as the context string_.

```
impl DigestTrancript {
    fn append_seq_header(&mut self, context: &[u8], len: usize) {
        self.append_bytes(context, "seq");
        self.append_bytes("len", (len as u64).to_le_bytes());
    }
}

impl Digestible for MySequence {
    fn append_to_transcript(&self, context: &[u8], transcript: &mut impl DigestTranscript) {
        if !self.is_empty() {
            transcript.append_seq_header(context, self.len());
            for elem in self.iter() {
                elem.append_to_transcript(b"", transcript);
            }
        } else {
            transcript.append_none(context);
        }
    }
}
```

A *none* is a special primitive used in a few corner cases. It can be thought of as a special kind of primitive.
Its role is to help with support for schema evolution. Types like empty sequences and empty optional's can map to None
in the cases when it isn't possible to completely omit them from the hash.

```
impl DigestTrnacript {
    fn append_none(&mut self, context: &[u8]) {
        self.append_bytes(context, "");
    }
}
```

A *variant* is appended to the Merlin transcript by first appending a variant header. Then, the value of the variant is appended to the transcript, and the _variant possibility name is used as the context string_.

The possibilities of a variant are each assigned a distinct number. A runtime value of the variant type has a number called the *discriminant* which indicates
which possibility is present.

```
impl DigestTranscript {
    fn append_var_header(&mut self, context: &[u8], type_ident &[u8], which: u32) {
        self.append_bytes(context, "var");
        self.append_bytes("name", type_name);
        self.append_bytes("which", which.to_le_bytes());
    }
}

impl Digestible for MyVariant {
    fn append_to_transcript(&self, context: &[u8], transcript: &mut impl DigestTranscript) {
        match self {
            ...
            Self::%variant_possibility_name(val) => {
                transcript.append_var_header(context, "%variant_name", %discriminant);
                val.append_to_transcript("%variant_possibility_name", transcript);
            },
            ...
        }
    }
```

Accessing the discriminant is different in different contexts -- in protobuf `.case()` is often
the API for getting this number. In C++ `boost::variant` and similar libraries, `.which()` is used. Stable rust does not expose an API for
getting this number directly, rust considers it an unspecified implementation detail for now. When `derive(Digestible)` is used with a
rust enum, the generated code obtains this value, by using the declaration order of the enumerators.

Correctness:
------------

The correctness of the protocol means that, for any two distinct ASTs, the two corresponding sequences of `append_bytes` calls to Merlin
are different. With this property in hand, we can be sure that two distinct ASTs have different hashes, assuming the collision resitance property of Merlin.

It is beyond the scope of this README to establish this property formally, but we refer the reader to a separate document which will establish this (TODO).
The main idea is to show that the map from possible ASTs to possible sequences of `(context, data)` pairs is a prefix-free map.
We prove this by induction on the structure of the AST.

Implementation notes and examples:
==================================

Primitives:
-----------

For this discussion, a *primitive* is a type which *has a canonical, portable representation as bytes*.

`Digestible` is implemented in this crate for *built-in integer types*, *byte slices and arrays*, and *strings*.

For built-in integer types, we specify the use of little-endian byte encoding, as merlin uses internally
for the encoding of buffer lengths. The type signifier is `"uint"` for unsigned and `"int"` for signed.
For integer types like `size_t` which have different possible sizes on different platforms, we specify that
they should be converted to 64-bit integers and then encoded, for portability.
For `bool`, the type signifier is `"bool"` and the data is `[0u8]` in case of `false` and `[1u8]` in case of `true`.

For buffers of bytes e.g. `Vec<u8>` the bytes themselves are the canonical representation. The type signifier is `"bytes"`.

For a UTF-8 string, the canonical byte representation is used. The type signifier is `"str"`.

For curve25519-scalars, the canonical byte representation is used, and the type signifier is `"scalar"`.
For Ristretto curve points, the canonical byte representation is used, and the type signifier is `"ristretto"`.
For ed25519 curve points, the canonical byte representation is used, and the type signifier is `"ed25519"`.
For x25519 curve points, the canonical byte representation is used, and the type signifier is `"x25519"`.

You can add custom primitives by implementing `Digestible` and making `append_to_transcript` call `append_primitive`.
You should choose a new type signifier if appropriate, and the data must be a portable, canonical representation of the
value as bytes.

Sequences:
----------

For this discussion, a *sequence* is a type representing a variable length sequence of elements
of a type which is digestible.

In rust sequences are iterable.
In protobuf sequences are usually represented using the `repeated` modifier.

In this crate, rust slices, and `Vec` are mapped to `seq` AST nodes.

For ordered sets, we specify that the ordered set should be treated as a `seq` AST node,
and the elements visited in increasing order.

In this crate, we implement `Digestible` for `BTreeSet` in this way.
It would be acceptable to implement `Digestible` for `BTreeMap` as well, thinking
of the BTreeMap as an ordered sequence of pairs, and mapping it to `seq` AST node.

Note that byte sequences are NOT treated as `seq` AST nodes, they are treated as primitives,
which significantly improves efficiency.

Aggregates:
-----------

For this discussion, an *aggregate* is a type consisting of a fixed sequence of members,
possibly of different types, which are themselves `digestible`.

An aggregate has a name (identifier for the type in source code).
The members have associated identifiers (identifier for the member in source code).

In Rust, a struct or tuple is typically an aggregate.
In protobuf, a message is an aggregate.
In type theory is this is sometimes called a product type.

For an aggregate, we specify that `append_to_transcript` shall be implemented as:

```
    fn append_to_transcript(&self, context: &[u8], transcript: &mut Transcript) {
        transcript.append_agg_header(context, "%aggregate_type_name");
        self.%field0.append_to_transcript("%field0", transcript);
        self.%field1.append_to_transcript("%field1", transcript);
        ...
        transcript.append_agg_closer(context, "%aggregate_type_name");
    }
```

For rust tuples, we treat the index of the element in the tuple as its field name, counting from 0,
and the aggregate type name should be the stringification of the tokens representing the type.

Variants:
---------

For this discussion a *variant* is a type whose values are values from one-of a fixed number of other types,
which are themselves `digestible`.

In rust, `enums` are `variant` types.
In protobuf, `OneOf` types are `variants`.
In type theory is this is sometimes called a sum type.

A variant type has a name, and each possibility for the variant also has a name.

A variant value has a `discriminant` which is an integer indicating which of the possibilities
is present. Often there is a function `.which()` which obtains this number.

For a variant, we specify that `append_to_transcript` shall be implemented as:

```
    fn append_to_transcript(&self, context: &[u8], transcript: &mut Transcript) {
        match self {
            ...
            Self::%variant_possibility_name(val) => {
                transcript.append_bytes(context, "var");
                transcript.append_bytes("name", "%variant_name");
                (self.which() as u64).append_to_transcript("which", transcript);
                val.append_to_transcript("%variant_possibility_name", transcript);
            },
            ...
        }
    }
```

In rust, an `enum` may have no associated data. (In documentation they call this a unit variant).
In this case, `val.append_to_transcript("%variant_possibility_name", transcript)` should simplify to
```
transcript.append_bytes("%variant_possbility_name", "");
```

In rust, a definition of an `enum` may implicitly declare anonymous structs and tuples associated
to an enumerator. In this case, we follow the rules for an aggregate when appending
the anonymous struct to the transcript, and use the empty string for its name.

In rust, an enum where every variant has no associated data can be tagged with e.g. `repr(u32)`
and interpreted directly as a `u32`, as in C enums. An implementor may reasonably decide
to implement `digestible` for such an enum by converting to a `u32` and then appending that
as a primitive. In this case `derive(Digestible)` should not be used, and this choice should be documented
to allow cross-language implementations to do the same.

Examples:
...



Schema Evolution:
=================

One of the main goals of this scheme is to support *schema evolution*, which means
that just as with protobuf, we can add fields to our structures without breaking
compatibillity. In this case, this means *ledger-compatibility* -- we would like to
be able to add new fields to e.g. the `TxOut` structure or the `BlockContents` structure
without changing the hashes of transactions or old blocks that don't have the new fields.

The main ideas that we have to support this are:

- Rust `core::option::Option` type is treated specially -- it *does not* get mapped
to a `var` AST node, as rust enums with `derive(Digestible)` do. Instead, when
an `Option` is visited, we append nothing if the value is `None`, and simply append the
value when the option is `Some`. So it is "transparent" from the point of view of the
digestible AST.

- The `agg` AST node *does not* include the number of fields as part of the digest.
  Instead, as many fields as needed are appended, and then there is a `closer` that
  is appended to the transcript.

Together this means that:
- New `Option` fields may be added to existing structures without breaking ledger compatibility.
- Old fields that were not `Option` may be made optional without breaking ledger compatibility.

Similarly, `Vec` is treated specially -- when `Vec` is a member of a struct and is empty, we treat
it the same as we would an empty `Option`, and append nothing. This is analogous to how new
`repeated` elements may be added to protobufs without breaking compatibility.

Note that struct fields may not be re-ordered or renamed.

As a compatibility tool, we allow a proc-macro attribute to change the name of a struct or enum,
for purpose of hashing.

For example, this might look like

```
#[derive(Digestible)]
#[digestible(name = "LedgerType")]
pub struct LegacyLedgerType {
    field1: Foo,
    field2: Option<Bar>,
}
```

This would cause the digestible proc-macro to use `LedgerType` as the name of the structure
for purposes of appending it to the transcript.

Additionally, rust enum's are another point of extensibility.
New enum possibilities may be added to an existing rust enum without breaking the hashes
for the other possibilities. Note that enum names cannot be changed and old enums cannot be
removed. The index of the enum possibility within the list does become part of the hash.

References
----------

FIXME: Find and mention the bitcoin and cryptonote and merkle tree examples re: framing and domain separation

TODO
