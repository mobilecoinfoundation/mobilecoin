mc-crypto-digestible
==========

NOTE: This crate is WIP, use at your own risk!

`mc-crypto-digestible` and its companion crate `mc-crypto-digestible-derive`,
represent a scheme for secure (nonmalleable) hashing of common rust objects using
a collision-resistant hash function. This represents critical infrastructure for
blockchain projects, because if e.g. an attacker can find two different blocks with
the same hash, they can subvert the integrity of the blockchain.

The `Digestible` trait is provided, which allows that the contents of the entire
object can be hashed together in a non-malleable way, after an implementation of
`Digest` trait is provided.

The scheme implicitly defines an "encoding" whereby your object is turned into a
byte sequence which is fed into the hasher.

This has a few benefits:
- The encoding is stable and canonical, not depending on implementation details of
  a serialization library, which typically do not provide byte-for-byte stability
  guarantees.
- Bringing the bytes directly to the hasher as they are produced is faster than
  marshalling them to a temporary buffer and then hashing the buffer.
- Digestible trait is not rooted in serde -- since many types implement serde traits
  without concern for cryptographic issues, basing digestible trait on serde risks
  creating problems. Secure hashing really is a different issue from serialization,
  close though they may seem.

Typically, serialization libraries offer a stable wire format, and then
progressively try to improve the efficiency of serialization and deserialization
over time, without breaking the wire format. This generally means that the byte
representation is not canonical, which makes this a bad way to hash objects.

Overview
--------

To achieve its goals, `mc-crypto-digestible` must specify an encoding for any type which
you derive `Digestible` on.

Ultimately, the engineering requirement is to show that the encoding function,
as it acts on objects of any particular type, is a "faithful" encoding -- that is,
no two objects correspond to the same bytes. If this is true, then under the assumption
that your `Digest` algo is second pre-image resistant, it is also hard to find two
instances of any structure with the same hash.

Our strategy is to work "inductively" over the structure of your types.

- We take as our correctness property called "prefix-free". Prefix-free is stronger
  than saying that an encoding is one-to-one / faithful, so if we have this for
  all types that we implement Digestible for, then we have achieved our goal.
  For a good overview of prefix codes, see wikipedia: https://en.wikipedia.org/wiki/Prefix_code
- We implement `Digestible` for primitive types in a way that accomplishes this.
  This is generally easy because most primitive types of interest have fixed length encodings,
  which are trivially prefix-free.
- For "compound" types like structures, enums, sequences, etc. we appeal to one of several
  abstract rules specifying how a prefix-free encoding can be built assuming that the children
  have prefix-free encodings.
  - These rules will be explained in detail in a separate document, but roughly, we think
    of each compound type as either a "product type" or a "sum type" and apply the corresponding
    rule.
  - This actual mapping is done either by generic implementations of `trait Digestible` e.g.
    for slices or `Vec<T>`, or it is done in the proc-macro logic in `mc-crypto-digestible-derive`,
    e.g. for `struct` and `enum`.

Roughly, the five categories that everything gets interpretted as, in this analysis, are:
- Primitives
- Aggregates (structs, tuples, fixed-length arrays)
- Sequences (variable length arrays, strings)
- Variant (including `Option`, `enum`)
- "Custom primitives" (generally means external types with canonical fixed-width representations,
                       e.g. curve25519-dalek curvepoints and scalars.)

(It's possible to extend this to include something like e.g. protobuf map types, but we haven't
implemented it and won't describe it here.)

If one applies this strategy naively and considers the results, it turns out that it corresponds
roughly to a "canonical" version of bincode, and is thus very efficient, adding very little "fluff"
to the encoding. This also makes it very believable that no two objects *of exactly the same type*
have the same encoding unless they are semantically equal, since bincode can actually be
deserialized, which is another way to demonstrate that the encoding is faithful.
https://docs.rs/bincode/1.2.1/bincode/

However, bincode would not normally be considered a suitable encoding for non-malleable hashing.
It's more common to use "self-describing" data-formats based on ASN.1 in cryptographic contexts,
where the serialized data essentially carries a schema that could be used to interpret it. The
purpose of this is to try to ensure that objects that have different schema are guaranteed to have
different hashes, and get the "semantics" of the data into the hash.

This is sometimes called the "Horton Principle": https://en.wikipedia.org/wiki/Horton_Principle

In the DER encoding rules, a strict Type-Length-Value protocol is used when encoding structures.
Types are mapped in some standardized way to a "type code", typically a fixed small number of bytes,
and this becomes part of the ASN.1 module specification. A struct is treated as a "group" and a
specific protocol is used for opening and closing a group, and listing the TLV bytes for its
members consecutively.

Creating type codes on a per-type basis generally has to be done manually, and so creates a maintanence
burden. There is very little tooling in rust (or indeed, most programming language ecosystems) to support
this.

One useful insight is that while DER is required to support deserialization, and so minimizing size-on-the-wire
is of critical interest, in the case when the encoding is only being made in order to hash the structure,
size on the wire is much less important. Modern hash functions are generally much faster on a per-byte
basis than elliptic curve operations. In our context, hashing transactions, hashing blocks, etc. is generally
not a performance bottleneck if done reasonably efficiently -- transaction validation is. So it's not
extremely important here to get an optimal or even near-optimal encoded representation in terms of the rate,
or number of bytes on the wire. It's much more important to get a non-malleable encoding.

In many modern crypto libraries based on the `dalek-cryptography` ecosystem, the merlin library is used to
generate hashes of the cryptographic transcript to use as challenges, when employing the Fiat-Shamir heuristic.
- https://merlin.cool/use/protocol.html
This means roughly that the "contents to be hashed" are visited and mapped to a STROBE `AD` operation:

```
AD[label || LE32(message.len())](message);
```
- https://merlin.cool/transcript/ops.html#appending-messages

Inspecting the actual source code shows that at the STROBE layer, this actually looks roughly like
```
strobe.meta_AD(label);
strobe.meta_AD(LE32(...));
strobe.AD(message);
```

This has some of the characteristics of a type-length-value encoding, in that the "label"
is often playing the role of the data-type descriptor. However, here the label is not escaped using
length encoding, even though it is a user-provided variable-length string, nor is there any standardized list
of labels to be synchronized across applications. So, none of these strategies is really producing a
"distinguished encoding", and it's possible that other protocols with pathologically chosen labels and
pathologically chosen values could happen to have merlin transcript hashes that collide with theirs.

Rather, the idea is that as long as the labels are "descriptive" and hence unlikely to collide by chance
with labels from another application, and all of the bytes in the actual application in question which
are potentially controlled by an adversary are properly framed, this represents "sound domain separation".
As long as the encodings of each actual message object are canonical, the overall protocol hash will be
canonical (and non-malleable), and so it should be hard for an adversary to trick the user's programs
by finding different values that those programs think are the same due to the hashes.

At present revision, `digestible` incorporates this idea in the following way:
- The naive "canonical bincode"-like strategy is extended to incorporate fixed labels.
  It is easy to see that adding fixed string constants as labels does not impact the prefix-free property,
  so this can do no harm.
- Fixed labels are used whenever a `struct` is encoded: The rust name of the structure is the outer label.
  Every struct member is also prefixed with a label corresponding to the member name.
- Digestible always incorporates proper framing: fixed-size objects are generally not framed,
  but anything not known statically to have a fixed size is framed, at any layer of the hierarchy where
  that is the case.

This domain separation scheme is not perfect -- it is not as good as e.g. hashing a DER encoding.
There are several straightforward ways to improve it, at the cost of somewhat increased complexity.
At the same time, it seems not much different from the ideas around domain separation in Bulletproofs and
Schnorrkel, which are critical dependencies of ours. It also seems difficult to imagine a realistic way to
create a collision that would impact the application.

We would like to improve this over time so that a more rigorous statement can be made -- we would like to
provably prevent collisions in the encoding even when the structure types are distinct in an appropriate sense,
and it's not clear that that is provable at this revision. It merely seems likely.

It would also be of interest to integrate with merlin, if only to support the `dalek-cryptography` ecosystem
which is building up around it. Structure hashing is full of pitfalls and yet it is a common need.

`Digestible` is potentially valuable because it provides a principled, systematic approach to the problem, seems comparable
to other practical solutions, and is easy to use especially by non-cryptographers, who can easily modify
structures and make new ones which derive digestible, and don't have to try to
determine appropriate domain separation labels, or figure out when to insert framing, manually.
Nevertheless it is WIP and the present revision is not going to be the ending state of the project.

FIXME: Find and mention the bitcoin and cryptonote and merkle tree examples re: framing and domain separation

References
----------

TODO
