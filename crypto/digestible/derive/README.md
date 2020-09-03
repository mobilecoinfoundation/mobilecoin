mc-crypto-digestible-derive
=================

This proc macro crate allows the use of `derive(Digestible)` in user structs and enums.

The intended code-gen for a struct is:

```
#[derive(Digestible)]
struct Foo {
    a: A,
    b: B,
    c: C
}
```

expands to something like:

```
impl Digestible for Foo {
    fn append_to_transcript<DT: DigestTranscript>(&self, context: &'static [u8], transcript: &mut DT) {
        transcript.append_agg_header(context, "Foo".as_bytes());
        self.a.append_to_transcript_allow_omit("a".as_bytes(), transcript);
        self.b.append_to_transcript_allow_omit("b".as_bytes(), transcript);
        self.c.append_to_transcript_allow_omit("c".as_bytes(), transcript);
        transcript.append_agg_closer(context, "Foo".as_bytes());
    }
}
```

The intended code-gen for an enum is:

```
#[derive(Digestible)]
struct Foo {
    a: A,
    b: B,
    c: C
}
```

expands to something like:

```
impl Digestible for Foo {
    fn append_to_transcript<DT: DigestTranscript>(&self, context: &'static [u8], transcript: &mut DT) {
        transcript.append_agg_header(context, "Foo".as_bytes());
        self.a.append_to_transcript_allow_omit("a".as_bytes(), transcript);
        self.b.append_to_transcript_allow_omit("b".as_bytes(), transcript);
        self.c.append_to_transcript_allow_omit("c".as_bytes(), transcript);
        transcript.append_agg_closer(context, "Foo".as_bytes());
    }
}
```


Configuration
-------------

`derive(Digestible)` can be configured by adding an attribute to the struct or enum,
of the form `#[digestible(...)]`

`#[digestible(transparent)]` can be used with any struct that contains exactly one member.
As `#[repr(transparent)]` in rust, this enables the use of newtype wrappers without impacting
the way that the value is treated by `digestible`.

```
#[derive(Digestible)]
#[digestible(transparent)]
struct Foo(A)
```

expands to something like:

```
impl Digestible for Foo {
    fn append_to_transcript<DT: DigestTranscript>(&self, context: &'static [u8], transcript: &mut DT) {
        self.0.append_to_transcript(context, transcript);
    }
    fn append_to_transcript_allow_omit<DT: DigestTranscript>(&self, context: &'static [u8], transcript: &mut DT) {
        self.0.append_to_transcript_allow_omit(context, transcript);
    }
}
```

`#[digestible(name = "new_name")]` can be used to make the type identifier used for hashing different
from the actual rust identifier for the struct. This may be useful if we need to have two "versions" of
a struct that hash in the same way.

```
#[derive(Digestible)]
#[digestible(name = "Foo")]
struct FooV2 {
    a: A,
    b: B,
    c: C
}
```

expands to the same codegen as we had for `struct Foo` earlier.

Future improvements
-------------------

Patches that would welcome include:
- Allow to rename individual fields in a struct, using `#[digestible(...)]` attribute
- Allow to unconditionally skip individual fields in a struct from the digest.
  This may be useful if e.g. you want to add a time-stamp to some record but you don't
  want it to become a part of the hash.

Implementation notes
--------------------

For comparison, the `derive(Hash)` stuff is implemented in `libsyntax_ext` in `rust/rust`,
however, that is implemented directly in the compiler and not in a proc_macro or even in libcore,
so we can't use the same code. Instead, the `derive(Digestible)` proc-macro code is based most directly on the `prost-derive` crate.
