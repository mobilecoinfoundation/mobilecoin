mc-crypto-digestible-test-utils
==========

`mc-crypto-digest-test-utils` includes two implementations of `DigestTranscript`
that can be used to verify that `digestible-derive` is generating the right code.

`MockMerlin` can be used to capture the sequence of `append_bytes` calls when
a given object is appended to the transcript.

There is also a higher-level debugging tool.
The interaction of an object with the `DigestTranscript` protocol naturally produces
an AST, which is normally only implicit, but can be made explicit using the `InspectAST`
visitor.

The `calculate_digestible_ast` function can be used to take a digestible object
and compute this AST.
This AST is represented using the `ASTNode` type defined in this crate. This function
visits the object using the `InspectAST` visitor. It also checks that a digest
computed using the `MerlinTranscript` directly with the object
corresponds with the digest computed from Merlin running over the AST.

The `ASTNode` can be pretty-printed use its `core::fmt::Display` implementation,
the debug implementation is also not too terrible.
