mc-transaction-extra
====================

This crate is meant to sit one level above `mc-transaction-core`, containing:

* Types and schema defining concepts related to transactions / transaction math,
  and which might appear in external.proto or be specified in MCIPs
* Are *NOT* directly related to the structure of a valid transaction or to
  MobileCoin transaction validation performed by the consensus enclave.

The consensus enclave does not directly depend on this crate, and so it is
easier see that changing something in this crate does not break enclave compatibility.

Examples of things that might appear in this crate:

* Memo types. (E.g. MCIP 4, MCIP 32, MCIP 39)
* `TxOutConfirmationNumber`. This is a hash derived from the `TxOut` shared secret,
  but it is only exchanged from client to client and isn't used by the consensus validators.
* `SignedContingentInput`. These use pieces of transaction-core but are not themselves
  validated by the consensus network. Rather, they are elements of a secondary protocol.
  (MCIP 31, MCIP 42)
  * `InputRules` on the other hand, are a core type and are part of validation.
* `TxSummaryUnblindingData` (MCIP 52) is not a core protocol type, it's a data type
  which a computer might send to a hardware wallet.
  * `TxSummary` (MCIP 52) is a core protocol type and is part of the digest that is
    signed by a valid `Tx`.
* `UnsignedTx`. This is partially-assembled `Tx` that can be passed to a custom
  signing implementation, for example if someone is doing a multi-party signature scheme.

It is hoped that during PR review for a new feature, seeing which files are in core vs.
extra will help the reviewer more quickly see which pieces of code are becoming part of
the enclave API / part of transaction validation, and which are not.
