transaction_signer
==================

NOTE: At this revision this is a module within transaction core.
In a future revision, we should split this, and the ring signature implementation,
out of core, into its own crate.

An interface and implementation for creating RingMLSAGs.

A RingMLSAG is a ring signature scheme used critically in the MobileCoin transaction
design. In a transaction, each real input is spent by a RingMLSAG -- this is the
signature that confers spending authority.

This crate contains a generic interface for creating these MLSAGs as desired.
This is intended to be useful for hardware wallets.
