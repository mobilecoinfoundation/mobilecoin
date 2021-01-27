# MobileCoin Fog Signatures

This crate provides implementations of the signing and verification scheme used to delegate transaction monitoring to an oblivious fog operator. The steps of operation are for the fog signature scheme is:

 1. Pre: Fog operator creates a CA chain terminating in an Ed25519 leaf certificate.
 1. Pre: Recipient signs the fog operator's CA pubkey in order to delegate authority to any ingest server signed by the operator.

 1. Fog operator (via report server) signs a list of ingest IAS enclave reports using the leaf private key (each ingest report contains a RistrettoPublic key which senders should encrypt fog hints for).
 1. Sender queries the report server for the latest signed report list.
 1. Sender verifies the signature chain and report contents.
 1. Sender encrypts the fog hint for the correct ingest server (as specified in the user's address).

 1. Ingest server decrypts the hint, indexes and re-encrypts the transaction for the recipient.

Toward this end, this crate provides the APIs related to creating and verifying the signatures in that chain, specifically for the times when:

 1. A transaction receiver wants to sign fog operator's certificate authority using their spend key.
 1. A fog operator wants to sign a series of ingest server reports, using the report server.
 1. A transaction sender wants to verify the chain of trust from the user's public spend key to the signature over the ingest server reports.
