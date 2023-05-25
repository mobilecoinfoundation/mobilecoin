ledger_enclave_server
=============

The ledger enclave server node serves queries against the mobilecoin ledger.
These are queries that the client could answer by downloading the ledger
themselves. The ledger enclave server answers these queries in a private way,
such that the node operator doesn't learn about the user's transactions.

This requires that clients attest to an SGX enclave, then encrypt all requests
directly to the enclave.  The responses will be encrypted back to the client.
In the current version of the code the enclave will rely on untrusted code to
do the actual ledger queries, so it is not truly private.  But it will allow us
to implement our Android SDK against the APIs that the final code will use.

Once we have a working ORAM implementation, untrusted code will only be used
to read and write ORAM paths and stash.  This will completely hide the data
accessed, both directly and also in terms of access patterns.  The data inside
the ORAM will use authenticated encryption to prevent untrusted code from altering
the data undetected, so the enclave and the client will know if any nefarious
activity is taking place.

The API includes:
- Attesting to the enclave
- Getting TXO "mixins" for rings,
- Checking if a given Key Image has been spent,
- Getting a proof-of-membership for a TXO