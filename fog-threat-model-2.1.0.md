# MobileCoin Fog Threat Model

MobileCoin Fog is a suite of services that enable use of MobileCoin payments in resource-constrained
environments, particularly, mobile devices. This threat model explains the security invariants of the system
for the following audiences:

* Users of MobileCoin Fog
* Developers integrating the MobileCoin SDK into their wallet software
* Parties interested in running a MobileCoin Fog deployment
* Security researchers and auditors curious about the system, or actively attempting to break the system

We employ the "user-first" approach of [Invariant-Centric Threat Modeling](https://github.com/defuse/ictm) in this document.

Below, we describe the hypothetical adversaries of the system, followed by the security invariants provided by the
system in the face of each adversary. We also identify specific non-goals in order to express the bounds of what the
system specifically cannot do.

# Terms

For the reader's ease, we have chosen simpler terms for some of the elements of MobileCoin. In particular,
in the literature, a transaction produces "transaction outputs," in this document, the term
"payment record" is used instead.  For example, when a transaction is submitted
successfully, (encrypted) "payment records" are added to the blockchain, and these
payment records are returned to the appropriate users privately via Fog.

When discussing information an adversary *may* possess, we use the following terms when discussing
the adversary's level of uncertainty about the information:

* *no information*: An adversary has *no information* about something. For example in the case of who
sent a transaction, if an adversary has total uncertainty about the recipient, it then is equally likely
given all their information for the recipient to have been any of the users.

* *some information*: An adversary has *some information* about who sent a transaction; they have less
than total uncertainty about this. For example, take the claim, "It must have been one of the people who
submitted a transaction to one of several blocks." The number of people on a list like this is typically
less than the total number of users. In this document, we only use the term *some information* when an
adversary has *at most* "block-level granularity" about a piece of data.

# Adversaries

### Baseline Adversary (Oscar)

The "baseline" adversary doesn't have access to Fog, to consensus service machines,
or to users' phones, but can still monitor (but not tamper with) IP-level traffic between all services and
users, and knows the IP address of every user.

### Infrastructure-surveilling Adversary (Eve)

Eve has the capabilities of Oscar, and additionally:

* Can monitor all Fog service machines and one MobileCoin consensus service machine participating in quorum, observing all working memory of these machines as they operate.
* Cannot compromise the confidentiality or integrity of SGX enclaves, nor that of RDRAND, nor the SGX remote attestation process.
* Can monitor the memory access patterns of any running enclave in the system, even if they cannot read the memory.
* Does not have access to the user's phone and cannot run malicious code there.

### Infrastructure-compromising Adversary (Mallory)

Mallory has the capabilities of Eve, and additionally:

* Has root access on Fog service machines and one MobileCoin consensus service machine participating in quorum,
  and can observe and tamper with all working memory and operations of these machines.

### SGX-compromising Adversary with root on Fog Infrastructure (Darth)

Darth has the capabilities of Mallory, and additionally:

* Can compromise either SGX itself, or the SGX remote attestation process.

### SGX-compromising Adversary without root on Fog Infrastructure (Trudy)

Trudy has the capabilities of Oscar, and additionally:

* Has the capability to compromise SGX, but does not have root access on any infrastructure machines.

# Security Invariants

### Baseline Adversary (Oscar)

Oscar cannot:

* Cause arbitrary code to run on the user's device.
* Learn any of the users' private keys.
* Learn any of the users' public addresses.
* Steal the user's funds.
* Make the user send funds without permission.
* Make the user send funds to someone other than who they intended.
* Cause the user's funds to become unavailable for use.
* Cause funds sent to a recipient to disappear from the sender's wallet but be unavailable for use by the recipient.
* Cause a user to associate the wrong public address with another user.
* Learn the amount of any user's transaction.
* Learn any user's balance.

Oscar can:

* See when a user submits a transaction to the consensus node.
* See when the submission is successful or unsuccessful.
* See in which block a particular successful transaction landed, and all of the payment records in that block.
* See when a user checks their balance, and the bandwidth and number of requests during a particular balance check operation.

Thus, Oscar has *some information* about the identity of the sender of any particular payment record.

Fog provides the following invariants protecting the recipient of a payment record from Oscar:

* When a user performs a balance check and retrieves zero or one payment records from Fog, the adversary has *no information* about which of these is the case.
* When a user performs a balance check retrieving more than one payment record, the adversary cannot determine the number of payment records to within a factor of two.
  * For example, if you received 6 payments, it is equally likely from the adversary's point of view that you received 5, 6, 7, or 8 payments, given the data they can see.
  * In particular, if a user reinstalls their wallet and downloads all their historical transactions via Fog, this adversary learns the number of total payment records to within a factor of two.

These are consequences of the design goals of MobileCoin Fog. Fog is designed to support *low-bandwidth*
users on a mobile device; it is designed so that users only download their own transactions, and not the entire
blockchain. This means that an adversary capable of traffic analysis can see when a user downloads many payment
records as opposed to a few. Fog is designed to make it difficult to distinguish when you download zero or one
payment records; even when you download many payment records, it's hard to determine the exact
number of up to a factor of two. However, this adversary does get *some information*.

A user that needs stronger privacy guarantees should consider running a desktop wallet, with
the caveat that one must sync the entire blockchain in order to check one's balance.

If a baseline adversary has *some information* about which blocks your payment records came from, then they have
*some information* about the sender, because they have *some information* about who submitted the transaction that
created any particular payment record.

### Infrastructure-surveilling Adversary (Eve)

Eve:

* Eve can see which IP created which payment record. (Oscar only has *some information* about this.)
  (This is the current threat model for MoblieCoin consensus server.)

* Otherwise, Eve obeys the SAME set of invariants as described for Oscar, with the following modifications:
  * Eve can observe the ring elements used to construct a user's outgoing transaction at the time of construction.

(Note: In a future release, we plan to improve the system so that these modifications are not necessary, and Eve
has no additional information beyond the baseline adversary.)

### Infrastructure-compromising Adversary (Mallory)

Mallory cannot:

* Cause arbitrary code to run on the user's device.
* Learn any of the user's private keys.
* Learn any of the user's public addresses.
* Steal the user's funds.
* Make the user send funds without permission.
* Make the user send funds to someone other than who they intended.
* Cause the user's funds to become unavailable for use.
  * Though the user may need to use a desktop wallet to find their funds.
* Cause a user to associate the wrong public address with another user.
* Learn the amount of any transaction.
* Learn any user's balance.
* Steal private keys from any of the enclaves.
* Exercise the fog-ingest, fog-ledger, or fog-view enclaves in any way that reveals additional non-trivial information
  about the amount or recipient of a transaction.
* Infer *anything* about the sender or recipient of a payment, that Eve cannot also infer.

Mallory can:

* Do anything Eve could.
* Cause the Fog service to become unavailable.
* Destroy encrypted payment records in Fog database, making it impossible for a user to successfully perform a balance check via Fog.
* Create fake encrypted payment records, which are not part of the blockchain, which users will download and treat as real, but which can't be used to make successful transactions.
* Cause users to display incorrect balances.
* Cause users to build invalid transactions.
  * Mallory cannot cause the users to submit transactions, but if they submit transactions, they may be invalid if they were built with invalid data.
* Tamper with the Fog reports, causing users not to receive their payment records via Fog.
  * If the sender encrypts for the wrong Fog ingress key, fog-ingest will not pick up the payment record.
  * The recipient would have to slow-scan the ledger instead to find the payment record.
* Cause the users to download large amounts of uninteresting data on their phone.

### SGX-compromising Adversary with root on Fog Infrastructure (Darth)

Darth cannot:

* Cause arbitrary code to run on the user's device.
* Learn any of the user's private keys.
* Steal the user's funds.
* Make the user send funds when they didn't want to.
* Make the user send funds to someone other than who they intended.
* Cause the user's funds to become unavailable for use.
* Cause a user to associate the wrong public address with another user.
* Learn the amount of any user's transaction.
* Learn any user's balance.

Darth can:

* Do anything Mallory could.
* Learn many view-public keys, which appear in the public addresses of Fog users.
* Learn the recipient of any payment record sent to a Fog user:
  * By attacking fog-ingest enclave in one of several ways, or by attacking fog-view enclave.
  * Darth can learn who the sender of a payment record was, just as Mallory can.
* Learn how many and in which blocks a Fog user received payments, if they perform full-wallet recovery
  * By attacking fog-view enclave.

The system has a forward-secrecy property:

* If SGX is patched and Fog enclaves are rebuilt and redeployed, Darth-level adversaries no longer have any additional information,
  and are degraded to the Mallory-level for transactions and interactions that occur after that point. This does not require
  the users to change their private keys, but may require them to update their app in order to trust the new enclave.

### SGX-compromising Adversary without root on Fog infrastructure (Trudy)

Trudy has the same set of invariants as Oscar, even if they have the ability
to conduct DNS-poisoning attacks and cause the user to talk to a malicious Fog report server.

These invariants carry over because of the design of the Fog authority signature chain, which leads
all the way back to the users' public addresses.

If Trudy signs their Fog reports with a different authority key, then the user will fail
to obtain valid Fog reports and be unable to submit transactions, rather than disclose the recipient
of those transactions to the adversary.
