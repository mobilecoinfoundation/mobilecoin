# Upgrading the Enclave

Any introduction of new code into the consensus network first requires the operators to reach consensus among themselves about the code they will be running, as well as the time and manner in which the new code will be introduced. This is a privacy measure the consensus enclave enforces; it rejects connections from any presumptive peer that lacks an identical MRENCLAVE measurement.

{% hint style="warning" %}
If this requirement were relaxed, that is, if the verification were incorrectly configured to only check the MRSIGNER values, such as where the three elements checked included MRSIGNER, product ID, and enclave security version, then key holders could be forced to sign malicious enclaves, which could intentionally leak all inbound user traffic. This malicious enclave could be attached to the consensus network by any existing member.
{% endhint %}

To introduce new enclave code, or also known as a consensus enclave upgrade, all operators should coordinate a “flag day.”

{% hint style="info" %}
It is possible to introduce new code that does not affect the enclave. If the new code does not impact the enclave, a “flag day” is not required**.**
{% endhint %}

The MobileCoin Foundation provides the MobileCoin Operators Group, which consensus node operators should utilize in order to schedule these "flag day" upgrades in response to enclaves issued by the MobileCoin Foundation Technical Committee and signed by the MobileCoin Foundation Key Management Group.

To upgrade a consensus node:

**Step 1: **The Node Operators Group (NOG), who exist under the MobileCoin Foundation, should agree on the new enclave to be deployed, as well as any upgrade-specific procedures and tests to be performed (which should be specified by the NOG in their charter). In addition, the upgrades should first be run on the testnet.

{% hint style="info" %}
An event coordinator is recommended to help with coordinating all of the upgrade functions.
{% endhint %}

**Step 2:** Once a maintenance window/video conference has been scheduled for upgrading the selected nodes, inbound client connection handlers (reverse proxy, load balancer, ingress controller, etc.) need to be configured to reject new connections.

1. Confirm no new transactions are being received/processed by the network.
2. Confirm that all nodes are at the same block height.

**Step 3: **Stop all nodes.

1.  Snapshot all nodes' local databases. The files to be backed up and Copied on Write (that is, copying local files to a backup whenever they are written to), include:

    * Ledger-db (lmdb)
    * Ledger-distribution’s statefile


2. Apply any forward-DB migration scripts.

**Step 4:** Restart all nodes with the new enclave.

1. Confirm that all nodes are attesting to each other.
2. Perform transaction tests (e.g. self-payment, cross-payment, fog, non-fog).
3. Configure inbound client connection handlers to accept connections.

**Step 5: **Maintain the call/maintenance window for a predefined "live" period to ensure stability.

