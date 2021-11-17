# Unacceptable Degradation of Service

In the event of an unacceptable degradation of service, which cannot be practically mitigated outside of the enclave, the enclave upgrade should be rolled back. The exact rollback procedure may vary depending on the scope of the upgrade and its procedures.

To rollback an enclave upgrade:

**Step 1: **If outside the maintenance window, declare emergency and select an incident commander, and convene the Operators Group.

* Agree that a rollback is necessary.

**Step 2: **Configure all inbound client handlers to reject new connections.

* Confirm no new transactions are being received/processed by the network.
* Confirm that all nodes are at the same block height.

**Step 3: **Stop all nodes.

* Snapshot all node's local databases.
* Apply any reverse-DB migration scripts.

**Step 4: **Restart all nodes with the old enclave.

* Confirm that all nodes are attesting to each other.
* Perform transaction tests.
* Configure inbound client handlers to accept new connections.

**Step 5: **Maintain the call/maintenance window for a predefined "live" period to ensure stability.
