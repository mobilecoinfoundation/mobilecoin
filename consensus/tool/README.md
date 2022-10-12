mc-consensus-tool
=================

This is a command-line utility which can be used to interrogate a consensus node.

* `status` prints the currently reported of the network status of one node
* `wait-for-quiet` polls a node or nodes until the reported block height is steady for a while

The `wait-for-quiet` option is intended to be used in integration tests which have
historically used "sleeps" to wait until previous commands have finished and their
transactions have settled, before attempting to perform more transactions. This
may be a more reliable approach in resource-starved test environments.

This tool can be used to quickly figure out the reported block version or other
such parameters of a node that are visible via its grpc API.
