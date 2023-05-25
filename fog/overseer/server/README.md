# Fog Overseer

The Fog Overseer service monitors the Fog Ingest cluster's nodes and ensures that there is always one active node in the cluster.

## Historical Context

Fog ingest nodes are organized into clusters, which enables high availability of the fog ingress private key, which is needed to decrypt Fog hints in incoming TxOuts. In a given cluster, only one node is active and performs work, and the others are idle backups that store this private key in SGX. The active node continually checks up on its peers and broadcasts the private key.

If the active node fails, then any one of the idle nodes can be activated via a grpc call.
(Generally there is only one cluster, but for purposes of upgrades, we use a blue-green deployment strategy. This is necessary because if there is an ingest enclave upgrade, the new enclaves cannot have the old private key, because the old enclaves cannot trust them. So sometimes there are two clusters, and an active node in each cluster, with the backups in each cluster ensuring availability of the two different keys that are both active during the rollover. The blue-green deployment strategy ensures that any key that is actively needed does not have any of its backups removed until it is no longer needed.)

Prior to Fog Overseer, MobileCoin DevOps engineers were required to perform manual steps to implement this failover procedure. To summarize, they have to get the “active key” and see if any of the idle nodes have that key. If one does, then they activate that idle node, and if one doesn’t then they have to report missed blocks, retire the ingress key, and then activate any of the idle nodes with a new ingress key.

This manual failover process is cumbersome for a few reasons. First, there might be some lag between when an active node fails and when we discover the failure and perform the manual failover. Second, the manual steps require a variety of CLI commands and analysis, which is never ideal when dealing with outages (the pressure's on, etc.). Finally, it just creates toil around a process that could be automated, which has a human cost. Another issue is that sometimes, ingest nodes in dev networks like alpha or mobiledev get bounced, and this causes tests to fail for SDK developers since there is no automation that reactivates the node. (See e.g. Bernie’s recent comments in #ops.) For less important networks like the dev networks we don’t have the resources to have a human intervene.

Moreover, this manual failover process highlights that we currently don’t have a good way to see simple metrics: the number of ingress keys, number of "outstanding" ingress keys, number of egress keys, and number of "outstanding" egress keys. Instead, we have to run CLI commands and these metrics aren’t persisted anywhere.

## Design

Fog Overseer is designed to automate this manual failover process.

It starts by querying all the Fog Ingest nodes to see if one node is active. If there exists one active node, then no further action is needed. If more than one node is active, then Overseer logs an error and doesn't take any action. If no nodes are active, then it initiates automatic failover.

This failover begins with retrieving all of the keys in the Fog DB that are “outstanding”, which means that they are not lost or finished retiring. If there are multiple outstanding keys, it disables overseer, logs an error, and sends an alert to human operators to fix the issue. If there is one outstanding key, then it tries to find an idle node with that key. If it finds such node, then it activates it. If no nodes are found for the key, it marks the key as lost, chooses an idle node, sets new keys on that node, and activates the node.

Note that this design does not support multiple Fog Overseers to run concurrently. See the Future Work > Multiple Fog Overseers section for more info.

## API

`POST /disable`: Stops Fog Overseer from performing it's monitoring. This is necessary during a blue-green deployment or certain failure scenarios in which we don't want Overseer to make any changes to cluster state. If Overseer is disabled, this is a no-op.
`POST /enable`: If Overseer is disabled, this restarts Overseer's monitoring. If Overseer is enabled, this is a no-op.

## Future Projects

## Metrics and Alerting
The service will publish the following metrics to prometheus:
- Number of ingress keys
- Number of egress keys
- Number of active nodes
- Number of idle nodes.

When certain critical failures occur, the service will log errors that get sent to Sentry, which will in turn use PagerDuty to alert team members of the specific failure.

### `GET /ingest_cluster_data`
We want to expose a `GET /ingest_cluster_data` API that provides basic metrics regarding the Fog Ingest
Cluster Data. It would return a response like this:

```
 “nodes”: [
    {
      “responder_id”: …,
      “mode”: “ACTIVE|IDLE”,
      “next_block_index”: …,
      “pubkey_expiry_window”: …,
      “ingress_pubkey” : …,
      “egress_pubkey”: …,
      “kex_rng_version” : …,
      “peers” : …,
      “ingest_invocation_id” : …
    },
    ...
  ]
}
```

### Multiple Fog Overseers
We’d like to support multiple Fog Overseer nodes running concurrently. Currently, Fog Overseer only operates on one Fog Ingest cluster. If we had two Fog Overseer Instances A and B and Fog Overseer instance A calls NewKeys on Fog Ingest instance A, and then Fog Overseer instance B calls Activate on Fog Ingest instance A in parallel, then there would be a race.

To prevent this, we can implement a mutex in Fog Ingest that prevents Activate and NewKeys from executing in parallel.
