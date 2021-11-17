# Configuring your Node to Connect with Trusted Peers

One of the largest responsibilities of a consensus node operator in the MobileCoin network is selecting your peers and defining your quorum set according to which institutions and individuals you trust. The validity and efficacy of the consensus algorithm depend on the trust relationships encapsulated in the networking and peer relationships of the consensus nodes.

### Network Configuration Overview

The consensus and broadcast networking configuration is encapsulated in the network.toml file for your node, passed via --network to the consensus service. An example toml file for a 3-node network is below:

```
broadcast_peers = [
  "mcp://peer1.test.mobilecoin.com:443/?consensus-msg-key=MCowBQYDK2VwAyEA-21ShHmvuuynH7Ec
  IgkdH2dWxCojgnWYbHxLrRseQ1s=",
  "mcp://peer2.test.mobilecoin.com:443/?consensus-msg-key=MCowBQYDK2VwAyEA0MaP19zCG3C87t98
  UOemqip3R9hmmaPmcSFAaehPQzQ=",
  "mcp://peer3.test.mobilecoin.com:443/?consensus-msg-key=MCowBQYDK2VwAyEAk-iUVhhmmXn23VCJ
  P0xqqtJabA9oQaJwdrHwHnfeJco=",
]
quorum_set = { threshold = 2, members = [
  { type = "Node", args = "peer1.test.mobilecoin.com:443" },
  { type = "Node", args = "peer2.test.mobilecoin.com:443" },
  { type = "Node", args = "peer3.test.mobilecoin.com:443" },
] }
tx_source_urls = [
  "https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node1.test.mobilecoin.com/",
  "https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node2.test.mobilecoin.com/",
  "https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node3.test.mobilecoin.com/",
]
```
