# Verify Nodes are Participating in Consensus

After the transaction has been sent, you can check logs for the Consensus Validators. A node that is participating in consensus will have messages regarding Ballots and phases such as Nominate and Prepare, for example:\


```
Nominate Round(2) with leaders:
{NodeID(peer4.test.mobilecoin.com:443:f2b4f1b561f09b063a7d2686e4a95d75ec4d3
a626151dc8f52cb04a7e5fdafa5),
NodeID(binance-0.man.bdi.sh:8443:477e1209d01e430f20c95bf53cfa1e80f0940ffc6a
9c03ddb606682aaa8041c5)}
```

If node is in catch-up, you will see messages such as:

```
sync_service reported we are behind, we're at slot 43704 and network state is
{NodeID(peer2.test.mobilecoin.com:443:d0c68fd7dcc21b70bceedf7c50e7a6aa2a774
7d86699a3e671214069e84f4334): 43706,
NodeID(peer3.test.mobilecoin.com:443:93e8945618669979f6dd50893f4c6aaad25a6c
0f6841a27076b1f01e77de25ca): 43703,
NodeID(peer1.test.mobilecoin.com:443:fb6d528479afbaeca71fb11c22091d1f6756c4
2a238275986c7c4bad1b1e435b): 43706,
NodeID(peer4.test.mobilecoin.com:443:f2b4f1b561f09b063a7d2686e4a95d75ec4d3a
626151dc8f52cb04a7e5fdafa5): 43703,
NodeID(peer5.test.mobilecoin.com:443:ee07bfb8852db7752cf53ff19c44604b2f646f
537175b0e1c4bb083cdf85037d): 43706}
```

