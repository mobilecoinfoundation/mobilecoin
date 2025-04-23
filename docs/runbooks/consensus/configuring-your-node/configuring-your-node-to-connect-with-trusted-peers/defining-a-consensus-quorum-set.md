# Defining a Consensus Quorum Set

The `quorum_set` section of the network.toml defines which nodes you trust. The quorum set is used to determine whether a sufficient set of nodes in the network agree on a value for you to also cast a vote in agreement. This is the process of solving the Byzantine Agreement Problem.

The `quorum_set` is a recursive structure which includes the following for each set:

| Quorum Set Component | Value                                                                 | Function                                                                                                                              |
| -------------------- | --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| Threshold            | Integer                                                               | Defines the number of members of the set which must cast a vote for your node to be convinced and also vote in agreement.             |
| Members              | A list of peers or sets.                                              | A member of a quorum set can be a peer or another quorum set.                                                                         |
| Member Type          | Node or InnerSet                                                      | Defines which type of quorum set member.                                                                                              |
| Member Args          | Args to construct either a Node or InnerSet member of the quorum set. | <p>If Node, then the arg is the address and port of the node. </p><p></p><p>If InnerSet, then the args are threshold and members.</p> |

### Example Quorum Sets

Two-of-three simple majority:

```
quorum_set = { threshold = 2, members = [
  { type = "Node", args = "peer1.test.mobilecoin.com:443" },
  { type = "Node", args = "peer2.test.mobilecoin.com:443" },
  { type = "Node", args = "peer3.test.mobilecoin.com:443" },
] }
```

Two-of-three, where one member is an InnerSet quorum set:

```
quorum_set = { threshold = 2, members = [
  { type = "Node", args = "peer1.test.mobilecoin.com:443" },
  { type = "Node", args = "peer2.test.mobilecoin.com:443" },
  { type = "InnerSet", args = { 
      threshold: 2,
      members = [
         { type = "Node", args = "peer3.test.mobilecoin.com:443" },
         { type = "Node", args = "peer4.test.mobilecoin.com:443" },
         { type = "Node", args = "peer5.test.mobilecoin.com:443" },
     ]}
   }
] }
```
