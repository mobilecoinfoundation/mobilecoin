# Broadcasting to Trusted and Untrusted Peers

The broadcast\_peers define the nodes to which your node will broadcast messages.

MobileCoin uses Universal Resource Identifiers (URIs) to specify peers. These include the address of the peer, the peer's public key, and can optionally include connection information, such as the certificate authority bundle, and tls-hostname.

The URIs indicate the following:

| URI Component                     | Value                                      | Function                                                                                                  |
| --------------------------------- | ------------------------------------------ | --------------------------------------------------------------------------------------------------------- |
| Scheme                            | `mcp` or `mcp-insecure`                    | Determines whether to use tls in the connection to the peer. Most often, these will be mcp.               |
| Address and Port                  | Address of node and peer listening port    | DNS address and listening port of the consensus peer.                                                     |
| consensus-msg-key query parameter | The public message signer key of the peer. | This is verified against every message from that peer to ensure it was signed by the peer you expect**.** |
