# Configuring your Node

### Accepting Connections from Trusted and Untrusted Peers

Your node will listen for messages from both trusted and untrusted peers. You must configure your node to listen via the `--peer-listen-uri `parameter to the consensus service.

An example `peer-listen-uri` is the following:

`mcp://0.0.0.0:8443/?tls-chain=/certs/your-tls.crt&tls-key=/certs/your-tls.key`

The components of the URI and their functions are:

| URI Component             | Value                                   | Function                                                                                                                                                                                                                                                                                                                                  |
| ------------------------- | --------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Scheme                    | `mcp` or `mcp-insecure`                 | <p><br>Determines whether to use tls in the connection to the peer. Most often, these will be <code>mcp</code>.</p><p><strong></strong></p><p>If you configure to terminate TLS in the consensus service by using the mcp scheme, you will also need to provide the <code>tls-chain</code> and <code>tls-key</code> query parameters.</p> |
| Address and Port          | Address of node and peer listening port | Address and listening port of the consensus peer.                                                                                                                                                                                                                                                                                         |
| tls-chain query parameter | Path to local certificate chain         | Used to terminate TLS in the consensus-service.                                                                                                                                                                                                                                                                                           |
| tls-key query parameter   | Path to local certificate keyfile       | Used to terminate TLS in the consensus-service.                                                                                                                                                                                                                                                                                           |
