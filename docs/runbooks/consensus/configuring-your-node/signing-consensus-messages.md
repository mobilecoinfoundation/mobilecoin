# Signing Consensus Messages

Each consensus validator node signs the consensus messages that it emits, using the Ed25519 `msg-signer-key` parameter passed to consensus.

To obtain this key, use the following code:

`openssl genpkey -algorithm ed25519 -out msg-signer.key`

The base64 string in the pem file may be copied directly into the msg-signer-key parameter value, for example:

`--msg-signer-key MC4CAQAwBQYDK2VwBCIEIJVq95XBwx7XpKnDElrxlL/dwNer0EqKc2igPojJSxHV`

Next, provide the corresponding public key to peers, who want you included in their broadcast\_peers specification in the network.toml. This public key must be URL-safe base64 encoded. You can perform this transformation with the following code:

`openssl pkey -in msg-signer-key.pem -pubout | sed 's/+/-/g; s/\//_/g'`

Finally, publish the following broadcast\_peer public URI:

`mcp://my_node.com:443/?consensus-msg-key=MCowBQYDK2VwAyEAJ4PLBX2wiSBk8OHS-Qe3EfnpuNiHpH_BpN1wJG2tE2U=`

{% hint style="info" %}
The msg-signer-key is private and should be safeguarded with best practices because anyone with this key could impersonate you and send consensus messages as though they were emitted from your node.
{% endhint %}

