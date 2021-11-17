# Running the Node

### Network Ports

The following ports need to be exposed. The actual ports assigned may vary according to your needs, but will need to be communicated for e.g. node and client connection. Presented here are the defaults.

{% hint style="info" %}
You can establish your ingress mapping in whatever manner is convenient to your infrastructure. We present an example of the default MobileCoin ingress configuration.
{% endhint %}



| Purpose                       | Service Port | Ingress Mapping | Dependencies                                                                                    |
| ----------------------------- | ------------ | --------------- | ----------------------------------------------------------------------------------------------- |
| Client transaction submission | 3223         | 443             | Clients must be aware of which port to submit TxPropose messages to.                            |
| Peer-to-peer consensus        | 8443         | 443             | Other nodes in the network who wish to peer with your node must be aware of the consensus port. |
| Admin (logging)               | 8000         | None            | Admin port to obtain information and statistics about the currently running node.               |
| Admin (metrics)               | 9090         | 9090            | Prometheus metrics are provided on the 9090 port.                                               |

### **Description of the MobileCoin Ledger**

In order for any payments network to function, it must be able to maintain a history of transactions. MobileCoin Ledger describes how the MobileCoin Network stores payment records in a public ledger. The ledger is implemented as a blockchain, in which each block contains transactions that include transaction outputs (txos) that might be spent in the future by their owners. Each transaction also includes a proof that all value spent in the transaction has never been spent before. The underlying design is based on the privacy-preserving CryptoNote ledger protocol, which obscures the identity of all txo owners using one-time recipient addresses. The link between sender and recipient is protected through the use of input rings that guard the actually-spent txo in a large set of possibly-spent txos.

The monetary value of each txo is encrypted using the method of Ring Confidential Transactions (RingCT). RingCT is implemented using bulletproofs for improved performance. Only the receiver of the transaction can reveal the encrypted monetary value and spend the new txos that are written to the ledger. The recipient’s cryptographic control over spending ensures that all transactions in MobileCoin are irreversible, similar to cash transactions in the real world.

Each txo in the input ring of a transaction is annotated with a Merkle proof of inclusion in the MobileCoin Ledger blockchain. This allows new transactions to be validated with fewer blockchain read operations, improving efficiency and reducing information leaked to data-access side channels.

Additionally, MobileCoin Ledger dramatically improves on the baseline privacy offered by CryptoNote and RingCT by requiring that the input rings for every transaction are deleted before the new payment is added to the public ledger. Digital signatures are added to the ledger in place of the full transaction records to provide a basis for auditing.
