## MobileCoin Consensus Service

MobileCoin Consensus Service facilitates transactions between MobileCoin users.

Using a modified version of the [Stellar Consensus Protocol](https://www.stellar.org/papers/stellar-consensus-protocol.pdf), nodes running the consensus service agree on the content of the blockchain and publish the results. By using Intel's SGX secure enclaves, transactions remain private.

For more information on how this works, see [MobileCoin Consensus Protocol](#mobilecoin-consensus-protocol).

### Table of Contents

  - [Getting Started](#getting-started)
    - [Requirements and Build](#requirements-and-build)
    - [Setup](#Setup)
    - [Run](#run)
      - [Configuration](#configuration)
  - [MobileCoin Consensus Protocol](#mobilecoin-consensus-protocol)
    - [Byzantine Agreement](#byzantine-agreement)
  - [Crates Overview](#crates-overview)

### Getting Started

#### Requirements and Build

The Consensus Service uses Intel's Software Guard eXtensions (SGX) for integrity and confidentiality. These secure enclaves have strict requirements and must be configured properly in order to peer with other consensus nodes in the MobileCoin network. Please see [BUILD.md](./BUILD.md).

#### Setup

To run consensus, you must develop a quorum set that provides the basis of trust required to solve the Byzantine Agreement Problem. You must also link your identity to your node for both Intel's attestation verification, as well as to sign messages in consensus.

Follow the steps below:

1. Determine who you trust for your quorum.

    By figuring out who to include in your quorum set, you specify peers that you trust.

    MobileCoin uses Universal Resource Identifiers (URIs) to specify peers. These include the address of the peer, the peer's public key, and can optionally include connection information, such as the certificate authority bundle, and tls-hostname.

    An example URI is:

    ```
    mcp://node1.test.mobilecoin.com:8443/?consensus-msg-key=MCowBQYDK2VwAyEA-21ShHmvuuynH7EcIgkdH2dWxCojgnWYbHxLrRseQ1s=
    ```

    The quorum set chosen represents a json dictionary specifying the `threshold` of nodes that you consider necessary to reach agreement, followed by the `members` of your quorum. An example quorum set is:

    ```
    '{"threshold":3,"members":[{"type":"Node","args":"node1.test.mobilecoin.com:8443"},{"type":"Node","args":"node2.test.mobilecoin.com:8443"},{"type":"Node","args":"node3.test.mobilecoin.com:8443"},{"type":"Node","args":"node5.test.mobilecoin.com:8443"}]}'
    ```

1. Obtain SPID key.

    Attestation with Intel's Attestation Service (IAS) requires the nodes making the request to be linked to a developer account on their platform. When running the consensus service, you will provide both the `IAS_API_KEY` and `IAS_SPID`, which you can obtain by registering with the [Intel SGX Portal](https://api.portal.trustedservices.intel.com/EPID-attestation).

    * Choose Dev for a developer network, or Prod for the TestNet.
    * Choose Linkable (name base mode). This allows other nodes in the network to blocklist nodes who are misbehaving by submitting too many attestation requests. If you choose Unlinkable, your node will be denied peer connections.

    >Note: You will provide the access qualifier when you run consensus, to indicate which Attestation endpoint to hit, via `IAS_MODE=DEV` or `IAS_MODE=PROD`

1. Generate your ed25519 message-signing key.

    ```
    openssl genpkey -algorithm ED25519 > example.com.key

    cat example.com.key
    -----BEGIN PRIVATE KEY-----
    MC4CAQAwBQYDK2VwBCIEIDlpHQLxELPlkwRhZ2UJNMZ9DTU3yK971yq+JW17Dprz
    -----END PRIVATE KEY-----
    ```

    To get the private key DER encoded, use:

    ```
    openssl genpkey -algorithm ed25519 -outform DER | openssl base64
    ```

    To get the public key from the private key, use:

    ```
    openssl genpkey -algorithm ed25519 -out example.com.key
    openssl pkey -in example.com.key -pubout -out example.com.pub.pem
    ```

    Note: For the URIs, the base64 encoding needs to use URL-safe characters, which you can achieve with:

    ```
    sed 's/+/-/g; s/\//_/g'
    ```

1. Bootstrap the ledger.

    In order to run consensus, you need to start with the correct "Origin Block." To obtain this, we recommend running our [bootstrap process](../../util/generate-sample-ledger/README.md).

1. Set up logging and node management

1. Publish node identity

    To make your node peerable, we recommend that you publish your node identity as a domain name, then run NGINX on 443 to route grpc services. For example:

    ```
    my_node.my_domain.com
    ```

1. Start the SGX daemons.

    >Note: Check your aesm location. It is either at `/opt/intel/libsgx-enclave-common/aesm` or `/opt/intel/sgx-aesm-service/aesm`. Update the commands below accordingly.

    ```
    source /opt/intel/sgxsdk/environment

    export AESM_PATH=/opt/intel/libsgx-enclave-common/aesm
    export LD_LIBRARY_PATH=${AESM_PATH}

    ${AESM_PATH}/linksgx.sh
    /bin/mkdir -p /var/run/aesmd/
    /bin/chown -R aesmd:aesmd /var/run/aesmd/
    /bin/chmod 0755 /var/run/aesmd/
    /bin/chown -R aesmd:aesmd /var/opt/aesmd/
    ${AESM_PATH}/aesm_service &
    ```

1. Set up your network.toml file.

    For example, put this inside `/etc/mc-network.toml`:
    ```
    broadcast_peers = [
        "mcp://peer1.test.mobilecoin.com:443/?consensus-msg-key=MCowBQYDK2VwAyEA-21ShHmvuuynH7EcIgkdH2dWxCojgnWYbHxLrRseQ1s=",
        "mcp://peer2.test.mobilecoin.com:443/?consensus-msg-key=MCowBQYDK2VwAyEA0MaP19zCG3C87t98UOemqip3R9hmmaPmcSFAaehPQzQ=",
    ]

    known_peers = [
        "mcp://peer3.test.mobilecoin.com:443/?consensus-msg-key=MCowBQYDK2VwAyEAk-iUVhhmmXn23VCJP0xqqtJabA9oQaJwdrHwHnfeJco=",
    ]

    quorum_set = { threshold = 2, members = [
        # Node 1
        { type = "Node", args = "peer1.test.mobilecoin.com:443" },

        # Node 2
        { type = "Node", args = "peer2.test.mobilecoin.com:443" },
    ] }

    tx_source_urls = [
        "https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node1.test.mobilecoin.com/",
        "https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node2.test.mobilecoin.com/",
    ]
    ```

#### Run

An example run command is the below.

>Note: The environment variables, `SGX_MODE`, `IAS_MODE`, `CONSENSUS_ENCLAVE_CSS` and `CONSENSUS_ENCLAVE_SIGNED` indicate important parameters to the SGX Enclave build. Please see [BUILD.md](./BUILD.md) for more details.

>Note: Running in `IAS_MODE=DEV` runs a debug enclave.

```
SGX_MODE=HW IAS_MODE=DEV \
    CONSENSUS_ENCLAVE_CSS=$(pwd)/consensus-enclave.css \
    CONSENSUS_ENCLAVE_SIGNED=$(pwd)/libconsensus-enclave.signed.so \
    cargo run --release -p mc-consensus-service -- \
    --client-responder-id my_node.my_domain.com:443 \
    --peer-responder-id node1.my_domain.com:8443 \
    --network /etc/mc-network.toml \
    --ias-api-key="${IAS_API_KEY}" \
    --ias-spid="${IAS_SPID}" \
    --ledger-path /tmp/ledger-db-1 \
    --peer-listen-uri='mcp://0.0.0.0:8443/' \
    --msg-signer-key MC4CAQAwBQYDK2VwBCIEIGz4xR7wuPKjwM1EK0MKrc9ukTjiDqvKKREITPXPkNku \
    --sealed-block-signing-key /sealed \
    --admin-listen-uri=insecure-mca://127.0.0.1:9091/
```

Alternatively, if the binary has already been built, you can run:

```
./target/release/consensus-service --client-responder-id \
    (omitted)
```

##### Configuration

For a full description of the configuration parameters, please run:

```
consensus-service --help
```

### MobileCoin Consensus Protocol

#### Byzantine Agreement

MobileCoin users must agree on the content of the blockchain for it to be useful as a record of accounts. Bad actors will have a financial motive to misrepresent the ledger to enable fraud and counterfeiting. In distributed computing, the challenge of reaching agreement in a group that cannot exclude malicious agents from participating is called the Byzantine Agreement Problem. All cryptocurrency payment networks must include code that solves the Byzantine Agreement Problem.

The MobileCoin Consensus Protocol solves the Byzantine Agreement Problem by requiring each user to specify a set of peers that they trust, called a quorum. Quorums are based on the real-life trust relationships between individuals, businesses, and other organizations that compose the MobileCoin Network. There is no central authority in the MobileCoin Network. Users accept statements about the blockchain ledger when their quorum convinces them that these statements are true. While the algorithmic design of MCP is based on the Stellar Consensus Protocol, the MobileCoin Network is not interoperable with the Stellar payment network.

The MobileCoin Consensus Protocol avoids the environmentally-damaging mathematical “work” required by Proof-of-Work (PoW) consensus protocols like Bitcoin and realizes a much higher transaction rate than the Bitcoin consensus protocol. In contrast to Proof-of-Stake (PoS) consensus protocols, practical control of governance in MCP is ceded to the users who are trusted the most by the extended MobileCoin community, rather than to the wealthiest users who control the largest financial stakes.

MCP ensures that all operators agree on the sequence of valid payments that are completed. New transactions are grouped in blocks and published approximately once every five seconds to the MobileCoin Ledger.

### Crates Overview

The following crates are particularly relevant to MobileCoin Consensus.

| Name    | Description |
| ------- | ----------- |
| [`consensus/api`](../api/README.md) | API for MobileCoin Consensus Validator services. |
| [`consensus/enclave`](../enclave/README.md) | Implementation of consensus enclave. |
| [`consensus/scp`](../scp/README.md) | Stellar Consensus Protocol |
| [`ledger/sync`](../../ledger/sync/README.md) | Sync ledger from peers. |
| [`mcconnection`](../../mcconnection/README.md) | Attested connections with peers and clients. |
| [`peers`](../../peers/README.md) | Peer-to-peer networking for the consensus layer. |
| [`transaction`](../../transaction/README.md) | Private transactions and validation of transactions. |
