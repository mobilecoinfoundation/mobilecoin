## mint-auditor

This is a service which provides a gRPC API for auditing mints and burns on the MobileCoin blockchain, and optionally correlating them with deposits and withdrawals on a [Gnosis Safe](https://gnosis-safe.io/).

The mint auditor stores its audit information in a SQLite database, and provides a gRPC for querying this database.
It also provides some Prometheus metrics to ease automated monitoring.

### Launching

The mint auditor requires a local ledger database to audit. It does not sync its own ledger, and relies on `mobilecoind` or `full-service` to take care of that. As such, the first step is to ensure something is running that is syncing the ledger to a local file.

To run the mint auditor we can use `cargo`:
```
    cargo run -p mc-mint-auditor -- \
        scan-ledger \
        --ledger-db /tmp/mc-local-network/node-ledger-0 \
        --mint-auditor-db /tmp/mc-local-network/auditor-db \
        --listen-uri insecure-mint-auditor://127.0.0.1:7334/
```

This will run a mint auditor that scans the ledger, performs audits into its local database, and exposes information over the gRPC endpoint.

For Gnosis auditing, an additional parameter (`--gnosis-safe-config gnosis-safe.toml`) needs to be passed. The TOML (or JSON) file contains information about the Gnosis safe configuration to audit. See more below for details about this.


### Gnosis Safe Auditing

The mint auditor supports syncing data from a Gnosis safe. It uses the [Gnosis transaction service API](https://github.com/safe-global/safe-transaction-service/) to get the data. This service is operated by Gnosis, and is available for [ETH main net](https://safe-transaction.gnosis.io/) and [Rinkeby, an ETH test net](https://safe-transaction.rinkeby.gnosis.io/).

Mints on the MobileCoin blockchain are expected to correlate with a deposit to a safe. The expected process is:
1. A deposit of the appropriate backing token is made to the safe using a standard Ethereum transaction.
2. A MintTx is then submitted to the MobileCoin blockchain, embedding the deposit transaction hash in the nonce of the
   MobileCoin MintTx. The nonce allows linking the MobileCoin mint to the Gnosis safe deposit.

Similarly, burns on the MobileCoin blockchain are expected to correlate with a withdrawal from a safe. The expected process is:
1. A transaction on the MobileCoin blockchain that moves the desired token to the burn address is issued.
2. A [batched transaction](https://help.gnosis-safe.io/en/articles/4680071-transaction-builder) is issued to the Ethereum blockchain. The batched transaction needs to contain two transactions:
    1. A transaction that moves the desired token out of the safe
    1. A transaction to an auxiliary contract (see more details below) that is used to link withdrawal to the MobileCoin burn.

Gnosis deposits are easily linked to the matching MobileCoin mints via the Ethereum transaction hash. Linking withdrawals is more difficult since standard Ethereum transactions do not have a way of including metadata. In an ideal world we would've had the option of including the MobileCoin burn transaction TxOut public key in the Ethereum withdrawal transaction, but there is no easy way to do that.
The solution we came up with is to deploy an "auxiliary contract", who has a single function that accepts arbitrary metadata bytes, and use that as part of a Gnosis batched transfer to include extra data in addition to the token transfer. Such contract can be seen [here](https://github.com/tbrent/ethereum-metadata) and is [deployed to the Rinkeby network](https://rinkeby.etherscan.io/address/0x76BD419fBa96583d968b422D4f3CB2A70bf4CF40).

#### Setting up

The first step is to decide which asset you are going to use on the Ethereum blockchain, and get some ETH (for paying gas fees) and some of this test asset. For testing purposes we have used `RinkUSDT` (Test USD Tether) - https://rinkeby.etherscan.io/token/0xB0Dfaaa92e4F3667758F2A864D50F94E8aC7a56B. You need to get some ETH, and some of this asset. Google around to find working faucets. At the time of writing, https://rinkeby-erc20-faucet.testnet.teleport.network/ and https://faucet.rinkeby.io/ worked.

To play around with Gnosis auditing the first step is to create a safe. This can be done on https://gnosis-safe.io/
Once the safe is created, it will be assigned an address on the Ethereum blockchain. This assumes you have a wallet that your browser can connect to such as [MetaMask](https://metamask.io/). Note that creating a Gnosis Safe requires submitting a transaction to the Ethereum blockchain, so your wallet will need to have some ETH to pay the gas fees.

The Ethereum network you are testing with will need to have the metadata contract deployed. For the Rinkeby test network, this was already done and assigned the address `0x76BD419fBa96583d968b422D4f3CB2A70bf4CF40`.
You will also need to know the 4 byte signature of the metadata contract `emitBytes` function. For the contract mentioned above, this is `AUX_BURN_FUNCTION_SIG.to_vec()` (since this is derived from the function signature, it should be the same for all unmodified deployments of this contract).

#### Running the mint auditor

1. The mint auditor requires a configuration file for auditing Gnosis safe. Below is an example of how this file should look like:

```toml
[[safes]]
safe_addr = "0xeC018400FFe5Ad6E0B42Aa592Ee1CF6092972dEe" # Safe address that is available once it is created
api_url = "https://safe-transaction.rinkeby.gnosis.io/"

[[safes.tokens]]
token_id = 1
eth_token_contract_addr = "0xB0Dfaaa92e4F3667758F2A864D50F94E8aC7a56B" # RinkUSDT
aux_burn_contract_addr = "0x76BD419fBa96583d968b422D4f3CB2A70bf4CF40" # Auxiliary metadata contract address
aux_burn_function_sig = [0xc7, 0x6f, 0x06, 0x35] # Auxiliary metadata emitBytes function signature hash
```

2. Start mobilecoind to sync the ledger:
```
mobilecoind \
         --ledger-db /tmp/ledger-db \
         --poll-interval 10 \
         --peer mc://node1.test.mobilecoin.com/ \
         --peer mc://node2.test.mobilecoin.com/ \
         --tx-source-url https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node1.test.mobilecoin.com/ \
         --tx-source-url https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node2.test.mobilecoin.com/
```

3. Start the mint auditor:
```
    MC_LOG=mc_mint_auditor=debug cargo run -p mc-mint-auditor -- \
        scan-ledger \
        --gnosis-safe-config gnosis-safe.toml \
        --ledger-db /tmp/ledger-db \
        --mint-auditor-db /tmp/mc-auditor-db
```
#### Depositing to the safe

Depositing to the safe is as simple as sending a standard Ethereum transaction that moves your desired token (`RinkUSDT` in this example) into the safe's address.

Once the Gnosis transaction service notices the transaction and the auditor syncs it you should see a log message similar to this:
`2022-06-21 20:40:42.785395662 UTC INFO Processing gnosis safe deposit: EthereumTransfer { from: EthAddr("0xdc079a637a1417020916FfB8a39fF5a2801A0F07"), to: EthAddr("0xeC018400FFe5Ad6E0B42Aa592Ee1CF6092972dEe"), token_addr: Some(EthAddr("0xB0Dfaaa92e4F3667758F2A864D50F94E8aC7a56B")), tx_hash: EthTxHash("0x744372bb82b2d0f0e7b2722d163ffef97656562b40cc7fad9a1809d14aaf626a"), tx_type: "ERC20_TRANSFER", value: JsonU64(10000000000000000000) }, mc.app: mc-mint-auditor, mc.module: mc_mint_auditor::gnosis::sync, mc.src: mint-auditor/src/gnosis/sync.rs:128`

#### Withdrawing from the safe

Withdrawal is slightly move involved since you will need to construct a multi-transaction that both moves the token out of the safe and transacts with the auxiliary metadata contracts to record the matching MobileCoin burn TxOut public key.

The steps to do that are:
1. On the [Gnosis safe web app](https://gnosis-safe.io/app/) click `Apps` and then select the `Transaction Builder` application.
2. We will first construct the transaction that moves the `RinkUSDT` token. In the `Enter Address or ENS Name` you need to put the contract address, which for `RinkUSDT` on Rinkeby is `0xB0Dfaaa92e4F3667758F2A864D50F94E8aC7a56B`
3. Under `Enter ABI` you need to put the contract ABI, which is:
    ```json
    [{"constant":true,"inputs":[],"name":"name","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_upgradedAddress","type":"address"}],"name":"deprecate","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"_spender","type":"address"},{"name":"_value","type":"uint256"}],"name":"approve","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"deprecated","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_evilUser","type":"address"}],"name":"addBlackList","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"totalSupply","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_from","type":"address"},{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],"name":"transferFrom","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"upgradedAddress","outputs":[{"name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"","type":"address"}],"name":"balances","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"maximumFee","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"_totalSupply","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[],"name":"unpause","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"_maker","type":"address"}],"name":"getBlackListStatus","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"","type":"address"},{"name":"","type":"address"}],"name":"allowed","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"paused","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"who","type":"address"}],"name":"balanceOf","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[],"name":"pause","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"getOwner","outputs":[{"name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"owner","outputs":[{"name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"symbol","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],"name":"transfer","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"newBasisPoints","type":"uint256"},{"name":"newMaxFee","type":"uint256"}],"name":"setParams","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"amount","type":"uint256"}],"name":"issue","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"amount","type":"uint256"}],"name":"redeem","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"_owner","type":"address"},{"name":"_spender","type":"address"}],"name":"allowance","outputs":[{"name":"remaining","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"basisPointsRate","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"","type":"address"}],"name":"isBlackListed","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_clearedUser","type":"address"}],"name":"removeBlackList","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"MAX_UINT","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"newOwner","type":"address"}],"name":"transferOwnership","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"_blackListedUser","type":"address"}],"name":"destroyBlackFunds","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"inputs":[{"name":"_initialSupply","type":"uint256"},{"name":"_name","type":"string"},{"name":"_symbol","type":"string"},{"name":"_decimals","type":"uint256"}],"payable":false,"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":false,"name":"amount","type":"uint256"}],"name":"Issue","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"name":"amount","type":"uint256"}],"name":"Redeem","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"name":"newAddress","type":"address"}],"name":"Deprecate","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"name":"feeBasisPoints","type":"uint256"},{"indexed":false,"name":"maxFee","type":"uint256"}],"name":"Params","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"name":"_blackListedUser","type":"address"},{"indexed":false,"name":"_balance","type":"uint256"}],"name":"DestroyedBlackFunds","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"name":"_user","type":"address"}],"name":"AddedBlackList","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"name":"_user","type":"address"}],"name":"RemovedBlackList","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"owner","type":"address"},{"indexed":true,"name":"spender","type":"address"},{"indexed":false,"name":"value","type":"uint256"}],"name":"Approval","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"from","type":"address"},{"indexed":true,"name":"to","type":"address"},{"indexed":false,"name":"value","type":"uint256"}],"name":"Transfer","type":"event"},{"anonymous":false,"inputs":[],"name":"Pause","type":"event"},{"anonymous":false,"inputs":[],"name":"Unpause","type":"event"}]
    ```
    The `RinkUSDT` contract is identical to the `USDT` token on main net, which can be viewed on https://etherscan.io/address/0xdac17f958d2ee523a2206206994597c13d831ec7#code
    This page contains a `Contract ABI` section that you copy-paste from.
4. Once you put the contract ABI, under the `Transaction information` section you should be able to select the `transfer` method under `Contract Method Selector`
5. Set `_to` to your destination wallet address. This is the address that will receive the tokens withdrawn from the safe.
6. Set `_value` to the amount to withdraw, for example `1000000000000000000`.
7. Click `Add transaction`. Now that you added the transaction to withdraw the tokens, you need to add the one to the auxiliary metadata contract.
8. Edit the `Enter Address or ENS Name` to contain the address of the auxiliary token. In Rinkeby this is `0x76BD419fBa96583d968b422D4f3CB2A70bf4CF40`.
9. For ABI, use:
    ```
    [{"inputs":[],"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"sender","type":"address"},{"indexed":false,"internalType":"bytes","name":"metadata","type":"bytes"}],"name":"MetadataReceived","type":"event"},{"inputs":[{"internalType":"bytes","name":"metadata","type":"bytes"}],"name":"emitBytes","outputs":[],"stateMutability":"nonpayable","type":"function"}]
    ```
    This is obtained by looking at https://rinkeby.etherscan.io/address/0x76BD419fBa96583d968b422D4f3CB2A70bf4CF40#code
10. Method will be automatically selected to the only one available - `emitBytes`.
11. `metadata (bytes)` should be 32 hex-encoded bytes (i.e. 64 hex chars) that represents the TxOut public key. For example, put `0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`.
12. Click `Add transaction`.
13. Now that everything is ready, click `Create Batch` and then `Send Batch`. Once the transaction goes through your wallet should contain the deposit and you should see a log message from the mint-auditor:
    ```
    2022-06-21 21:11:05.933236816 UTC INFO Processing withdrawal from multi-sig tx: GnosisSafeWithdrawal { id: None, eth_tx_hash: "0x0e781edb7739aa88ad2ffb6a69aab46ff9e32dbd0f0c87e4006a176838b075d2", eth_block_number: 10892902, safe_addr: "0xeC018400FFe5Ad6E0B42Aa592Ee1CF6092972dEe", token_address: "0xB0Dfaaa92e4F3667758F2A864D50F94E8aC7a56B", amount: 1000000000000000000, mc_tx_out_public_key_hex: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00" }, mc.app: mc-mint-auditor, mc.module: mc_mint_auditor::gnosis::sync, mc.src: mint-auditor/src/gnosis/sync.rs:170
    ```
