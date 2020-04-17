## FAQ

### What is the impact of an SGX compromise on transaction privacy?

Secure enclaves can provide improved integrity and confidentiality while functioning as intended. Like most complex new technologies, we should anticipate that design flaws will inevitably be discovered. Several side channel attacks against secrets protected by Intel SGX have been published, and subsequently patched or otherwise mitigated. MobileCoin is designed to provide "defense in depth" in the event of an attack based on a secure enclave exploit. MobileCoin transactions use CryptoNote technology to ensure that, even in the clear, the recipient is concealed with a one-time address, the sender is concealed in a ring signature, and the amounts are concealed with Ring Confidential Transactions (RingCT).

In the event of an SGX compromise, the attacker's view of the ledger inside the enclave would still be protected by both ring signatures and one-time addresses, and amounts would remain concealed with RingCT. These privacy protection mechanisms leave open the possibility of statistical attacks that rely on tracing the inputs in ring signatures to determine probabilistic relationships between transactions. This attack is only applicable to transactions made during the time that the secure enclave exploit is known, but not patched. Once the SGX vulnerability is discovered and addressed, statistical attacks are no longer possible, therefore forward secrecy is preserved.

### Can I run a *validator node* without Intel SGX?

You can run the `consensus-service` using SGX in simulation mode, however you will not be able to participate in consensus with other *validator nodes*. Your software measurement will be different from hardware-enabled SGX peers and remote attestation will fail.

### Can I run a *watcher node* without Intel SGX?

Yes, you can operate a *watcher node* and validate block signatures by running the `mobilecoind` daemon, which does not require SGX.

### I thought you were called *MobileCoin*. Where is the code for mobile devices?

We are hard at work building mobile SDKs for iOS and Android, as well as additional privacy-preserving infrastructure to support blockchain transactions from mobile devices. We will be releasing this software soon.

### Will I need to put my keys on a remote server to scan the blockchain for incoming transactions?

Keys will never leave your mobile device. This is a challenging problem and we are very excited to share our solution when we release our mobile SDK software.
