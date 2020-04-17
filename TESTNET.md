## TestNet User Guide

A public TestNet is now online to help node operators practice running MobileCoin network infrastructure. Interested individuals and organizations are invited to participate and share feedback with the developers.

In addition to bug reports and code contributions, we are seeking feedback on the clarity of our documentation, any criticisms you may have of our design, and any other constructive feedback you would like to share.

MobileCoin Inc. will be announcing details on a formal bug bounty program in the coming weeks.

### Sending Your First Payment

You can make your first MobileCoin payment right now!

1. Sign up to participate in the MobileCoin TestNet using our [online form](https://forms.gle/ULNjA6cMxCD5XNyT7).

1. You will receive an email with a *root entropy* value that you can use to claim *mobilecoins* in the TestNet ledger. Anyone who knows your *root entropy* will be able to spend your TestNet coin allocation, so keep it secret!

1. Download the TestNet Client for [mac](), [windows](), or [linux]()

1. Launch the TestNet Client and follow the on screen instructions to send your first payment.

### Running a TestNet *Watcher Node*

If you have a Linux-compatible home computer, or if you are willing to operate a linux-compatible server in the cloud, you can run a *watcher node* in the MobileCoin TestNet.

1. Compile and run the [`mobilecoind`](./mobilecoind/) daemon.

1. Use your *root entropy* with one of the `mobilecoind` [example clients](./mobilecoind/clients) (or write your own!) to create an account.

1. Exchange payment request information with other community members at the [MobileCoin Forum](https://community.mobilecoin.com).

1. Collaborate to help stress test the *validator nodes* to help discover potential problems.

### Running a TestNet *Validator Node*

If you have an SGX-capable machine, or if you are willing to operate an SGX-capable server in the cloud, you can run a *validator node* in the MobileCoin TestNet.

1. Send an email to [support@mobilecoin.com](mailto://support@mobilecoin.com) and let us know how you'd like to get involved!
