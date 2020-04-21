## TestNet User Guide

A public TestNet is now online to help node operators practice running MobileCoin network infrastructure. Interested individuals and organizations are invited to participate and share feedback with the developers.

In addition to bug reports and code contributions, we are seeking feedback on the clarity of our documentation, any criticisms you may have of our design, and any other constructive feedback you would like to share.

MobileCoin Inc. will be announcing details on a formal bug bounty program in the coming weeks.

### Sign up to receive TestNet *mobilecoins*

Register to participate in the MobileCoin TestNet to receive an allocation of *mobilecoins*.

1. Sign up using our [online form](https://forms.gle/ULNjA6cMxCD5XNyT7).

1. You will receive an email containing a *root entropy* value that you can use to claim *mobilecoins* in the TestNet ledger. Anyone who knows your *root entropy* will be able to spend your TestNet coin allocation, so keep it secret!

### Send Your First Payment

You can make your first MobileCoin payment right now!

1. Download the TestNet client package for [mac](), [windows](), or [linux]().

1. Expand the client package archive and read the included instructions file.

1. Exchange payment requests with other community members at the [MobileCoin Forum](https://community.mobilecoin.com).

### Run a TestNet *Watcher Node*

If you have a Linux-compatible home computer, or if you are willing to operate a Linux-compatible server in the cloud, you can run a *watcher node* in the MobileCoin TestNet.

1. Clone the official MobileCoin repository at [Github](https://github.com/mobilecoinofficial/mobilecoin).

1. Make sure you've installed [Docker](https://docs.docker.com/get-docker/) and [Python](https://www.python.org/downloads/).

1. Launch the MobileCoin build system Docker container using the command: `./mob prompt`

1. At the container prompt, compile and launch the [`mobilecoind`](./mobilecoind/) daemon using the command: `TBD`

1. Use your *root entropy* with the [TestNet client](#send-your-first-payment), one of the `mobilecoind` [example clients](./mobilecoind/clients), or your own code!

1. Exchange payment request information with other community members at the [MobileCoin Forum](https://community.mobilecoin.com).

1. Collaborate to help stress test the *validator nodes* to help discover potential problems.

### Run a TestNet *Validator Node*

If you have an SGX-capable machine, or if you are willing to operate an SGX-capable server in the cloud, you can run a *validator node* in the MobileCoin TestNet.

1. Send an email to [support@mobilecoin.com](mailto://support@mobilecoin.com) and let us know how you'd like to get involved!

## MobileCoin TestNet Schedule

The MobileCoin ledger will be reset at the end of each TestNet period to accommodate breaking changes. Each time the ledger is reset, new TestNet coins will be allocated to all registered users.

During normal service hours our goal will be to maintain 100% uptime. We plan to rehearse enclave updates that will cause service interruption during *Maintenance Hours*.

|Period | Start Date | End Date | Maintenance Hours |
| -- | -- | -- | -- | -- |
| 1 | Wed Apr 22 | Wed Apr 29 |  Daily 5PM-10PM PST |
| 2 | Wed Apr 29 | Wed May 13 |  M-F 5PM-7PM PST |
| 3 | Wed May 13 | (TBD) | M,W,F 5PM-6PM PST |
