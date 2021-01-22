## TestNet User Guide

A public TestNet is now online to help node operators practice running MobileCoin network infrastructure. Interested individuals and organizations are invited to participate and share feedback with the developers.

In addition to bug reports and code contributions, we are seeking feedback on the clarity of our documentation, any criticisms you may have of our design, and any other constructive feedback you would like to share.

### Sign up to receive TestNet *mobilecoins*

Register to participate in the MobileCoin TestNet to receive an allocation of *mobilecoins*.

1. Sign up using our [online form](https://forms.gle/ULNjA6cMxCD5XNyT7).

1. You will receive an email containing a *master key* that you can use to claim *mobilecoins* in the TestNet ledger. Anyone who knows your *master key* will be able to spend your money, so keep it secret!

### Send Your First Payment

You can make your first MobileCoin payment right now!

1. Download the TestNet client package for [mac](https://github.com/mobilecoinfoundation/mobilecoin/releases/latest/download/MobileCoin.TestNet.dmg) or [linux](https://github.com/mobilecoinfoundation/mobilecoin/releases/latest/download/mobilecoin-testnet-linux.tar.gz).

1. Expand the package archive and launch the "MobileCoin TestNet" client, an app bundle (mac) or shell script (linux).

1. Enter the *master key* you received in your email and confirm your balance.

1. Try completing a payment to the sample request code you received in your email.

1. Create your own payment request and share it in the [MobileCoin forum](https://community.mobilecoin.foundation).

### Run a TestNet *Watcher Node*

If you have a Linux-compatible home computer, or if you are willing to operate a Linux-compatible server in the cloud, you can run a *watcher node* in the MobileCoin TestNet.

1. Clone the official MobileCoin repository at [Github](https://github.com/mobilecoinfoundation/mobilecoin).

1. Make sure you've installed [Docker](https://docs.docker.com/get-docker/) and [Python](https://www.python.org/downloads/).

1. Launch the MobileCoin build system Docker container using the command: `./mob prompt`

1. At the container prompt, compile and launch the [`mobilecoind`](./mobilecoind/) daemon using the TestNet quickstart script: `./start-testnet-client.sh`

1. Use your *master key* with the [TestNet client](#send-your-first-payment), or as the *root entropy* in one of the `mobilecoind` [example clients](./mobilecoind/clients) or your own code!

1. Exchange payment request information with other community members at the [MobileCoin Forum](https://community.mobilecoin.foundation).

1. Collaborate to help stress test the *validator nodes* to help discover potential problems.

### Run a TestNet *Validator Node*

If you have an SGX-capable machine, or if you are willing to operate an SGX-capable server in the cloud, you can run a *validator node* in the MobileCoin TestNet.

1. Send an email to [support@mobilecoin.com](mailto://support@mobilecoin.com) and let us know how you'd like to get involved!

## MobileCoin TestNet Schedule

The MobileCoin ledger will be reset at the end of each TestNet period to accommodate breaking changes. Each time the ledger is reset, new TestNet *mobilecoins* will be allocated to all registered users.

During *Operating Hours* our goal will be to maintain 100% uptime. We plan to rehearse enclave updates that will cause service interruption during maintenance hours.

|Period | Start Date | End Date | Operating Hours |
| -- | -- | -- | -- |
| 1 | Wed Apr 22 | Wed Apr 29 |  M-F 10AM-5PM PST |
| 2 | Wed Apr 29 | Wed May 13 |  M-F 10AM-5PM PST |
| 3 | Wed May 13 | (TBD) | M-F 10AM-5PM PST |

## Getting Help

For troubleshooting and questions, please visit the community forum at https://community.mobilecoin.foundation. You can also open a technical support ticket via email to <support@mobilecoin.com>.
