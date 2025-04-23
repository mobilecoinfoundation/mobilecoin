# Table of contents

* [Consensus Server Runbook](README.md)

## About

* [About this Runbook](about/about-this-runbook/README.md)
  * [Audience](about/about-this-runbook/audience/README.md)
    * [How to Use This Information](about/about-this-runbook/audience/how-to-use-this-information.md)

## Common Tasks

* [About Common Tasks](common-tasks/about-common-tasks.md)

***

* [Understanding the Consensus Server](understanding-the-consensus-server/README.md)
  * [Secure Enclaves](understanding-the-consensus-server/secure-enclaves.md)
* [Prerequisites](prerequisites/README.md)
  * [IAS Account](prerequisites/ias-account.md)
  * [SGX-Enabled Machine](prerequisites/sgx-enabled-machine.md)
* [Getting Intel Attestation Service Credentials](getting-intel-attestation-service-credentials/README.md)
  * [Quote Status Responses](getting-intel-attestation-service-credentials/quote-status-responses.md)
  * [Validating the Attestation](getting-intel-attestation-service-credentials/validating-the-attestation.md)
* [SGX Provisioning](sgx-provisioning/README.md)
  * [Provisioning with Azure](sgx-provisioning/provisioning-with-azure.md)
  * [Downloading the Consensus Server Software](sgx-provisioning/downloading-the-consensus-server-software/README.md)
    * [Downloading the Pre-Built Container from Docker Hub](sgx-provisioning/downloading-the-consensus-server-software/downloading-the-pre-built-container-from-docker-hub.md)
* [Running the Node](running-the-node/README.md)
  * [Running the Node in a Container (Preferred Method)](running-the-node/running-the-node-in-a-container-preferred-method/README.md)
    * [Environment Variables: How to Configure Your Node](running-the-node/running-the-node-in-a-container-preferred-method/environment-variables-how-to-configure-your-node.md)
    * [Run It!](running-the-node/running-the-node-in-a-container-preferred-method/run-it.md)
  * [Using Your Own Binaries (Without Docker)](running-the-node/using-your-own-binaries-without-docker/README.md)
    * [Run It!](running-the-node/using-your-own-binaries-without-docker/run-it.md)
* [Upgrading the Enclave](upgrading-the-enclave/README.md)
  * [Unacceptable Degradation of Service](upgrading-the-enclave/unacceptable-degradation-of-service.md)
  * [Uneven Node Block Heights](upgrading-the-enclave/uneven-node-block-heights.md)
  * [Monitoring](upgrading-the-enclave/monitoring.md)
* [Configuring your Node](configuring-your-node/README.md)
  * [Configuring your Node to Connect with Trusted Peers](configuring-your-node/configuring-your-node-to-connect-with-trusted-peers/README.md)
    * [Broadcasting to Trusted and Untrusted Peers](configuring-your-node/configuring-your-node-to-connect-with-trusted-peers/broadcasting-to-trusted-and-untrusted-peers.md)
    * [Defining a Consensus Quorum Set](configuring-your-node/configuring-your-node-to-connect-with-trusted-peers/defining-a-consensus-quorum-set.md)
    * [Obtaining Ledger Contents from S3 Archive for Catchup](configuring-your-node/configuring-your-node-to-connect-with-trusted-peers/obtaining-ledger-contents-from-s3-archive-for-catchup.md)
  * [Signing Consensus Messages](configuring-your-node/signing-consensus-messages.md)
  * [Distributing Ledger Contents to S3 Archive](configuring-your-node/distributing-ledger-contents-to-s3-archive.md)
  * [Obtaining the Origin Block](configuring-your-node/obtaining-the-origin-block.md)
  * [Updating Your Network Configuration](configuring-your-node/updating-your-network-configuration.md)
* [Attesting to the Consensus Server](attesting-to-the-consensus-server.md)
* [Proposing Transactions](proposing-transactions.md)
* [Verifying Transactions are Working Correctly](verifying-transactions-are-working-correctly/README.md)
  * [Send Transaction](verifying-transactions-are-working-correctly/send-transaction.md)
  * [Use the Python API to Check Balance and Send Transactions](verifying-transactions-are-working-correctly/use-the-python-api-to-check-balance-and-send-transactions.md)
  * [Verify Nodes are Participating in Consensus](verifying-transactions-are-working-correctly/verify-nodes-are-participating-in-consensus.md)

## Common Errors and Alerts

* [Common Errors](common-errors-and-alerts/common-errors.md)
* [Common Alerts](common-errors-and-alerts/common-alerts.md)

## Glossary

* [Glossary](glossary/glossary.md)

## Frequently Asked Questions (FAQs)

* [FAQs](frequently-asked-questions-faqs/faqs.md)
