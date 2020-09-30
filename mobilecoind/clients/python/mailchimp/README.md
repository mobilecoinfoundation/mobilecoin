## TestNet Allocation Script

Users who sign up to participate in the TestNet using our [online form](https://forms.gle/ULNjA6cMxCD5XNyT7) are added to an audience in MailChimp using Zapier.

This script polls for records in the MailChimp TestNet audience that have not been assigned a master key. When new entries are found, keys are generated and added to the MailChimp record. An allocation of TestNet mobilecoins is then paid to the generated account from a provided sender account. Finally, tags are added to the entry in MailChimp that trigger a campaign automation that sends a "Welcome" email to the new user, with their master key and further instructions.

### Allocating TestNet mobilecoins to Mailchimp audience members

1. Run the installation script `./start_mobilecoind.sh` to install requirements, generate python code for the api, and compile and run mobilecoin. An optional `--clean` argument may be provided to the script to additionally delete databases from prior runs.

1. Run the python script: `python3 ./allocate_mobilecoins.py -m=[MailChimp API key] -k=[sender master key as hex]`

The python script supports the following args:

arg | description | example
---- | ---- | ----
-m or --mailchimp | The MailChimp API key | `{32 hex characters}-us19`
-k or --key | MobileCoin sender master key as hex | `{64 hex characters}`
-v or --value | mobilecoins to allocate in MOB (defaults to 100 if not set) | `100`
--clean | remove any old monitors from mobileconid | (flag only)

Note that the allocation script will quit when the sender's balance gets low (< 1000 MOB), at which point it can be restarted with a new sender master key, or a payment can be made to replenish the sender account that is in use.

### Downloading current balance information for the Mailchimp audience members

1. Run the installation script `./start_mobilecoind.sh` to install requirements, generate python code for the api, and compile and run mobilecoin. An optional `--clean` argument may be provided to the script to additionally delete databases from prior runs.

1. Run the python script: `python3 ./download_members.py -m=[MailChimp API key]`

The python script supports the following args:

arg | description | example
---- | ---- | ----
-m or --mailchimp | The MailChimp API key | `{32 hex characters}-us19`
--clean | remove any old monitors from mobileconid | (flag only)

Note that mobilecoind can only process approximately 200 "monitor-blocks" per second, so it may require a long time to check all of the balances. For example, it will require about 7 hours to check balances for a list of 1000 members when the ledger contains 5000 blocks.
