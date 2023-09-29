#!/bin/bash

# Copyright (c) 2018-2022 The MobileCoin Foundation

set -eo pipefail

/usr/local/bin/ledger-download.sh /fog-data

exec "$@"
