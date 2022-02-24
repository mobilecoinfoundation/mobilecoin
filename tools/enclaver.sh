#!/bin/bash

# Usage:
# ./tools/enclaver.sh test.mobilecoin.com
#
# First:
#   Sets the NETWORK environment variable for ./tools/download_sigstruct.sh
#   which downloads the `.css` files for Consensus, Ingest, Ledger, and View
#
# Then:
#   Compile/run mc-sgx-css-dump to compute and print MrEnclave values to stdout
#
# Example usage:
#
# $ ./tools/enclaver.sh test.mobilecoin.com
#
#    % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
#                                  Dload  Upload   Total   Spent    Left  Speed
#  100  1808  100  1808    0     0  18833      0 --:--:-- --:--:-- --:--:-- 18833
#    % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
#                                  Dload  Upload   Total   Spent    Left  Speed
#  100  1808  100  1808    0     0  19234      0 --:--:-- --:--:-- --:--:-- 19234
#    % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
#                                  Dload  Upload   Total   Spent    Left  Speed
#  100  1808  100  1808    0     0  21270      0 --:--:-- --:--:-- --:--:-- 21270
#    % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
#                                  Dload  Upload   Total   Spent    Left  Speed
#  100  1808  100  1808    0     0  24432      0 --:--:-- --:--:-- --:--:-- 24432
#
#  Consensus Enclave
#      MRENCLAVE: 0x3dc0c6b273ca16c50d3d94d6e1042998980cf977a79521c6d87366cddc70db03
#
#  View Enclave
#      MRENCLAVE: 0x4e598799faa4bb08a3bd55c0bcda7e1d22e41151d0c591f6c2a48b3562b0881e
#
#  Ingest Enclave
#      MRENCLAVE: 0x185875464ccd67a879d58181055383505a719b364b12d56d9bef90a40bed07ca
#
#  Ledger Enclave
#      MRENCLAVE: 0x7330c9987f21b91313b39dcdeaa7da8da5ca101c929f5740c207742c762e6dcd
#

export NETWORK=$1; ./download_sigstruct.sh

echo -e "\nConsensus Enclave"
cargo run -p mc-sgx-css-dump --release 2>/dev/null < ./consensus-enclave.css | grep MRENCLAVE | sed 's/,//'
echo -e "\nView Enclave"
cargo run -p mc-sgx-css-dump --release 2>/dev/null < ./view-enclave.css | grep MRENCLAVE | sed 's/,//'
echo -e "\nIngest Enclave"
cargo run -p mc-sgx-css-dump --release 2>/dev/null < ./ingest-enclave.css  | grep MRENCLAVE | sed 's/,//'
echo -e "\nLedger Enclave"
cargo run -p mc-sgx-css-dump --release 2>/dev/null < ./ledger-enclave.css  | grep MRENCLAVE | sed 's/,//'
echo -e "\n"
