#!/bin/bash

# Copyright (c) 2018-2020 MobileCoin Inc.

set -e

if [[ PYTHON_ENV=$(python -c "import sys; sys.stdout.write('1') if hasattr(sys, 'real_prefix') else sys.stdout.write('0')") ]]; then
    echo "Not running in a virtual env. Installing requirements may have side effects."
fi

echo "Downloading requirements."
pip3 install -r requirements.txt

echo "Compiling Protos."
./compile_proto.sh

echo "Starting python wallet client."
python3 ./main.py --mobilecoind localhost:4444
