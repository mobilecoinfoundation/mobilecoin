#!/usr/bin/python3
# Copyright (c) 2018-2022 The MobileCoin Foundation

# This script can be run after starting a local network in order to generate and
# authorize minters.
#
# It must be kept in sync with the governor setup in local_network.py
#
# This is a way to prepare the network for running the mint auditor integration tests

import json
import os
import subprocess
import tempfile

from local_network import *

# Generate minter 1 and minter 2 ed25519 keys in the minting keys dir, if they don't already exist
if not os.path.exists(f'{MINTING_KEYS_DIR}/minter1'):
    subprocess.check_output(f'openssl genpkey -algorithm ed25519 -out {MINTING_KEYS_DIR}/minter1', shell=True)
    subprocess.check_output(f'openssl pkey -pubout -in {MINTING_KEYS_DIR}/minter1 -out {MINTING_KEYS_DIR}/minter1.pub', shell=True)

if not os.path.exists(f'{MINTING_KEYS_DIR}/minter2'):
    subprocess.check_output(f'openssl genpkey -algorithm ed25519 -out {MINTING_KEYS_DIR}/minter2', shell=True)
    subprocess.check_output(f'openssl pkey -pubout -in {MINTING_KEYS_DIR}/minter2 -out {MINTING_KEYS_DIR}/minter2.pub', shell=True)

# Submit a MintConfigTx that allows minter1.private to mint up to 1 billion token 1 tokens.
with tempfile.NamedTemporaryFile(mode='w') as tf:
    json.dump({
        'token_id': 1,
        'total_mint_limit': 10000000000,
        'configs': [
            {
                'mint_limit': 1000000000,
                'minters': {
                    'type': 'Single',
                    'pub_key': open(os.path.join(MINTING_KEYS_DIR, 'minter1.pub'), 'r').read()
                }
            }
        ]
    }, tf)
    tf.flush()

    output = subprocess.check_output(' '.join([
        f'cd {PROJECT_DIR} && exec {TARGET_DIR}/mc-consensus-mint-client',
        'generate-and-submit-mint-config-tx',
        f'--node insecure-mc://localhost:{BASE_CLIENT_PORT}',
        f'--signing-key {MINTING_KEYS_DIR}/governor1',
        f'--mint-config-tx-file {tf.name}',
    ]), shell=True)
    print('Token 1 client output:')
    print(output.decode('utf-8'))
    print()

# Submit a MintConfigTx that allows minter2.private to mint up to 1 billion token 2 tokens.
with tempfile.NamedTemporaryFile(mode='w') as tf:
    json.dump({
        'token_id': 2,
        'total_mint_limit': 10000000000,
        'configs': [
            {
                'mint_limit': 1000000000,
                'minters': {
                    'type': 'Single',
                    'pub_key': open(os.path.join(MINTING_KEYS_DIR, 'minter2.pub'), 'r').read()
                }
            }
        ]
    }, tf)
    tf.flush()

    output = subprocess.check_output(' '.join([
        f'cd {PROJECT_DIR} && exec {TARGET_DIR}/mc-consensus-mint-client',
        'generate-and-submit-mint-config-tx',
        f'--node insecure-mc://localhost:{BASE_CLIENT_PORT}',
        f'--signing-key {MINTING_KEYS_DIR}/governor2',
        f'--mint-config-tx-file {tf.name}',
    ]), shell=True)
    print('Token 2 client output:')
    print(output.decode('utf-8'))
    print()
