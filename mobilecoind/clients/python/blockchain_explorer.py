# Copyright (c) 2018-2020 MobileCoin Inc.

import argparse
from mob_client import mob_client
from flask import Flask, render_template
from sys import getsizeof

client = mob_client('localhost:4444', False)
app = Flask(__name__)

def command_args():
    parser = argparse.ArgumentParser(description='MobileCoin Block Explorer')
    parser.add_argument(
        '--port',
        type=int,
        required=False,
        default=5000,
        help='Block Explorer listen port'
    )
    parser.add_argument(
        '--mobilecoind_port',
        type=int,
        required=False,
        default=4444,
        help='Port of mobilecoind service to connect to'
    )
    parser.add_argument(
        '--mobilecoind_host',
        type=str,
        required=False,
        default='localhost',
        help='Hostname of mobilecoind service to connect to'
    )
    return parser.parse_args()

@app.route('/')
def index():
    num_blocks, num_transactions = client.get_ledger_info()

    blocks = []
    signers = {}
    for i in range(num_blocks - 1, max(num_blocks - 100, -1), -1):
        _key_image_count, txo_count = client.get_block_info(i)
        # Will get ResourceExhausted if message larger than 4194304
        if txo_count > 20000:
            continue
        block = client.get_block(i)
        size_of_block = getsizeof(block) * .001
        print("block.signatures = ", block.signatures)
        block_row = (i, txo_count, size_of_block, len(block.signatures),
                     bytes.hex(block.block.contents_hash.data))
        blocks.append(block_row)

        # Process signature data - sort by signer
        for signature_data in block.signatures:
            signature = signature_data.signature
            signer = signature_data.signer
            # If a new signer has appeared, prepend False for all previous blocks
            if signer not in signers:
                signers[signer] = [False for i in range(i - 1)]
            signers[signer].append(True)

    return render_template('index.html',
                           blocks=blocks,
                           num_blocks=num_blocks,
                           num_transactions=num_transactions,
                           signers=signers)


@app.route('/block/<block_num>')
def block(block_num):
    block = client.get_block(int(block_num))
    size_of_block = getsizeof(block)
    return render_template('block.html',
                           block_num=int(block_num),
                           block_hash=block.block.contents_hash.data,
                           key_image_count=len(block.key_images),
                           txo_count=len(block.txos),
                           txos=block.txos,
                           key_images=block.key_images,
                           size_of_block=size_of_block,
                           signatures=block.signatures)

if __name__ == "__main__":
    args = command_args()
    client = mob_client(args.mobilecoind_host + ':' + str(args.mobilecoind_port), False)
    app.run(host='0.0.0.0', port=str(args.port))
