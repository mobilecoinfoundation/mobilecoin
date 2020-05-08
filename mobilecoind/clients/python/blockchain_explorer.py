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
    for i in range(num_blocks - 1, max(num_blocks - 100, -1), -1):
        _key_image_count, txo_count = client.get_block_info(i)
        # Will get ResourceExhausted if message larger than 4194304
        if txo_count > 20000:
            continue
        block = client.get_block(i)
        size_of_block = getsizeof(block) * .001
        block_row = (i, txo_count, size_of_block, bytes.hex(block.block.contents_hash.data))
        blocks.append(block_row)

    return render_template('index.html',
        blocks=blocks,
        num_blocks=num_blocks,
        num_transactions=num_transactions)

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
        size_of_block=size_of_block)

if __name__ == "__main__":
    args = command_args()
    client = mob_client(args.mobilecoind_host + ':' + str(args.mobilecoind_port), False) 
    app.run(host='0.0.0.0', port=str(args.port))
