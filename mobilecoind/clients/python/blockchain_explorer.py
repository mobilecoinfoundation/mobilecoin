# Copyright (c) 2018-2020 MobileCoin Inc.

from mob_client import mob_client
from flask import Flask
from flask import render_template
from sys import getsizeof

mob_client = mob_client('localhost:4444', False)
app = Flask(__name__)

@app.route('/')
def index():
    num_blocks, num_transactions = mob_client.get_ledger_info()

    blocks = []
    for i in range(num_blocks - 1, max(num_blocks - 100, -1), -1):
        _key_image_count, txo_count = mob_client.get_block_info(i)
        block = mob_client.get_block(i)
        size_of_block = getsizeof(block) * .001
        block_row = (i, txo_count, size_of_block, bytes.hex(block.hash))
        blocks.append(block_row)

    return render_template('index.html',
        blocks=blocks,
        num_blocks=num_blocks,
        num_transactions=num_transactions)

@app.route('/block/<block_num>')
def block(block_num):
    block_hash, signature, txos, key_images = mob_client.get_block_details(int(block_num))
    size_of_block = sum([getsizeof(x) for x in [block_hash, signature, txos, key_images]]) * .001
    return render_template('block.html',
        block_num=block_num,
        block_hash=block_hash,
        key_image_count=len(key_images),
        txo_count=len(txos),
        txos=enumerate(txos),
        key_images=enumerate(key_images),
        size_of_block=size_of_block)
