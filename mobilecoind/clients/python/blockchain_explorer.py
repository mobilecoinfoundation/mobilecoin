# Copyright (c) 2018-2020 MobileCoin Inc.

from mob_client import mob_client
from flask import Flask, render_template
from sys import getsizeof

mob_client = mob_client('localhost:4444', False)
app = Flask(__name__)

@app.route('/')
def index():
    num_blocks, num_transactions = mob_client.get_ledger_info()

    blocks = []
    for i in range(num_blocks - 1, max(num_blocks - 100, -1), -1):
        _key_image_count, txo_count = mob_client.get_block_info(i)
        # Will get ResourceExhausted if message larger than 4194304
        if txo_count > 20000:
            continue
        block = mob_client.get_block(i)
        size_of_block = getsizeof(block) * .001
        print("block= ", block)
        block_row = (i, txo_count, size_of_block, bytes.hex(block.block.contents_hash.data))
        blocks.append(block_row)

    return render_template('index.html',
        blocks=blocks,
        num_blocks=num_blocks,
        num_transactions=num_transactions)

@app.route('/block/<block_num>')
def block(block_num):
    block = mob_client.get_block(int(block_num))
    size_of_block = getsizeof(block)
    return render_template('block.html',
        block_num=int(block_num),
        block_hash=block.block.contents_hash.data,
        key_image_count=len(block.key_images),
        txo_count=len(block.txos),
        txos=enumerate(block.txos),
        key_images=enumerate(block.key_images),
        size_of_block=size_of_block)
