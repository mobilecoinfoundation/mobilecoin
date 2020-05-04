from mob_client import mob_client
from flask import Flask
from flask import render_template

mob_client = mob_client('localhost:4444', False)
app = Flask(__name__)

@app.route('/')
def index():
    num_blocks, num_transactions = mob_client.get_ledger_info()

    blocks = []
    for i in range(num_blocks - 1, max(num_blocks - 100, -1), -1):
        key_image_count, txo_count = mob_client.get_block_info(i) 
        blocks.append((i, key_image_count, txo_count))

    return render_template('index.html', 
        blocks=blocks, 
        num_blocks=num_blocks,
        num_transactions=num_transactions)

@app.route('/block/<block_num>')
def block(block_num):
    block_hash, signature, txos, key_images = mob_client.get_block_details(int(block_num))
    return render_template('block.html', 
        block_num=block_num,
        block_hash=block_hash,
        key_image_count=len(key_images),
        txo_count=len(txos),
        txos=txos,
        key_images=key_images) 
    
    #return str(mob_client.get_block_details(int(block_num)))