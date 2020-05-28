# Copyright (c) 2018-2020 MobileCoin Inc.

import argparse
import json
import sys

from flask import Flask, render_template, request
from tinydb import TinyDB, Query

sys.path.append('../mob_client')
from mob_client import mob_client

MOB = 1_000_000_000_000
WINNING_AMOUNT = 10_000 * MOB

# Load defaults to make available to app. Override in __main__.
client = mob_client('localhost:4444', False)
db = TinyDB('/tmp/players.json')
credentials = None
app = Flask(__name__)


def command_args():
    parser = argparse.ArgumentParser(description='PizzaMOB Leaderboard')
    parser.add_argument('--entropy',
                        type=str,
                        required=True,
                        help='Entropy for PizzaMOB account.')
    parser.add_argument('--port',
                        type=int,
                        required=False,
                        default=5000,
                        help='PizzaMOB Leaderboard listen port.')
    parser.add_argument('--player_db',
                        type=str,
                        required=False,
                        default='/tmp/players.json',
                        help='Path to DB for PizzaMOB players.')
    parser.add_argument('--mobilecoind_port',
                        type=int,
                        required=False,
                        default=4444,
                        help='Port of mobilecoind service to connect to.')
    parser.add_argument('--mobilecoind_host',
                        type=str,
                        required=False,
                        default='localhost',
                        help='Hostname of mobilecoind service to connect to.')
    return parser.parse_args()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/add_user', methods =['POST'])
def add_user():
    player_data = request.form['player_data']
    players = db.table('Players')
    player = Query()
    res = players.search(player.passphrase == player_data)
    new_player = len(res) == 0
    if new_player:
        # add monitor for new subaddress
        subaddress = get_next_subaddress()

    else:
        assert len(res) == 1 # FIXME: collisions
        subaddress = res[0]['subaddress']

    monitor = get_or_add_monitor(subaddress)
    request_code = get_request_code(monitor, subaddress)
    balance = client.get_balance(monitor, subaddress)

    if new_player:
        players.insert({
            'passphrase': player_data,
            'subaddress': subaddress,
            'code': request_code
        })
    else:
        # update the request code
        players.update({'code': request_code}, player.passphrase == player_data)

    leaderboard = get_leaderboard()

    response = {
        "code": request_code,
        "balance": balance / MOB,
        "leaderboard": leaderboard,
        "goal": WINNING_AMOUNT / MOB,
        "new": new_player,
    }

    return json.dumps(response)


# TinyDB Utility Methods
def get_next_subaddress():
    player_table = db.table('Players')
    subaddresses = sorted([p['subaddress'] for p in player_table.all()])
    last_subaddy = subaddresses[-1] if len(subaddresses) > 0 else 0
    return last_subaddy + 1

# PizzaMOB Utility Methods for interacting with mob_client
def get_or_add_monitor(subaddress):
    try:
        monitor_id = client.get_monitor_id(credentials, index=subaddress)
    except Exception as _e:
        # Always only add for the master credentials.
        monitor_id = client.add_monitor(credentials)
    return monitor_id

def get_request_code(monitor, subaddress):
    public_address = client.get_public_address(monitor, subaddress)
    return client.get_request_code(public_address)

def get_leaderboard():
    player_table = db.table('Players')
    players = player_table.all()
    res = []
    for p in players:
        monitor = get_or_add_monitor(p['subaddress'])
        balance = client.get_balance(monitor, p['subaddress'])
        res.append({'balance': balance / MOB, 'code': p['code']})
    res.sort(key=lambda player: player['balance'])
    res.reverse()
    return res


if __name__ == "__main__":
    args = command_args()

    # Load tinydb for user -> subaddress, request_code
    db = TinyDB(args.player_db)

    # Initialize tables if they don't already exist
    players_table = db.table('Players')

    # Open connection to mobilecoind
    client = mob_client(
        args.mobilecoind_host + ':' + str(args.mobilecoind_port), False)

    # Load the credentials for the master account
    credentials = client.get_account_key(bytes.fromhex(args.entropy))
    get_or_add_monitor(0)

    app.run(host='0.0.0.0', port=int(args.port))
