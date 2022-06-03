#!/usr/bin/env python3

# Copyright (c) 2022 The MobileCoin Foundation
#
# Integration test that uses mobilecoind-json to submit a transaction and check balance.

import argparse
import glob
import json
import logging
import os
import sys
import time
import urllib.request


logging.basicConfig(stream = sys.stdout, level = logging.INFO, format="%(levelname)s:%(module)s:%(lineno)s: %(message)s")


class MobilecoindJsonClient:
    def __init__(self, base_url):
        if not base_url.endswith("/"):
            base_url += "/"
        self.base_url = base_url

    def request(self, url, data=None):
        req = urllib.request.Request(self.base_url + url)

        if data:
            data = json.dumps(data)
            data_bytes = data.encode("utf-8")

            req.add_header("Content-Type", "application/json; charset=utf-8")
            req.add_header("Content-Length", len(data_bytes))
            response = urllib.request.urlopen(req, data_bytes)
        else:
            response = urllib.request.urlopen(req)

        return json.loads(response.read())

    def get_balance(self, monitor_id, subaddress_index=0):
        response = self.request(f"monitors/{monitor_id}/subaddresses/{subaddress_index}/balance")
        if "balance" not in response:
            raise Exception(f"Invalid response: {response}")
        return int(response["balance"])

    def create_monitor(self, account_key, first_subaddress_index=0, num_subaddresses=1):
        return self.request(f"monitors", {
            "account_key": account_key,
            "first_subaddress": first_subaddress_index,
            "num_subaddresses": num_subaddresses,
        })

    def get_monitor(self, monitor_id):
        return self.request(f"monitors/{monitor_id}")

    def get_ledger_local(self):
        return self.request(f"ledger/local")

    # Takes the json loaded from a private key file, tests if it is mnemnonic or root entropy
    #
    # If it is mnemonic, we pass the mnemonic to `account-key-from-mnemonic` route
    # Otherwise, we hit the `entropy/{root_entropy}` route.
    # Both return Json account key response.
    def account_key_from_json(self, obj):
        if "mnemonic" in obj:
            return self.request("account-key-from-mnemonic", {"mnemonic": obj["mnemonic"]})
        elif "root_entropy" in obj:
            # Take the integer array in obj["root_entropy"], convert it to builtin bytes, then
            # get hex string of that.
            return self.request("entropy/{}".format(bytes(obj["root_entropy"]).hex()))
        else:
            raise Exception("unknown key format", obj)

    def get_public_address(self, monitor_id, subaddress_index=0):
        return self.request(f"monitors/{monitor_id}/subaddresses/{subaddress_index}/public-address")

    def pay_address_code(self, from_monitor_id, from_subaddress_index, to_b58_address, value):
        return self.request(f"monitors/{from_monitor_id}/subaddresses/{from_subaddress_index}/pay-address-code", {
            "receiver_b58_address_code": to_b58_address,
            "value": str(value),
        })

    def tx_status_as_sender(self, tx_info):
        return self.request(f"tx/status-as-sender", tx_info)

    def tx_status_as_receiver(self, monitor_id, receipt):
        return self.request(f"monitors/{monitor_id}/tx-status-as-receiver", receipt)

    def get_utxos(self, monitor_id, subaddress_index=0):
        return self.request(f"monitors/{monitor_id}/subaddresses/{subaddress_index}/utxos")["output_list"]

    def wait_for_monitor_to_sync(self, monitor_id, poll_interval=0.1):
        while True:
            local_ledger = self.get_ledger_local()
            monitor = self.get_monitor(monitor_id)
            if int(monitor["next_block"]) >= int(local_ledger["block_count"]):
                break
            time.sleep(poll_interval)


def load_keys(keys_dir):
    """Load all keys from the keys_dir directory"""

    # When Comparing filenames, make shorter file names compare less than longer filenames,
    # using this key function
    def filename_key(filename):
        return (len(filename), filename);

    return [
        json.load(open(f)) for f in
        sorted(glob.glob(os.path.join(keys_dir, "*.json")), key=filename_key)
    ]


def run_test(mobilecoind_json_url, keys_dir, max_seconds):
    logging.info(f"mobilecoind-json integration test starting with url={mobilecoind_json_url} keys_dir={keys_dir} max_seconds={max_seconds}")
    keys = load_keys(keys_dir)
    if not keys:
        raise Exception(f"No keys found in directory: {keys_dir}")
    logging.info(f"Loaded {len(keys)} keys")

    client = MobilecoindJsonClient(mobilecoind_json_url)

    # Add two monitors and wait for them to sync
    monitor_ids = []
    for i in range(2):
        account_key = client.account_key_from_json(keys[i])
        monitor = client.create_monitor(account_key)
        logging.info(f"{i}: Monitor created: {monitor}, waiting to sync...")
        monitor_id = monitor["monitor_id"]
        client.wait_for_monitor_to_sync(monitor_id)
        balance = client.get_balance(monitor_id)
        logging.info(f"{i}: Monitor synced: balance={balance}")
        monitor_ids.append(monitor_id)

    # Run tests
    test_pay_address_code(client, monitor_ids)
    test_utxos(client, monitor_ids[1])

def test_pay_address_code(client, monitor_ids):
    # Get the balance of both monitors and then transact from one to the other using the pay_address_code endpoint
    balance0 = client.get_balance(monitor_ids[0])
    balance1 = client.get_balance(monitor_ids[1])

    amount = 1
    addr1 = client.get_public_address(monitor_ids[1])["b58_address_code"]
    tx_info = client.pay_address_code(monitor_ids[0], 0, addr1, amount)
    logging.info(f"Tx submitted: {tx_info}")

    # Wait up to 30 seconds for tx to happen
    for _ in range(30):
        new_balance1 = client.get_balance(monitor_ids[1])
        if new_balance1 != balance1:
            break
        time.sleep(1)

    assert new_balance1 == balance1 + amount, f"Balance mismatch: {new_balance1} != {balance1} + {amount}"
    logging.info("Balance check passed")

    # Check the status as the sender
    response = client.tx_status_as_sender(tx_info)
    logging.info(f"tx_status_as_sender: {response}")
    if response["status"] != "verified":
        raise Exception(f"Failed tx_status_as_sender check: {response}")

    # Check the status as the receiver
    response = client.tx_status_as_receiver(monitor_ids[1], tx_info["receiver_tx_receipt_list"][0])
    logging.info(f"tx_status_as_receiver: {response}")
    if response["status"] != "verified":
        raise Exception(f"Failed tx_status_as_receiver check: {response}")


def test_utxos(client, monitor_id):
    # Confirm the balance matches the list of utos
    balance = client.get_balance(monitor_id)
    utxos = client.get_utxos(monitor_id)

    utxo_balance = sum(int(utxo["value"]) for utxo in utxos)
    logging.info(f"balance is {balance}, utxo_balance is {utxo_balance}")
    assert balance == utxo_balance


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--mobilecoind-json-url",
                        default="http://localhost:9090/",
                        type=str,
                        help="mobilecoind-json host")
    parser.add_argument("--key-dir",
                        type=str,
                        help="Path to directory of account_keys",
                        required=True)
    parser.add_argument("--max-seconds",
                        type=int,
                        default=40,
                        help="Number of seconds to wait for a tx to clean")
    args = parser.parse_args()
    run_test(
        args.mobilecoind_json_url,
        args.key_dir,
        args.max_seconds,
    )

