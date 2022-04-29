#!/usr/bin/env python3

# Copyright (c) 2018-2022 The MobileCoin Foundation

"""
The purpose of this strategy is to drain funds from one account to another.
This is one way to transfer tokens to a fog account, which were created after bootstrap.
This is the case for minted tokens (which fog distro cannot transfer).

This script thus provides a method for testing transactions with minted tokens, with fog wallets.

It zips the source accounts and dest accounts together, and each source account sends
its entire balance (less fee) to the dest account

(Currently the process of using mc-util-generate-sample-ledger to generate an origin block
and then sending transactions via mc-fog-distribution is blind to minted tokens because
mc-fog-distribution only sends transactions based on initial balances generated in the sample
ledger.)

Example setup and usage:
```
    python3 drain-accounts.py --key-dir ../../../target/sample_data/master/keys/ --dest-key-dir ../../../target/sample_data/master/fog_keys/ --fee 20
```
"""
import argparse
import glob
import logging
import mobilecoind_api_pb2
import os
import sys
import time
from accounts import connect, load_key_and_register, poll, wait_for_accounts_sync, TransferStatus
from google.protobuf.empty_pb2 import Empty

logging.basicConfig(stream = sys.stdout, level = logging.INFO, format="%(levelname)s:%(module)s:%(lineno)s: %(message)s")


def parse_args() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mobilecoind-host",
                        default="localhost",
                        type=str,
                        help="Mobilecoind host")
    parser.add_argument("--mobilecoind-port",
                        default="4444",
                        type=str,
                        help="Mobilecoind port")
    parser.add_argument("--key-dir",
                        type=str,
                        help="Path to directory of account_keys")
    parser.add_argument("--dest-key-dir",
                        type=str,
                        help="Path to directory of destination account_keys")
    parser.add_argument("--max-seconds",
                        type=int,
                        default=40,
                        help="Number of seconds to wait for a tx to clean")
    parser.add_argument("--fee",
                        type=int,
                        default=20,
                        help="Amount less than the balance that we attempt to send")
    parser.add_argument("--max-accounts",
                        type=int,
                        default=-1,
                        help="Number of accounts to pull from the account keys / destination accounts keys folders")
    parser.add_argument("--token-id",
                        type=int,
                        default=0,
                        help="Token id to transact in")


    return parser.parse_args()

def read_file(path):
    with open(path, "r") as file:
        return file.read()

def run_test(stub, amount, monitor_id, dest, max_seconds, token_id):
    tx_stats = {}
    sync_start = time.time()
    wait_for_accounts_sync(stub, [monitor_id], 3)
    logging.info("Time to sync: %s", time.time() - sync_start)

    resp = stub.GetBalance(
        mobilecoind_api_pb2.GetBalanceRequest(monitor_id=monitor_id, token_id=token_id))
    starting_balance = resp.balance
    logging.info("Starting balance prior to transfer: %s", starting_balance)
    tx_resp = stub.SendPayment(
        mobilecoind_api_pb2.SendPaymentRequest(
            sender_monitor_id=monitor_id,
            sender_subaddress=0,
            outlay_list=[
                mobilecoind_api_pb2.Outlay(
                    value=amount,
                    receiver=dest,
                )
            ],
            fee=0,
            tombstone=0,
            token_id=token_id,
        ))

    tx_stats[0] = {
        'start': time.time(),
        'time_delta': None,
        'tombstone': tx_resp.sender_tx_receipt.tombstone,
        'block_delta': None,
        'status': TransferStatus.pending,
        'receipt': tx_resp,
    }
    stats = poll(monitor_id, tx_stats, stub)
    # FIXME: Move max seconds check inside polling
    assert tx_stats[0]['time_delta'] < max_seconds, "Did not clear in time"
    assert tx_stats[0]['status'] == TransferStatus.success, "Transfer did not succeed"
    return stats

# When Comparing filenames, make shorter file names compare less than longer filenames,
# using this key function
def filename_key(filename):
    return (len(filename), filename);


if __name__ == '__main__':
    args = parse_args()
    logging.debug(args)

    stub = connect(args.mobilecoind_host, args.mobilecoind_port)
    source_accounts = [
        load_key_and_register(account_key, stub)
        for account_key in sorted(glob.glob(os.path.join(args.key_dir, '*.json')), key=filename_key)
    ]

    dest_b58addresses = [
        read_file(b58_pubfile)
        for b58_pubfile in sorted(glob.glob(os.path.join(args.dest_key_dir, '*.b58pub')), key=filename_key)
    ]

    # convert from b58 to external.PublicAddress using mobilecoind helpers
    dest_addresses = [
        stub.ParseAddressCode(mobilecoind_api_pb2.ParseAddressCodeRequest(b58_code = b58)).receiver
        for b58 in dest_b58addresses
    ]

    # Go through each account and have all their friends transact to them
    for i, (src_account, dest) in enumerate(zip(source_accounts, dest_addresses)):
        # If we have already done max_accounts many accounts, then stop
        if i == args.max_accounts:
            break;

        wait_for_accounts_sync(stub, [src_account.monitor_id], 3)
        # Get starting balance
        resp = stub.GetBalance(
            mobilecoind_api_pb2.GetBalanceRequest(monitor_id=src_account.monitor_id, token_id=args.token_id))
        balance = resp.balance
        logging.info("Starting balance for account %s : %s", i, resp)

        amount = balance - args.fee

        # Create a pool of transfers to all other accounts
        logging.info("Transferring %s to %s", amount, dest)

        run_test(stub, amount, src_account.monitor_id, dest, args.max_seconds, args.token_id)

    logging.info("All transfers successful")
