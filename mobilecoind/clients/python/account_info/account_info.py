#!/usr/bin/env python3

# Copyright (c) 2018-2020 MobileCoin Inc.

# look up information for an account based on its master key

import argparse
import time
import datetime
import mobilecoin

MONITOR_SYNC_INTERVAL_SECONDS = 5

# constants
default_subaddress_index = 0
MOB = 1_000_000_000_000

def wait_for_ledger():
    last_remote_count, last_local_count, is_behind = mobilecoind.get_network_status()
    if is_behind:
        print("#\n# waiting for the ledger to download")
    start = datetime.datetime.now()
    total_blocks = 0
    while is_behind:
        remote_count, local_count, is_behind = mobilecoind.get_network_status()
        print("# ledger has {} of {} blocks".format(local_count, remote_count))
        delta = datetime.datetime.now() - start
        total_seconds = delta.microseconds/1e6 + delta.seconds
        new_blocks = local_count - last_local_count
        total_blocks += new_blocks
        blocks_per_second = total_blocks / total_seconds
        print("#    {} blocks added ({} blocks per second)".format(new_blocks, round(blocks_per_second,1)))
        blocks_remaining = remote_count - local_count
        if blocks_per_second > 0:
            time_remaining_seconds = blocks_remaining / blocks_per_second
            print("#    {} blocks remain ({} seconds)".format(blocks_remaining, round(time_remaining_seconds,1)))
        else:
            print("#    {} blocks remain (? seconds)".format(blocks_remaining))
        last_remote_count = remote_count
        last_local_count = local_count
    if total_blocks > 0:
        print("# ledger has downloaded all {} blocks\n#".format(last_local_count))
    return last_local_count

def wait_for_monitor(monitor_id_hex):
    ledger_block_count = wait_for_ledger()
    starting_next_block = mobilecoind.get_monitor_status(bytes.fromhex(monitor_id_hex)).next_block
    if starting_next_block > ledger_block_count:
        return 0
    blocks_to_scan = ledger_block_count - starting_next_block
    print("#\n# waiting for monitor {} to process {} blocks".format(monitor_id_hex, blocks_to_scan))
    start_time = datetime.datetime.now()
    next_block = 0
    while next_block < ledger_block_count:
        time.sleep(MONITOR_SYNC_INTERVAL_SECONDS)
        next_block = mobilecoind.get_monitor_status(bytes.fromhex(monitor_id_hex)).next_block
        if next_block > ledger_block_count:
            break
        print("# monitor {} is now processing block {}".format(monitor_id_hex, next_block))
        delta = datetime.datetime.now() - start_time
        total_seconds = delta.microseconds/1e6 + delta.seconds
        total_blocks = next_block - starting_next_block
        blocks_per_second = total_blocks / total_seconds
        print("#    {} blocks processed in {} seconds ({} blocks per second)".format(total_blocks, round(total_seconds,1), round(blocks_per_second,1)))
        blocks_remaining = ledger_block_count - next_block
        if blocks_per_second > 0:
            time_remaining_seconds = blocks_remaining / blocks_per_second
            print("#    {} blocks remain ({} seconds)".format(blocks_remaining, round(time_remaining_seconds,1)))
        else:
            print("#    {} blocks remain (? seconds)".format(blocks_remaining))
    print("# monitor {} has processed all {} blocks\n#".format(monitor_id_hex, ledger_block_count))
    return blocks_to_scan

def display_in_MOB(picoMOB: int) -> str:
    if picoMOB == 0:
        return "0.000000"
    MOB = float(picoMOB) / 1e12
    if MOB < 0.000001:
        return "{:0.6f}e-6".format(float(picoMOB)/1e6)
    if MOB > 1000000:
        return "{:0.6f}e6".format(float(picoMOB)/1e18)
    return "{:0.6f}".format(MOB)

if __name__ == '__main__':
    # Parse the arguments and generate the mob_client
    parser = argparse.ArgumentParser(description='provide secrets')
    parser.add_argument('-k', '--key', help='account master key', type=str)
    parser.add_argument('--first_block', help='ledger block to begin scan', type=int, required=False)
    parser.add_argument('-b', '--balance', help='also check balance', action="store_true")
    args = parser.parse_args()

    # Parse the arguments and generate a mob_client
    mobilecoind = mobilecoin.Client("localhost:4444", ssl=False)

    # Wait for mobilecoind to sync ledger
    ledger_block_count = wait_for_ledger()

    # create monitor
    entropy = args.key
    account_key = mobilecoind.get_account_key(bytes.fromhex(entropy))
    if args.first_block:
        monitor_id = mobilecoind.add_monitor(account_key, first_subaddress=default_subaddress_index, num_subaddresses=1, first_block=args.first_block).hex()
    else:
        monitor_id = mobilecoind.add_monitor(account_key, first_subaddress=default_subaddress_index, num_subaddresses=1).hex()

    public_address = mobilecoind.get_public_address(bytes.fromhex(monitor_id), default_subaddress_index)

    if args.balance:
        blocks_processed = wait_for_monitor(monitor_id)
    balance_picoMOB = mobilecoind.get_balance(bytes.fromhex(monitor_id), default_subaddress_index) if args.balance else "...Skipped"

    address_code = mobilecoind.create_address_code(public_address)

    # print account information
    print("\n")
    print("    {:<18}{}".format("Master Key:", entropy))
    print("    {:<18}{}".format("Address Code:", address_code))
    print("    {:<18}{} picoMOB".format("Balance:", balance_picoMOB))
    print("    {:<18}{} MOB".format(" ", display_in_MOB(balance_picoMOB)))
    print("\n")
