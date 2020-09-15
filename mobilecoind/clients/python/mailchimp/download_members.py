#!/usr/bin/env python3

# Copyright (c) 2018-2020 MobileCoin Inc.

# used to download our mailing list and output a table with all user balances

import os.path
import sys
import mobilecoin

import argparse
from mailchimp3 import MailChimp
import time

import datetime

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

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='provide secrets')
    parser.add_argument('-k', '--key', help='MailChimp API key', type=str)
    parser.add_argument('--clean', help='remove all old monitors', action='store_true')
    parser.add_argument('--limit', help='limit to a subset of members', type=int)
    args = parser.parse_args()

    print("\n# *\n# * Starting up member balance check script!\n# *\n#")

    # Parse the arguments and generate the mobilecoind client
    mobilecoind = mobilecoin.Client("localhost:4444", ssl=False)

    # clean up all old monitors
    if args.clean:
        for monitor_id in mobilecoind.get_monitor_list():
            print("# removing existing monitor_id {}.".format(monitor_id.hex()))
            mobilecoind.remove_monitor(monitor_id)

    # Wait for mobilecoind to sync ledger
    ledger_block_count = wait_for_ledger()

    # generate the MailChimp client
    mailchimp = MailChimp(mc_api=args.key)

    # figure out the id for the list of interest
    # print(mailchimp.lists.all(get_all=True, fields="lists.name,lists.id"))
    list_id = '5f47419453' # The "MobileCoin" Audience

    # go through all the subscribers in chunks
    fields="members.id,members.email_address,members.merge_fields,members.status" # important: no spaces!
    offset = 0
    count = 200 # can be up to 1000
    members = []
    while count > 0:
        chunk_of_members = mailchimp.lists.members.all(list_id, count=count, offset=offset, fields=fields)["members"]
        count = len(chunk_of_members)
        offset += count
        members.extend(chunk_of_members)

    print("# mailing list contains {} members.".format(len(members)))

    start = datetime.datetime.now()

    # create monitors
    monitor_ids = dict()
    emails = dict()

    limit = len(members)
    if args.limit:
        limit = int(args.limit)
    print("# cropping to the first {} members.".format(limit))

    for member_record in members[:limit]:
        if member_record["merge_fields"]["ENTROPY"]:
            entropy = member_record["merge_fields"]["ENTROPY"]
            email = member_record["email_address"]
            try:
                account_key = mobilecoind.get_account_key(bytes.fromhex(entropy))
                monitor_ids[entropy] = mobilecoind.add_monitor(account_key, first_subaddress=0, num_subaddresses=1).hex()
                emails[entropy] = email
                print("# adding monitor_id {} for {}".format(monitor_ids[entropy], emails[entropy]))
            except:
                print("\n ERROR: trouble converting {} to bytes for {} \n".format(entropy, email))

    # wait until all monitors are current
    print("#\n# waiting to process {} monitors-blocks".format(limit * ledger_block_count))
    loop_start = datetime.datetime.now()
    blocks_processed = 0
    for i, (entropy, monitor_id_hex) in enumerate(monitor_ids.items()):
        blocks_processed_now = wait_for_monitor(monitor_id_hex)
        if i == 0:
            blocks_processed = blocks_processed_now
    delta = datetime.datetime.now() - loop_start
    total_loop_seconds = delta.microseconds/1e6 + delta.seconds
    monitor_blocks_per_second = blocks_processed * limit / total_loop_seconds
    print("# all {} monitors are now current ({} monitor-blocks per second)\n#".format(limit, monitor_blocks_per_second))

    print("# printing csv table of member balances")
    balances = dict()
    for entropy, monitor_id_hex in monitor_ids.items():
        balances[entropy] = mobilecoind.get_balance(bytes.fromhex(monitor_id_hex), default_subaddress_index)
    print("")
    print("entropy, email, picoMOB, MOB")
    for entropy, email in emails.items():
        print("{}, {}, {}, {}".format(entropy, email, balances[entropy], balances[entropy]/MOB))

    delta = datetime.datetime.now() - start
    total_seconds = delta.microseconds/1e6 + delta.seconds
    print("\n# *\n# * found balances for {} members in {} seconds\n# *".format(limit, total_seconds))
