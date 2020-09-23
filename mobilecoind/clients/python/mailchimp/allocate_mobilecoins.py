#!/usr/bin/env python3

# Copyright (c) 2018-2020 MobileCoin Inc.

# used to allocation TestNet mobilecoins to users who sign up for our mailing list

import os.path
import sys
import mobilecoin

import argparse
from mailchimp3 import MailChimp
import time
import datetime

TX_RECEIPT_CHECK_INTERVAL_SECONDS = 4
MONITOR_SYNC_INTERVAL_SECONDS = 4

TX_STATUS_VERIFIED = 1

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

# useful for testing
def self_payment(monitor_id_hex, subaddress_index):
    wait_for_monitor(monitor_id_hex)
    tx_list = mobilecoind.get_unspent_tx_output_list(bytes.fromhex(monitor_id_hex), subaddress_index)
    public_address = mobilecoind.get_public_address(bytes.fromhex(monitor_id_hex), subaddress_index)
    outlays = [{'value': 1 * MOB, 'receiver': public_address}]
    tx_proposal = mobilecoind.generate_tx(bytes.fromhex(monitor_id_hex), subaddress_index, tx_list, outlays)
    sender_tx_receipt = mobilecoind.submit_tx(tx_proposal).sender_tx_receipt
    # Wait for the transaction to clear
    while not int(mobilecoind.get_tx_status_as_sender(sender_tx_receipt)) == TX_STATUS_VERIFIED:
        time.sleep(TX_RECEIPT_CHECK_INTERVAL_SECONDS)

# generates a new master key, allocates funds, stores data at Mailchimp and sends a welcome email
def allocate_MOB(mailchimp_member_record, amount_picoMOB):
    email_sent = 0 # return either zero or one

    new_user_email = mailchimp_member_record["email_address"]
    new_user_hash = mailchimp_member_record["id"]

    # Wait for mobilecoind to sync ledger
    block_count = wait_for_ledger()

    # abort if sender's balance is too low
    wait_for_monitor(sender_monitor_id.hex())
    sender_balance_picoMOB = mobilecoind.get_balance(sender_monitor_id, default_subaddress_index)
    if sender_balance_picoMOB < args.value * MOB:
        print("# sender's balance is running low ({} MOB)... aborting!".format(sender_balance_picoMOB/MOB))
        sys.exit()

    # create and fund a new MobileCoin TestNet account
    recipient_entropy = mobilecoind.generate_entropy()
    recipient_account_key = mobilecoind.get_account_key(recipient_entropy)
    print("# assigning entropy {} to email {}".format(recipient_entropy.hex(), new_user_email))

    # no need to start the recipient from the origin block since we know we just created this account
    recipient_monitor_id = mobilecoind.add_monitor(recipient_account_key, first_subaddress=0, num_subaddresses=1, first_block=block_count)
    recipient_public_address = mobilecoind.get_public_address(recipient_monitor_id, default_subaddress_index)
    print("# added monitor {} for {} (first block = {})".format(recipient_monitor_id.hex(), new_user_email, block_count))

    # Construct and send the MOB allocation transaction
    tx_list = mobilecoind.get_unspent_tx_output_list(sender_monitor_id, default_subaddress_index)
    outlays = [{'value': amount_picoMOB, 'receiver': recipient_public_address}]

    tx_proposal = mobilecoind.generate_tx(sender_monitor_id, default_subaddress_index, tx_list, outlays)
    if args.verbose:
        input("About to transfer funds. Continue?")
    sender_tx_receipt = mobilecoind.submit_tx(tx_proposal).sender_tx_receipt

    # Wait for the transaction to clear
    while not int(mobilecoind.get_tx_status_as_sender(sender_tx_receipt)) == TX_STATUS_VERIFIED:
        time.sleep(TX_RECEIPT_CHECK_INTERVAL_SECONDS)

    # TODO: fix after MCC-132

    # Check balances
    recipient_balance = mobilecoind.get_balance(recipient_monitor_id, default_subaddress_index)
    sender_balance = mobilecoind.get_balance(sender_monitor_id, default_subaddress_index)
    print("# recipient balance = {} picoMOB, sender balance = {} picoMOB".format(recipient_balance, sender_balance))

    # If the recipient's balance is not as expected, complain and do not update Mailchimp
    if recipient_balance != amount_picoMOB:
        print(
            "ERROR... recipient balance is not correct! Generated entropy {} has only {} MOB. Expected {} MOB."
            .format(recipient_entropy.hex(), recipient_balance/MOB, amount_picoMOB/MOB)
        )
    else:
        if args.verbose:
            input("About to assign entropy. Continue?")

        # set the entropy value at MailChimp
        data = {"merge_fields":{"ENTROPY":recipient_entropy.hex()}}
        response = mailchimp.lists.members.update(list_id, subscriber_hash=new_user_hash, data=data)

        if args.verbose:
            input("About to tag with welcome email trigger. Continue?")

        # adding "send_key_now" tag triggers the welcome email automation!
        data = {"tags":[{"name":"has_entropy", "status":"active"},{"name":"send_key_now", "status":"active"}]}
        mailchimp.lists.members.tags.update(list_id, subscriber_hash=new_user_hash, data=data)

        email_sent = 1
        print("# sending welcome email to {} now!".format(new_user_email))

    # remove recipient monitor
    mobilecoind.remove_monitor(recipient_monitor_id)
    print("# removed monitor {} for {}".format(recipient_monitor_id.hex(), new_user_email))

    return email_sent

def process_records(fields, since_last_changed = ""):
    offset = 0
    count = 200 # can be up to 1000
    emails_sent = 0
    while count > 0:
        if since_last_changed:
            members = mailchimp.lists.members.all(list_id, count=count, offset=offset, fields=fields, since_last_changed=since_last_changed)["members"]
        else:
            members = mailchimp.lists.members.all(list_id, count=count, offset=offset, fields=fields)["members"]
        count = len(members)
        offset += count
        if count > 0 :
            print("# processed {} records found at MailChimp".format(offset))
        for member_record in members:
            if member_record["status"] == "subscribed" and not member_record["merge_fields"]["ENTROPY"]:
                emails_sent += allocate_MOB(member_record, args.value * MOB)
    if emails_sent > 0:
        print("# sent {} MOB to each of {} new records found at MailChimp".format(args.value, emails_sent))
    else:
        print("# no new records found.")

    return emails_sent

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='provide secrets')
    parser.add_argument('-k', '--key', help='MailChimp API key', type=str)
    parser.add_argument('-s', '--sender', help='MobileCoin sender master key as hex', type=str)
    parser.add_argument('-v', '--value', help='mobilecoins to allocate in MOB', type=int)
    parser.add_argument('-i', '--interval', help='new record polling interval in seconds', type=int)
    parser.add_argument('--verbose', help='confirm each action', action='store_true')
    parser.add_argument('--clean', help='remove all old monitors', action='store_true')
    args = parser.parse_args()

    print("\n# *\n# * Starting up TestNet allocation script!\n# *\n#")

    if args.verbose:
        input("Running in verbose mode. Continue?")

    # Parse the arguments and generate the mobilecoind client
    mobilecoind = mobilecoin.Client("localhost:4444", ssl=False)

    # Set up our "bank"
    sender_entropy = args.sender
    if not sender_entropy:
        print("You must provide entropy for the sender! (--sender)")
        sys.exit()

    sender_account_key = mobilecoind.get_account_key(bytes.fromhex(sender_entropy))
    sender_monitor_id = mobilecoind.add_monitor(sender_account_key, first_subaddress=0, num_subaddresses=1)
    sender_public_address = mobilecoind.get_public_address(sender_monitor_id, default_subaddress_index)

    # clean up all old monitors -- except for sender_monitor_id
    if args.clean:
        for monitor_id in mobilecoind.get_monitor_list():
            if monitor_id != sender_monitor_id:
                print("# removing existing monitor_id {}.".format(monitor_id.hex()))
                mobilecoind.remove_monitor(monitor_id)

    # Wait for mobilecoind to sync ledger
    block_count = wait_for_ledger()

    # Wait for mobilecoind to get sender's current balance
    wait_for_monitor(sender_monitor_id.hex())

    # generate the MailChimp client
    mailchimp = MailChimp(mc_api=args.key)

    # figure out the id for the list of interest
    # print(mailchimp.lists.all(get_all=True, fields="lists.name,lists.id"))
    list_id = '5f47419453' # The "MobileCoin" Audience

    # go through all the subscribers in chunks and find any who don't have an assigned entropy
    print("# * Processing all existing records")
    fields="members.id,members.email_address,members.merge_fields,members.status" # important: no spaces!
    process_records(fields)
    print("# * Finished processing all existing records")

    if args.interval and args.interval > 0:
        monitor_interval_seconds = int(args.interval)
        monitor_internal_minutes = monitor_interval_seconds/60
        monitor_start_time = datetime.datetime.now().replace(tzinfo=datetime.timezone.utc).isoformat()

        # for efficiency, limit members to recent sign-ups using the `since_last_changed` api parameter
        # see https://mailchimp.com/developer/reference/lists/list-members/
        emails_sent = 0
        while True:
            print("#\n# *\n# * Waiting {} minutes until next MailChimp check\n# *".format(round(monitor_internal_minutes,1)))
            time.sleep(monitor_interval_seconds);

            wait_for_monitor(sender_monitor_id.hex())

            fields="members.id,members.email_address,members.merge_fields,members.status" # important: no spaces!
            cutoff_time = datetime.datetime.utcnow() - datetime.timedelta(seconds=2*monitor_interval_seconds)
            since_last_changed = cutoff_time.replace(tzinfo=datetime.timezone.utc).isoformat() #ISO_8601

            print("# checking for new records since {}".format(since_last_changed))

            emails_sent += process_records(fields, since_last_changed = since_last_changed)
            if emails_sent > 0:
                print("# we've sent {} MOB to each of {} new records found at MailChimp since {}".format(int(args.value), emails_sent, monitor_start_time))
