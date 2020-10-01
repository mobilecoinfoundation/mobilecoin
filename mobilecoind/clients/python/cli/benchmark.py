#!/usr/bin/env python3

# Copyright (c) 2018-2020 MobileCoin Inc.

# check the performance for mobilecoind
import datetime

import os,sys
sys.path.insert(1, os.path.realpath(os.path.join(os.path.pardir, "lib")))
import mobilecoin

if __name__ == '__main__':
    # Connect to mobilecoind
    mobilecoind = mobilecoin.Client("localhost:4444", ssl=False)

    # Make sure the ledger is current before we begin
    (ledger_is_behind, local_count, remote_count, blocks_per_second) = mobilecoind.wait_for_ledger()
    if ledger_is_behind:
        print("#\n# waiting for the ledger to download {} blocks".format(remote_count - local_count))
        while ledger_is_behind:
            blocks_remaining = (remote_count - local_count)
            if blocks_per_second > 0:
                time_remaining_seconds = blocks_remaining / blocks_per_second
                print("#    {} blocks remain ({} seconds)".format(blocks_remaining, round(time_remaining_seconds, 1)))
            else:
                print("#    {} blocks remain (? seconds)".format(blocks_remaining))
            (ledger_is_behind, local_count, remote_count, blocks_per_second) = mobilecoind.wait_for_ledger(max_blocks_to_sync=10000, timeout_seconds=60)
        print("# ledger has downloaded {} blocks\n#".format(remote_count))

    monitors = []

    # Test how fast we can add a monitor with different numbers of subaddresses
    print("...testing `mobilecoind.add_monitor` duration vs. num_subaddresses")
    print("{:>18}, {:>18}".format("num_subaddresses", "duration (sec)")
    subaddress_counts = [1, 10, 100, 1000, 10_000, 100_000, 500_000]
    for count in subaddress_counts:
        entropy_bytes = mobilecoind.generate_entropy()
        account_key = mobilecoind.get_account_key(entropy_bytes)
        start = datetime.datetime.now()
        monitor_id = mobilecoind.add_monitor(account_key,
                                             first_subaddress = mobilecoin.DEFAULT_SUBADDRESS_INDEX,
                                             num_subaddresses = count,
                                             first_block = remote_count)
        finish = datetime.datetime.now()
        print("{:>18}, {:>18}".format(count, (finish - start).total_seconds()))
        monitors.append(monitor_id)
    print("\n")

    # Test how fast we can remove a monitor with different numbers of subaddresses
    print("...testing `mobilecoind.remove_monitor` duration vs. num_subaddresses")
    print("{:>18}, {:>18}".format("num_subaddresses", "duration (sec)")
    subaddress_counts = [1, 10, 100, 1000, 10_000, 100_000, 500_000]
    for count in subaddress_counts:
        start = datetime.datetime.now()
        monitor_id = mobilecoind.remove_monitor(monitor_id)
        finish = datetime.datetime.now()
        print("{:>18}, {:>18}".format(count, (finish - start).total_seconds()))
    print("\n")

