#!/usr/bin/env python3

# Copyright (c) 2018-2020 MobileCoin Inc.

# check the performance for mobilecoind
import time, datetime

import os,sys
sys.path.insert(1, os.path.realpath(os.path.join(os.path.pardir, "lib")))
import mobilecoin

if __name__ == '__main__':
    # Connect to mobilecoind
    mobilecoind = mobilecoin.Client("localhost:4444", ssl=False)

    # If the ledger db has been recently cleaned, we can get a sense for our average download rate
    (ledger_is_behind, local_count, remote_count, blocks_per_second) = mobilecoind.wait_for_ledger()
    if ledger_is_behind:
        print("\n...testing ledger download rate while downloading {} blocks".format(remote_count - local_count))
        prev_local_count = local_count
        while ledger_is_behind:
            (ledger_is_behind, local_count, remote_count, blocks_per_second) = mobilecoind.wait_for_ledger(max_blocks_to_sync=1000, timeout_seconds=10)
            print("downloaded {} blocks at {} blocks per second".format(local_count - prev_local_count, blocks_per_second))
            prev_local_count = local_count
    else:
        print("\n...can't test ledger download rate because ledger is in sync!")

    # Test how fast we can add and remove monitors with different numbers of subaddresses
    monitors = []
    subaddress_counts = [1, 10, 100, 500, 1000, 5_000, 10_000, 50_000]
    print("\n...testing `mobilecoind.add_monitor`")
    print("{:>18}, {:>18}".format("num_subaddresses", "duration (sec)"))
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
    print("\n...testing `mobilecoind.remove_monitor`")
    print("{:>18}, {:>18}".format("num_subaddresses", "duration (sec)"))
    for (i, count) in enumerate(subaddress_counts):
        start = datetime.datetime.now()
        monitor_id = mobilecoind.remove_monitor(monitors[i])
        finish = datetime.datetime.now()
        print("{:>18}, {:>18}".format(count, (finish - start).total_seconds()))

    def active_monitors():
        count = 0
        for monitor_id in mobilecoind.get_monitor_list():
            (monitor_is_behind, next_block, remote_count, blocks_per_second) = mobilecoind.wait_for_monitor(monitor_id)
            if monitor_is_behind:
                count += 1
        print("...there are {} monitors working")

    # watch performance while the exiting monitors sync
    print("\n...testing block processing rate using all active monitors")
    monitors_are_behind = True
    while monitors_are_behind:
        monitors_are_behind = False
        for monitor_id in mobilecoind.get_monitor_list():
            (monitor_is_behind, prev_next_block, remote_count, blocks_per_second) = mobilecoind.wait_for_monitor(monitor_id)
            if monitor_is_behind:
                (monitor_is_behind, next_block, remote_count, blocks_per_second) = mobilecoind.wait_for_ledger(max_blocks_to_sync=1000, timeout_seconds=10)
                print("{} processed {} blocks at {} blocks per second".format(monitor_id.hex(), next_block - prev_next_block, blocks_per_second))
                if monitor_is_behind:
                    monitors_are_behind = True

    # watch performance for a new monitor
    for count in subaddress_counts:
        print("\n...testing block processing rate with new monitor with {} subaddresses".format(count))
        entropy_bytes = mobilecoind.generate_entropy()
        account_key = mobilecoind.get_account_key(entropy_bytes)
        monitor_id = mobilecoind.add_monitor(account_key,
                                             first_subaddress = mobilecoin.DEFAULT_SUBADDRESS_INDEX,
                                             num_subaddresses = count,
                                             first_block = remote_count-5000)

        (monitor_is_behind, prev_next_block, remote_count, blocks_per_second) = mobilecoind.wait_for_monitor(monitor_id)
        while monitor_is_behind:
            (monitor_is_behind, next_block, remote_count, blocks_per_second) = mobilecoind.wait_for_monitor(monitor_id, max_blocks_to_sync=1000, timeout_seconds=10)
            print("{} processed {} blocks at {} blocks per second".format(monitor_id.hex(), next_block - prev_next_block, blocks_per_second))
            prev_next_block = next_block

        mobilecoind.remove_monitor(monitor_id)

    print("\n")
