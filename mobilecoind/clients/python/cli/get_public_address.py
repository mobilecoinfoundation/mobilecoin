#!/usr/bin/env python3

# Copyright (c) 2018-2020 MobileCoin Inc.

# display the b58 public address and URI that correspond to a master key

import argparse
import mobilecoin

if __name__ == '__main__':
    # Connect to mobilecoind
    mobilecoind = mobilecoin.Client("localhost:4444", ssl=False)

    # Parse the arguments
    parser = argparse.ArgumentParser(description='You must provide your master key as a 32 byte hex string.')
    parser.add_argument('-k', '--key', help='account master key', type=str)
    parser.add_argument('-s', '--subaddress', help='(optional) subaddress', nargs='?', const=mobilecoind.DEFAULT_SUBADDRESS_INDEX, type=int)
    args = parser.parse_args()

    # create a monitor and use it to calculate the public address
    entropy_bytes = bytes.fromhex(args.key)
    account_key = mobilecoind.get_account_key(entropy_bytes)
    monitor_id = mobilecoind.add_monitor(account_key, first_subaddress=args.subaddress)
    public_address = mobilecoind.get_public_address(monitor_id, subaddress_index=args.subaddress)

    # print the public address information
    print("\n")
    print("    {:<18}{}".format("Master Key:", args.key))
    print("    {:<18}{}".format("Address Code:", public_address.b58_code))
    print("    {:<18}{}".format("Address URL:", public_address.mob_url))
    print("\n")
