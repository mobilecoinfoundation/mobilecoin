#!/usr/bin/env python3

# Copyright (c) 2018-2020 MobileCoin Inc.

import argparse
import json

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Write entropy as hex to file')
    parser.add_argument('keyfile', help='Location of keyfile to process', type=str)
    parser.add_argument('outfile', help='Location to write the hex-encoded entropy bytes', type=str)
    args = parser.parse_args()

    with open(args.keyfile) as account_key:
        contents = json.load(account_key)
        with open(args.outfile, 'w') as outfile:
            outfile.write(''.join('{:02x}'.format(x) for x in contents['root_entropy']))
