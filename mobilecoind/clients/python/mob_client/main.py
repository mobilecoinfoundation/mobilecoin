#!/usr/bin/env python3

# Copyright (c) 2018-2020 MobileCoin Inc.

import argparse

try:
    import readline
except ImportError:
    # readline not required on Windows
    pass

from wallet import Session

if __name__ == '__main__':
    # Parse the arguments and generate the mob_client
    parser = argparse.ArgumentParser(
        description='Connect to a mobilecoind daemon')
    parser.add_argument('daemon', help='Address and port of daemon', type=str)
    parser.add_argument('--ssl', help='Use SSL', action='store_true')
    args = parser.parse_args()

    session = Session(args.daemon, args.ssl)
    session.cmdloop()
