#!/usr/bin/env python3
#
# Test vector generator for slip10 output -> mobilecoin conversion
#
# This takes a SLIP-0010 output (specifically, what is termed the "Ed25519
# private key" by the spec) and runs it through a pair of KDF instances to
# create the view and spend outputs.
#
# This code should not be re-used in a production system.
#

import hkdf
import hashlib
import sys

args = sys.argv[1:]
print(args)
for arg in args:
    print("SlipToRistretto {")
    print(f"    slip10_hex: \"{arg}\",")

    slip10 = bytes.fromhex(arg)
    kdf = hkdf.Hkdf(b"mobilecoin-ristretto255-view", slip10, hashlib.sha512)
    key = kdf.expand(length=64)

    print(f"    view_hex: \"{key.hex()}\",")

    kdf = hkdf.Hkdf(b"mobilecoin-ristretto255-spend", slip10, hashlib.sha512)
    key = kdf.expand(length=64)

    print(f"    spend_hex: \"{key.hex()}\",")
    print("},")

