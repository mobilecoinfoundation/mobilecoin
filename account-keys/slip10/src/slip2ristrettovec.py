#!/usr/bin/env python3

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

