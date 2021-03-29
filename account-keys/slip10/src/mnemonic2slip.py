#!/usr/bin/env python3
#
# Test vector generator for mnemonics -> mobilecoin conversion.
#
# This code reads a series of BIP-39 wordlists encoded as string arguments and
# runs them through BIP-39 and the SLIP-0010 test vector code, followed by the
# our own pair of HKDF instances to construct both view and spend keys.
#
# Much of this code was copy/pasted from
# https://github.com/satoshilabs/slips/slip-0010/testvectors.py and probably
# should not be re-used in a production setting.
#

import hashlib
import hkdf
import hmac
import mnemonic
import sys


def int_to_string(x, pad):
    result = ['\x00'] * pad
    while x > 0:
        pad -= 1
        ordinal = x & 0xFF
        result[pad] = (chr(ordinal))
        x >>= 8
    return ''.join(result)


def string_to_int(s):
    result = 0
    for c in s:
        if not isinstance(c, int):
            c = ord(c)
        result = (result << 8) + c
    return result


# mode 0 - compatible with BIP32 private derivation
def seed2hdnode(seed, modifier, curve):
    while True:
        h = hmac.new(modifier, seed, hashlib.sha512).digest()
        key, chaincode = h[:32], h[32:]
        a = string_to_int(key)
        if curve == 'ed25519':
            break
        if a < curve.order and a != 0:
            break
        seed = h
        # print 'RETRY seed: ' + binascii.hexlify(seed)
    return key, chaincode


def main():
    args = sys.argv[1:]
    path_str = ""
    i = 0
    for arg in args:
        print("MnemonicToRistretto {")
        print(f"    phrase: \"{arg}\",")

        mnemo = mnemonic.Mnemonic("english")
        seed = mnemo.to_seed(arg, "")

        slip10, _chain = seed2hdnode(seed, b"ed25519 seed", 'ed25519')
        kdf = hkdf.Hkdf(b"mobilecoin-ristretto255-view", slip10, hashlib.sha512)
        key = kdf.expand(length=64)

        print(f"    view_hex: \"{key.hex()}\",")

        kdf = hkdf.Hkdf(b"mobilecoin-ristretto255-spend", slip10, hashlib.sha512)
        key = kdf.expand(length=64)

        print(f"    spend_hex: \"{key.hex()}\",")
        print("},")


main()
