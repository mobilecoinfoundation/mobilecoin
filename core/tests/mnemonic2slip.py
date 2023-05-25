#!/usr/bin/env python3
#
# Test vector generator for mnemonics -> mobilecoin conversion.
#
# This code reads a series of BIP-39 wordlists encoded as string arguments and
# runs them through BIP-39 and the SLIP-0010 test vector code, followed by the
# our own pair of HKDF instances to construct both view and spend keys.
#
# Much of this code was copy/pasted from
# https://raw.githubusercontent.com/satoshilabs/slips/master/slip-0010/testvectors.py
# and probably should not be re-used in a production setting.
#

import hashlib
import struct

import ed25519
import hkdf
import hmac
import mnemonic
import sys


privdev = 0x80000000


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
    k = seed
    while True:
        h = hmac.new(modifier, seed, hashlib.sha512).digest()
        key, chaincode = h[:32], h[32:]
        a = string_to_int(key)
        if curve == 'ed25519':
            break
        if a < curve.order and a != 0:
            break
        seed = h
    return key, chaincode


def publickey(private_key, curve):
    if curve == 'ed25519':
        sk = ed25519.SigningKey(private_key)
        return b'\x00' + sk.get_verifying_key().to_bytes()
    else:
        Q = string_to_int(private_key) * curve.generator
        xstr = int_to_string(Q.x(), 32)
        parity = Q.y() & 1
        return chr(2 + parity) + xstr


def derive(parent_key, parent_chaincode, i, curve):
    assert len(parent_key) == 32
    assert len(parent_chaincode) == 32
    k = parent_chaincode
    if (i & privdev) != 0:
        key = b'\x00' + parent_key
    else:
        key = publickey(parent_key, curve)
    d = key + struct.pack('>L', i)
    while True:
        h = hmac.new(k, d, hashlib.sha512).digest()
        key, chaincode = h[:32], h[32:]
        if curve == 'ed25519':
            break
        a = string_to_int(key)
        key = (a + string_to_int(parent_key)) % curve.order
        if a < curve.order and key != 0:
            key = int_to_string(key, 32)
            break
        d = '\x01' + h[32:] + struct.pack('>L', i)

    return key, chaincode


def main():
    args = sys.argv[1:]
    for arg in args:
        print("// Path: m/44'/866'/0'")
        print("MnemonicToRistretto {")
        print(f"    phrase: \"{arg}\",")
        print("    account_index: 0,")

        mnemo = mnemonic.Mnemonic("english")
        master_seed = mnemo.to_seed(arg, "")

        # manually build the path to m/usage/cointype/acctidx
        # for us, usage is BIP-44, cointype is MobileCoin
        # m
        k, c = seed2hdnode(master_seed, b"ed25519 seed", 'ed25519')
        # m/44
        k, c = derive(k, c, 44 + privdev, 'ed25519')
        # m/44/866
        k, c = derive(k, c, 866 + privdev, 'ed25519')
        # m/44/866/0
        acct0, _c = derive(k, c, 0 + privdev, 'ed25519')

        kdf = hkdf.Hkdf(b"mobilecoin-ristretto255-view", acct0, hashlib.sha512)
        key = kdf.expand(length=64)

        print(f"    view_hex: \"{key.hex()}\",")

        kdf = hkdf.Hkdf(b"mobilecoin-ristretto255-spend", acct0, hashlib.sha512)
        key = kdf.expand(length=64)

        print(f"    spend_hex: \"{key.hex()}\",")
        print("},")

        print("// Path: m/44'/866'/1'")
        print("MnemonicToRistretto {")
        print(f"    phrase: \"{arg}\",")
        print("    account_index: 1,")

        # m/44/866/1
        acct1, _c = derive(k, c, 1 + privdev, 'ed25519')

        kdf = hkdf.Hkdf(b"mobilecoin-ristretto255-view", acct1, hashlib.sha512)
        key = kdf.expand(length=64)

        print(f"    view_hex: \"{key.hex()}\",")

        kdf = hkdf.Hkdf(b"mobilecoin-ristretto255-spend", acct1, hashlib.sha512)
        key = kdf.expand(length=64)

        print(f"    spend_hex: \"{key.hex()}\",")
        print("},")

main()
