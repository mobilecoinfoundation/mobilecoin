#!/usr/bin/env python3

import binascii
import hashlib
import hmac
import struct
import ecdsa
import ed25519
from base58 import b58encode_check

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
        if (curve == 'ed25519'):
            break
        if (a < curve.order and a != 0):
            break
        seed = h
    return (key, chaincode)

def fingerprint(publickey):
    h = hashlib.new('ripemd160', hashlib.sha256(publickey).digest()).digest()
    return h[:4]

def b58xprv(parent_fingerprint, private_key, chain, depth, childnr):
    raw = ('\x04\x88\xad\xe4' +
              chr(depth) + parent_fingerprint + int_to_string(childnr, 4) +
              chain + '\x00' + private_key)
    return b58encode_check(raw)

def b58xpub(parent_fingerprint, public_key, chain, depth, childnr):
    raw = ('\x04\x88\xb2\x1e' +
              chr(depth) + parent_fingerprint + int_to_string(childnr, 4) +
              chain + public_key)
    return b58encode_check(raw)

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
    if ((i & privdev) != 0):
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
        if (a < curve.order and key != 0):
            key = int_to_string(key, 32)
            break
        d = '\x01' + h[32:] + struct.pack('>L', i)
                        
    return (key, chaincode)

def get_curve_info(curvename):
    if curvename == 'secp256k1':
        return (ecdsa.curves.SECP256k1, b'Bitcoin seed') 
    if curvename == 'nist256p1':
        return (ecdsa.curves.NIST256p, b'Nist256p1 seed') 
    if curvename == 'ed25519':
        return ('ed25519', b'ed25519 seed')
    raise BaseException('unsupported curve: '+curvename)

def show_testvector(name, curvename, seedhex, derivationpath):
    curve, seedmodifier = get_curve_info(curvename)
    master_seed = binascii.unhexlify(seedhex)
    k,c = seed2hdnode(master_seed, seedmodifier, curve)
    p = publickey(k, curve)
    fpr = b'\x00\x00\x00\x00'
    path = 'm'
    print("### "+name+" for "+curvename)
    print('')
    print("Seed (hex): " + seedhex)
    print('')
    print('* Chain ' + path)
    print('  * fingerprint: ' + fpr.hex())
    print('  * chain code: ' + c.hex())
    print('  * private: ' + k.hex())
    print('  * public: ' + p.hex())
    depth = 0
    for i in derivationpath:
        if curve == 'ed25519':
            # no public derivation for ed25519
            i = i | privdev
        fpr = fingerprint(p)
        depth = depth + 1
        path = path + "/" + str(i & (privdev-1))
        if ((i & privdev) != 0):
            path = path + "<sub>H</sub>"
        k,c = derive(k, c, i, curve)
        p = publickey(k, curve) 
        print('* Chain ' + path)
        print('  * fingerprint: ' + fpr.hex())
        print('  * chain code: ' + c.hex())
        print('  * private: ' + k.hex())
        print('  * public: ' + p.hex())
        #print b58xprv(fpr, kc, cc, depth, i)
        #print b58xpub(fpr, pc, cc, depth, i)
    print

def show_testvectors(name, curvenames, seedhex, derivationpath):
    for curvename in curvenames:
        show_testvector(name, curvename, seedhex, derivationpath)


show_testvectors("Real", ['ed25519'],
                 '5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4',
                 [privdev + 44, privdev + 866, privdev + 0])

