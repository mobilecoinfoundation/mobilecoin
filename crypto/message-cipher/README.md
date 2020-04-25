mc-crypto-message-cipher
==============

Message cipher provides a simple API for a short-lived cipher used to encrypt and decrypt messages.

The intended use is to e.g. encrypt in-flight transactions so that they can be cached outside of the enclave,
so that the encrypting and decrypting parties are actually the same and key exchange is not needed.

Message cipher can be simply initialized using an rng (RdRandRng is expected),
and prost messages can be directly encrypted and decrypted using the cipher, for convenience.

The AeadMessageCipher can be used with any implementation of the Aead trait, so this API is potentially compatible
with Intel's sealing functionality if that is desired.
