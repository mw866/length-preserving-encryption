# Homework 2 (CS5830) 
# Trying to implement a length preserving Encryption function.
# 

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
import base64
import binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes # [mw866] Added
from collections import deque #[mw866] Added

def xor(a,b):
    """
    xors two raw byte streams.
    """
    assert len(a) == len(b), "Lengths of two strings are not same. a = {}, b = {}".format(len(a), len(b))
    return ''.join(chr(ord(ai)^ord(bi)) for ai,bi in zip(a,b))

class MyFeistel:
    def __init__(self, key, num_rounds, backend=None):
        if backend is None:
            backend = default_backend()

        key = base64.urlsafe_b64decode(key)
        if len(key) != 16:
            raise ValueError(
                "Key must be 16 url-safe base64-encoded bytes. Got: {} ({})".format(key, len(key))
            )
        self._num_rounds = num_rounds
        self._encryption_key = key
        self._backend = backend
        self._round_keys = deque([self._encryption_key \
                            for _ in xrange(self._num_rounds)]) #[mw866] changed from list to collections.dequeue
        for i  in xrange(self._num_rounds):
            if i==0: continue
            self._round_keys[i] = self._SHA256hash(self._round_keys[i-1])
            # _round_keys length = 32 bytes


    def _SHA256hash(self, data):
        h = hashes.Hash(hashes.SHA256(), self._backend)
        h.update(data)
        return h.finalize()

    def encrypt(self, data):
        assert len(data)%2 == 0, "Supports only balanced feistel at "\
            "this moment. So provide even length messages."

        # [Done] - Fill in
        padder = padding.PKCS7(256).padder()
        data = padder.update(data) + padder.finalize()
        for i in xrange(self._num_rounds):
            data = self._feistel_round_enc(data)
        return data

    def decrypt(self, ctx):
        assert len(ctx)%2 == 0, "Supports only balanced feistel at "\
            "this moment. So provide even length ciphertext."

        # [Done] - Fill in
        for i in xrange(self._num_rounds):
            ctx = self._feistel_round_dec(ctx)
        unpadder = padding.PKCS7(256).unpadder()
        ctx = unpadder.update(ctx) + unpadder.finalize()
        return ctx

    def _prf(self, key, data):
        """Set up secure round function F
        """
        # [DONE] - set up round function using AES 
        encryptor = Cipher(algorithms.AES(key),modes.ECB(), self._backend).encryptor()
        return (encryptor.update(data) + encryptor.finalize())[-24:]

    def _feistel_round_enc(self, data):
        """This function implements one round of Fiestel encryption block.
        """
        # [Done] - Implement this function
        round_key = self._round_keys.pop()
        self._round_keys.appendleft(round_key)

        L, R = data[:len(data)/2], data[len(data)/2:]
        L_next, R_next = R, xor(L, self._prf(round_key, R))
        return L_next + R_next
    
    def _feistel_round_dec(self, data):
        """This function implements one round of Fiestel decryption block.
        """
        # [Done] - Implement this function 
        round_key = self._round_keys.popleft()
        self._round_keys.append(round_key)

        L_next, R_next = data[:len(data)/2], data[len(data)/2:]
        L, R = xor(R_next, self._prf(round_key, L_next)) , L_next
        return L + R

class LengthPreservingCipher(object):
    #'length' is in bytes here
    def __init__(self, key, length=6):
        self._length = 6
        #TODO 

    def encrypt(self, data):
        # TODO
        return data

    def decrypt(self, data):
        # TODO
        return data

    # TODO - add other functions if required
