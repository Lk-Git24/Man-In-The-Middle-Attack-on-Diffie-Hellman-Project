#crypto_protocol.py
#!/usr/bin/env python3
from random import randint
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256

def gen_rand_data(length=16):
    from Crypto.Random import get_random_bytes
    return get_random_bytes(length)

def pkcs_7_pad(data):
    padding_len = 16 - (len(data) % 16)
    return data + bytes([padding_len]) * padding_len

class PaddingException(Exception):
    """ Padding for input data incorrect """

def pkcs_7_unpad(data):
    if not data:
        raise PaddingException
    padding_len = data[-1]
    if padding_len == 0 or padding_len > 16:
        raise PaddingException
    if data[-padding_len:] != bytes([padding_len]) * padding_len:
        raise PaddingException
    return data[:-padding_len]

def AES_128_ECB_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)

def AES_128_ECB_decrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(data)

def xor_data(A, B):
    return bytes(a ^ b for a, b in zip(A, B))

def AES_128_CBC_encrypt(data, key, iv):
    data = pkcs_7_pad(data)
    encrypted_data = b''
    prev_block = iv
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        encrypted_block = AES_128_ECB_encrypt(xor_data(block, prev_block), key)
        encrypted_data += encrypted_block
        prev_block = encrypted_block
    return encrypted_data

def AES_128_CBC_decrypt(data, key, iv):
    decrypted_data = b''
    prev_block = iv
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        decrypted_block = AES_128_ECB_decrypt(block, key)
        decrypted_data += xor_data(decrypted_block, prev_block)
        prev_block = block
    return pkcs_7_unpad(decrypted_data)

def int_to_bytes(i):
    return i.to_bytes((i.bit_length()+7)//8, byteorder='big') or b"\x00"

class CryptoProtocol:
    """
    Construct from shared_secret_int and salt (bytes).
    Uses HKDF(SHA256) to derive AES key (32 bytes) and IV (16 bytes).
    """

    def __init__(self, shared_secret_int, salt):
        shared_bytes = int_to_bytes(shared_secret_int)
        key_material = HKDF(master=shared_bytes, key_len=48, salt=salt, hashmod=SHA256)
        self.AES_key = key_material[:32]
        self.AES_iv = key_material[32:48]

    def encrypt(self, data):
        return AES_128_CBC_encrypt(data.encode(), self.AES_key, self.AES_iv)

    def decrypt(self, data):
        try:
            return AES_128_CBC_decrypt(data, self.AES_key, self.AES_iv).decode()
        except (PaddingException, UnicodeDecodeError):
            # إذا فشل فك التشفير، نرجع رسالة خطأ بدل crash
            return "[ERROR: Could not decrypt]"
