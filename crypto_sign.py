# crypto_sign.py
import base64
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def load_private_key(path):
    with open(path, "rb") as f:
        return RSA.import_key(f.read())

def load_public_key(path):
    with open(path, "rb") as f:
        return RSA.import_key(f.read())

def sign_bytes(private_key_obj, message_bytes):
    """
    Returns signature as raw bytes.
    """
    h = SHA256.new(message_bytes)
    signature = pkcs1_15.new(private_key_obj).sign(h)
    return signature

def verify_bytes(public_key_obj, message_bytes, signature_bytes):
    """
    Returns True if valid, False otherwise.
    """
    h = SHA256.new(message_bytes)
    try:
        pkcs1_15.new(public_key_obj).verify(h, signature_bytes)
        return True
    except (ValueError, TypeError):
        return False

def b64encode(b):
    return base64.b64encode(b).decode()

def b64decode(s):
    return base64.b64decode(s)
